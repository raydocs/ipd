package ingest

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ipd/internal/config"
	"ipd/internal/lookup"
)

// FeedResult is one dataset after a refresh attempt.
type FeedResult struct {
	ID   string `json:"id"`
	Rows int    `json:"rows"`
	URL  string `json:"url,omitempty"`
	Err  string `json:"err,omitempty"`
	Note string `json:"note,omitempty"`
}

// Summary is what `ipd data update` prints.
type Summary struct {
	Dir   string       `json:"dir"`
	Feeds []FeedResult `json:"feeds"`
}

// Update downloads the free datasets and merges each one into eng.
// A feed that fails is reported and skipped. Bundled rows for the other sources stay.
// GeoLite2 runs only when IPD_MAXMIND_KEY is set. IPinfo Lite runs only when IPD_IPINFO_TOKEN is set.
func Update(ctx context.Context, cfg *config.Config, eng *lookup.Engine, logf func(string)) (Summary, error) {
	if cfg == nil {
		cfg = config.FromEnv()
	}
	if logf == nil {
		logf = func(string) {}
	}
	if err := os.MkdirAll(filepath.Join(cfg.DataDir, "feeds"), 0o755); err != nil {
		return Summary{}, err
	}
	u := &updater{
		cfg:    cfg,
		eng:    eng,
		logf:   logf,
		client: &http.Client{Timeout: 90 * time.Second},
	}
	sum := Summary{Dir: cfg.DataDir}
	sum.Feeds = append(sum.Feeds, u.cloud(ctx))
	sum.Feeds = append(sum.Feeds, u.list(ctx, "tor_exits",
		[]string{"https://check.torproject.org/torbulkexitlist"},
		lookup.Rec{Flags: []string{"tor"}},
		"Tor exit list", "https://check.torproject.org/torbulkexitlist")...)
	sum.Feeds = append(sum.Feeds, u.list(ctx, "firehol",
		[]string{"https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"},
		lookup.Rec{Flags: []string{"malicious"}},
		"FireHOL level 1", "https://github.com/firehol/blocklist-ipsets")...)
	sum.Feeds = append(sum.Feeds, u.list(ctx, "ipsum",
		[]string{"https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"},
		lookup.Rec{Flags: []string{"malicious"}},
		"ipsum", "https://github.com/stamparm/ipsum")...)
	sum.Feeds = append(sum.Feeds, u.spamhaus(ctx))
	sum.Feeds = append(sum.Feeds, u.x4b(ctx))
	sum.Feeds = append(sum.Feeds, u.dbip(ctx))
	sum.Feeds = append(sum.Feeds, u.rir(ctx))
	sum.Feeds = append(sum.Feeds, u.asn(ctx))
	sum.Feeds = append(sum.Feeds, u.geolite(ctx))
	sum.Feeds = append(sum.Feeds, u.ipinfo(ctx))
	return sum, nil
}

// Load reads a previously written snapshot into eng. Missing files are not an error.
func Load(eng *lookup.Engine, cfg *config.Config) error {
	if eng == nil || cfg == nil {
		return nil
	}
	dir := filepath.Join(cfg.DataDir, "feeds")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return attachMMDB(eng, cfg)
		}
		return err
	}
	seenSnap := map[string]bool{}
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".ipds") {
			continue
		}
		id := strings.TrimSuffix(ent.Name(), ".ipds")
		if _, err := eng.InstallSnapshot(filepath.Join(dir, ent.Name())); err != nil {
			return err
		}
		seenSnap[id] = true
	}
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".tsv") {
			continue
		}
		id := strings.TrimSuffix(ent.Name(), ".tsv")
		if seenSnap[id] {
			continue
		}
		rows, meta, err := readSnapshot(filepath.Join(dir, ent.Name()), filepath.Join(dir, id+".meta.json"))
		if err != nil {
			return err
		}
		if meta.ID == "" {
			meta.ID = id
		}
		eng.MergeSource(meta, rows)
	}
	return attachMMDB(eng, cfg)
}

func attachMMDB(eng *lookup.Engine, cfg *config.Config) error {
	path := cfg.MaxMindCity
	if path == "" {
		candidate := filepath.Join(cfg.DataDir, "GeoLite2-City.mmdb")
		if _, err := os.Stat(candidate); err == nil {
			path = candidate
		}
	}
	if path == "" {
		return nil
	}
	return eng.AttachMMDB(path)
}

type updater struct {
	cfg    *config.Config
	eng    *lookup.Engine
	logf   func(string)
	client *http.Client
	get    func(ctx context.Context, url string, max int64) ([]byte, error)
}

func (u *updater) fetch(ctx context.Context, urls []string, max int64) ([]byte, string, error) {
	var last error
	for _, raw := range urls {
		if ctx.Err() != nil {
			return nil, raw, ctx.Err()
		}
		var b []byte
		var err error
		if u.get != nil {
			b, err = u.get(ctx, raw, max)
		} else {
			b, err = httpGet(ctx, u.client, raw, max)
		}
		if err != nil {
			last = err
			continue
		}
		if len(b) == 0 {
			last = fmt.Errorf("empty body")
			continue
		}
		return b, raw, nil
	}
	if last == nil {
		last = fmt.Errorf("no url")
	}
	return nil, "", last
}

func httpGet(ctx context.Context, client *http.Client, raw string, max int64) ([]byte, error) {
	if max <= 0 {
		max = 80 << 20
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("user-agent", "ipd/0.9 data-update")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s exceeded %d bytes", raw, max)
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s: %d %s", redact(raw), resp.StatusCode, truncate(b))
	}
	return gunzip(b)
}

func gunzip(b []byte) ([]byte, error) {
	if len(b) < 2 || b[0] != 0x1f || b[1] != 0x8b {
		return b, nil
	}
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	const limit = 1 << 30
	out, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if len(out) > limit {
		return nil, fmt.Errorf("decompressed body exceeded %d bytes", limit)
	}
	return out, nil
}

func redact(s string) string {
	for _, key := range []string{"license_key=", "token="} {
		for {
			i := strings.Index(s, key)
			if i < 0 {
				break
			}
			j := strings.IndexAny(s[i+len(key):], "& \t")
			if j < 0 {
				s = s[:i+len(key)] + "REDACTED"
				break
			}
			s = s[:i+len(key)] + "REDACTED" + s[i+len(key)+j:]
		}
	}
	return s
}

func truncate(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 160 {
		return s[:160]
	}
	return s
}

func (u *updater) apply(id string, m lookup.SourceMeta, rows []lookup.SourceRow, srcURL, note string, err error) FeedResult {
	fr := FeedResult{ID: id, URL: srcURL, Note: note}
	if err != nil {
		fr.Err = err.Error()
		u.logf(id + " 失败: " + fr.Err)
		return fr
	}
	if u.eng != nil {
		fr.Rows = u.eng.MergeSource(m, rows)
	} else {
		fr.Rows = len(rows)
	}
	if fr.Rows == 0 {
		fr.Err = "no rows parsed"
		u.logf(id + " 没有解析出前缀，保留原快照")
		return fr
	}
	if err := u.writeSnapshot(m, rows); err != nil {
		fr.Err = err.Error()
	}
	u.logf(fmt.Sprintf("%s 已更新 %d 条", id, fr.Rows))
	return fr
}

// streamRows writes a memory-mappable snapshot and swaps it into the engine.
// The row cap is gone: max is not applied. A failed empty parse leaves the previous table in place.
func (u *updater) streamRows(m lookup.SourceMeta, srcURL, note string, fill func(func(lookup.Rec)) error) FeedResult {
	fr := FeedResult{ID: m.ID, URL: srcURL, Note: note}
	bldr := lookup.NewSnapshotBuilder(m)
	err := fill(func(r lookup.Rec) { bldr.Add(r) })
	if err != nil {
		fr.Err = err.Error()
		u.logf(m.ID + " 失败: " + fr.Err)
		return fr
	}
	if bldr.Len() == 0 {
		fr.Err = "no rows parsed"
		u.logf(m.ID + " 没有解析出前缀，保留原快照")
		return fr
	}
	dir := filepath.Join(u.cfg.DataDir, "feeds")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fr.Err = err.Error()
		return fr
	}
	path := filepath.Join(dir, m.ID+".ipds")
	if err := bldr.CommitFile(path); err != nil {
		fr.Err = err.Error()
		return fr
	}
	metaPath := filepath.Join(dir, m.ID+".meta.json")
	if raw, err := json.Marshal(bldr.Meta); err == nil {
		_ = os.WriteFile(metaPath, raw, 0o644)
	}
	if u.eng != nil {
		n, err := u.eng.InstallSnapshot(path)
		if err != nil {
			fr.Err = err.Error()
			return fr
		}
		fr.Rows = n
	} else {
		fr.Rows = bldr.Len()
	}
	u.logf(fmt.Sprintf("%s 已更新 %d 条", m.ID, fr.Rows))
	return fr
}

func (u *updater) writeSnapshot(m lookup.SourceMeta, rows []lookup.SourceRow) error {
	dir := filepath.Join(u.cfg.DataDir, "feeds")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, m.ID+".tsv")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriterSize(f, 1<<20)
	for _, row := range rows {
		rec := row.Rec
		org := strings.ReplaceAll(rec.Org, "\t", " ")
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n",
			rec.Prefix, rec.ASN, rec.CC, org, rec.ASType, strings.Join(rec.Flags, "|"), rec.Cloud, rec.RegisteredCC)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	metaPath := filepath.Join(dir, m.ID+".meta.json")
	b, _ := json.Marshal(m)
	return os.WriteFile(metaPath, b, 0o644)
}

func readSnapshot(tsv, metaPath string) ([]lookup.SourceRow, lookup.SourceMeta, error) {
	var m lookup.SourceMeta
	if b, err := os.ReadFile(metaPath); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	f, err := os.Open(tsv)
	if err != nil {
		return nil, m, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var rows []lookup.SourceRow
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) < 1 || f[0] == "" {
			continue
		}
		rec := lookup.Rec{Prefix: f[0]}
		if len(f) > 1 {
			rec.ASN, _ = strconv.Atoi(f[1])
		}
		if len(f) > 2 {
			rec.CC = f[2]
		}
		if len(f) > 3 {
			rec.Org = f[3]
		}
		if len(f) > 4 {
			rec.ASType = f[4]
		}
		if len(f) > 5 && f[5] != "" {
			rec.Flags = strings.Split(f[5], "|")
		}
		if len(f) > 6 {
			rec.Cloud = f[6]
		}
		if len(f) > 7 {
			rec.RegisteredCC = f[7]
		}
		rows = append(rows, lookup.SourceRow{Source: m.ID, Rec: rec})
	}
	return rows, m, sc.Err()
}

func (u *updater) cloud(ctx context.Context) FeedResult {
	u.logf("下载云厂商网段")
	var rows []lookup.SourceRow
	var used []string
	var errs []string
	parts := []struct {
		urls  []string
		parse func([]byte) ([]lookup.SourceRow, error)
	}{
		{[]string{"https://ip-ranges.amazonaws.com/ip-ranges.json"}, func(b []byte) ([]lookup.SourceRow, error) { return parseAWS(b, 0) }},
		{[]string{"https://www.gstatic.com/ipranges/cloud.json"}, func(b []byte) ([]lookup.SourceRow, error) { return parseGCP(b, 0) }},
		{[]string{"https://www.cloudflare.com/ips-v4"}, func(b []byte) ([]lookup.SourceRow, error) { return parseCloudflare(b) }},
		{[]string{"https://www.cloudflare.com/ips-v6"}, func(b []byte) ([]lookup.SourceRow, error) { return parseCloudflare(b) }},
		{[]string{"https://raw.githubusercontent.com/femueller/cloud-ip-ranges/master/microsoft-azure-ip-ranges.json"}, func(b []byte) ([]lookup.SourceRow, error) {
			return parseAzure(b, 0)
		}},
	}
	for _, p := range parts {
		b, url, err := u.fetch(ctx, p.urls, 40<<20)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		got, err := p.parse(b)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		rows = append(rows, got...)
		used = append(used, url)
	}
	note := ""
	if len(errs) > 0 {
		note = strings.Join(errs, "; ")
	}
	m := meta("cloud_ranges", "provider terms, public ranges", "Official cloud IP range publications (AWS, GCP, Azure, Cloudflare)", "https://ip-ranges.amazonaws.com/ip-ranges.json", "day")
	fr := u.apply("cloud_ranges", m, rows, strings.Join(used, " "), note, nil)
	if fr.Rows == 0 && note != "" {
		fr.Err = note
	}
	return fr
}

func (u *updater) list(ctx context.Context, id string, urls []string, rec lookup.Rec, attr, page string) []FeedResult {
	u.logf("下载 " + id)
	b, url, err := u.fetch(ctx, urls, 30<<20)
	if err != nil {
		return []FeedResult{u.apply(id, meta(id, "source terms", attr, page, "day"), nil, "", "", err)}
	}
	rows, perr := parseCIDRList(b, id, rec, 0)
	if perr != nil {
		err = perr
	}
	return []FeedResult{u.apply(id, meta(id, "source terms", attr, page, "day"), rows, url, "", err)}
}

func (u *updater) spamhaus(ctx context.Context) FeedResult {
	u.logf("下载 Spamhaus DROP")
	var rows []lookup.SourceRow
	var urls []string
	var errs []string
	for _, raw := range []string{"https://www.spamhaus.org/drop/drop.txt", "https://www.spamhaus.org/drop/edrop.txt"} {
		b, url, err := u.fetch(ctx, []string{raw}, 5<<20)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		got, err := parseCIDRList(b, "spamhaus_drop", lookup.Rec{Flags: []string{"malicious"}}, 0)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		rows = append(rows, got...)
		urls = append(urls, url)
	}
	m := meta("spamhaus_drop", "Spamhaus terms", "Spamhaus DROP and EDROP", "https://www.spamhaus.org/drop/", "day")
	fr := u.apply("spamhaus_drop", m, rows, strings.Join(urls, " "), strings.Join(errs, "; "), nil)
	if fr.Rows == 0 && len(errs) > 0 {
		fr.Err = strings.Join(errs, "; ")
	}
	return fr
}

func (u *updater) x4b(ctx context.Context) FeedResult {
	u.logf("下载 X4BNet")
	var rows []lookup.SourceRow
	var urls []string
	var errs []string
	specs := []struct {
		url string
		rec lookup.Rec
	}{
		{"https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt", lookup.Rec{Flags: []string{"vpn"}}},
		{"https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt", lookup.Rec{ASType: "hosting", Flags: []string{"hosting"}}},
	}
	for _, s := range specs {
		b, url, err := u.fetch(ctx, []string{s.url}, 40<<20)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		got, err := parseCIDRList(b, "x4bnet", s.rec, 0)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		rows = append(rows, got...)
		urls = append(urls, url)
	}
	m := meta("x4bnet", "source terms", "X4BNet VPN and datacenter lists", "https://github.com/X4BNet/lists_vpn", "day")
	fr := u.apply("x4bnet", m, rows, strings.Join(urls, " "), strings.Join(errs, "; "), nil)
	if fr.Rows == 0 && len(errs) > 0 {
		fr.Err = strings.Join(errs, "; ")
	}
	return fr
}

func (u *updater) dbip(ctx context.Context) FeedResult {
	kind := "country"
	if u.cfg.DBIPCity {
		kind = "city"
	}
	now := time.Now().UTC()
	var urls []string
	for _, t := range []time.Time{now, now.AddDate(0, -1, 0)} {
		urls = append(urls, fmt.Sprintf("https://download.db-ip.com/free/dbip-%s-lite-%s.csv.gz", kind, t.Format("2006-01")))
	}
	u.logf("下载 DB-IP " + kind + " lite")
	b, url, err := u.fetch(ctx, urls, 256<<20)
	if err != nil {
		return u.apply("dbip_lite", lookup.SourceMeta{}, nil, "", "", err)
	}
	m := meta("dbip_lite", "CC BY 4.0", "IP Geolocation by DB-IP", url, "month")
	return u.streamRows(m, url, "", func(add func(lookup.Rec)) error {
		return walkDBIP(bytes.NewReader(b), "dbip_lite", 0, func(row lookup.SourceRow) error {
			add(row.Rec)
			return nil
		})
	})
}

func (u *updater) rir(ctx context.Context) FeedResult {
	u.logf("下载 RIR delegated-extended")
	urls := []string{
		"https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
		"https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
		"https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
		"https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
		"https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
	}
	var rows []lookup.SourceRow
	var gotURL []string
	var errs []string
	for _, raw := range urls {
		b, url, err := u.fetch(ctx, []string{raw}, 40<<20)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		part, err := parseRIR(b, "rir_delegated", 0)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		rows = append(rows, part...)
		gotURL = append(gotURL, url)
	}
	m := meta("rir_delegated", "RIR statistics", "ARIN, RIPE, APNIC, LACNIC, AFRINIC delegated-extended", "https://ftp.ripe.net/pub/stats/", "day")
	fr := u.apply("rir_delegated", m, rows, strings.Join(gotURL, " "), strings.Join(errs, "; "), nil)
	if fr.Rows == 0 && len(errs) > 0 {
		fr.Err = strings.Join(errs, "; ")
	}
	return fr
}

func (u *updater) asn(ctx context.Context) FeedResult {
	u.logf("下载 prefix-to-ASN")
	b, url, err := u.fetch(ctx, []string{
		"https://bgp.tools/table.txt",
		"https://iptoasn.com/data/ip2asn-v4.tsv.gz",
		"https://iptoasn.com/data/ip2asn-v4.tsv",
	}, 256<<20)
	if err != nil {
		return u.apply("bgp", lookup.SourceMeta{}, nil, "", "", err)
	}
	m := meta("bgp", "public BGP table", "bgp.tools / RIPE RIS / RouteViews derived prefix-to-ASN", url, "day")
	return u.streamRows(m, url, "", func(add func(lookup.Rec)) error {
		return walkIP2ASN(bytes.NewReader(b), "bgp", 0, func(row lookup.SourceRow) error {
			add(row.Rec)
			return nil
		})
	})
}

func (u *updater) geolite(ctx context.Context) FeedResult {
	if u.cfg.MaxMindKey == "" {
		return FeedResult{ID: "maxmind_geolite", Note: "skipped: IPD_MAXMIND_KEY is not set"}
	}
	u.logf("下载 GeoLite2-City")
	raw := "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=" + u.cfg.MaxMindKey + "&suffix=tar.gz"
	b, _, err := u.fetch(ctx, []string{raw}, 80<<20)
	if err != nil {
		return FeedResult{ID: "maxmind_geolite", Err: err.Error(), Note: "token was not logged"}
	}
	path := filepath.Join(u.cfg.DataDir, "GeoLite2-City.mmdb")
	if err := extractMMDB(b, path); err != nil {
		return FeedResult{ID: "maxmind_geolite", Err: err.Error()}
	}
	if u.eng != nil {
		if err := u.eng.AttachMMDB(path); err != nil {
			return FeedResult{ID: "maxmind_geolite", Err: err.Error()}
		}
	}
	u.logf("GeoLite2-City 已写入 " + path)
	return FeedResult{ID: "maxmind_geolite", Rows: 1, URL: path, Note: "mmdb attached; not expanded into the prefix index"}
}

func extractMMDB(b []byte, dest string) error {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer r.Close()
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if hdr.FileInfo().IsDir() || !strings.HasSuffix(hdr.Name, ".mmdb") {
			continue
		}
		f, err := os.Create(dest)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(f, io.LimitReader(tr, 120<<20))
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	}
	return fmt.Errorf("tar.gz contained no mmdb")
}

func (u *updater) ipinfo(ctx context.Context) FeedResult {
	token := ""
	if u.cfg.ProviderKeys != nil {
		token = u.cfg.ProviderKeys["ipinfo"]
	}
	if token == "" {
		return FeedResult{ID: "ipinfo_lite", Note: "skipped: IPD_IPINFO_TOKEN is not set"}
	}
	u.logf("下载 IPinfo Lite")
	urls := []string{
		"https://ipinfo.io/data/free/ipinfo_lite.csv.gz?token=" + token,
		"https://ipinfo.io/data/ipinfo_lite.csv.gz?token=" + token,
	}
	b, url, err := u.fetch(ctx, urls, 80<<20)
	if err != nil {
		return FeedResult{ID: "ipinfo_lite", Err: err.Error(), Note: "token was not logged"}
	}
	rows, err := parseIPinfoLite(b, "ipinfo_lite", 0)
	m := meta("ipinfo_lite", "CC BY-SA 4.0", "IP address data powered by IPinfo", "https://ipinfo.io/data/free/ipinfo_lite", "day")
	fr := u.apply("ipinfo_lite", m, rows, "ipinfo lite", "", err)
	_ = url
	return fr
}
