package ingest

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"ipd/internal/lookup"
)

func meta(id, license, attr, url, freq string) lookup.SourceMeta {
	return lookup.SourceMeta{
		ID: id, Kind: "local", Version: time.Now().UTC().Format("2006-01-02"),
		UpdatedAt: time.Now().UTC(), Frequency: freq, License: license,
		Attribution: attr, URL: url, Redistributable: true, Enabled: true,
	}
}

func row(source, prefix string, rec lookup.Rec) lookup.SourceRow {
	rec.Prefix = prefix
	return lookup.SourceRow{Source: source, Rec: rec}
}

func parseDBIP(b []byte, source string, max int) ([]lookup.SourceRow, error) {
	var out []lookup.SourceRow
	err := walkDBIP(bytes.NewReader(b), source, max, func(row lookup.SourceRow) error {
		out = append(out, row)
		return nil
	})
	return out, err
}

// walkDBIP streams DB-IP lite rows. max <= 0 means the whole file.
func walkDBIP(r io.Reader, source string, max int, emit func(lookup.SourceRow) error) error {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	n := 0
	for {
		f, err := cr.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if len(f) < 3 {
			continue
		}
		start, err1 := netip.ParseAddr(strings.TrimSpace(f[0]))
		end, err2 := netip.ParseAddr(strings.TrimSpace(f[1]))
		if err1 != nil || err2 != nil {
			continue
		}
		// Country lite is start,end,cc. City lite is start,end,continent,cc,state,city,lat,lon.
		ccIdx := 2
		if len(f) >= 6 {
			ccIdx = 3
		}
		cc := strings.ToUpper(strings.TrimSpace(f[ccIdx]))
		if cc == "" || cc == "ZZ" {
			continue
		}
		rec := lookup.Rec{CC: cc}
		if len(f) >= 6 {
			rec.Region = strings.TrimSpace(f[4])
			rec.City = strings.TrimSpace(f[5])
		}
		if len(f) >= 8 {
			rec.Lat, _ = strconv.ParseFloat(strings.TrimSpace(f[6]), 64)
			rec.Lon, _ = strconv.ParseFloat(strings.TrimSpace(f[7]), 64)
		}
		for _, p := range prefixesBetween(start, end) {
			if err := emit(row(source, p.String(), rec)); err != nil {
				return err
			}
			n++
			if max > 0 && n >= max {
				return nil
			}
		}
	}
}

func parseRIR(b []byte, source string, max int) ([]lookup.SourceRow, error) {
	var out []lookup.SourceRow
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "|")
		if len(f) < 7 {
			continue
		}
		kind := f[2]
		status := f[6]
		if status != "allocated" && status != "assigned" {
			continue
		}
		cc := strings.ToUpper(f[1])
		if cc == "" || cc == "*" || cc == "ZZ" {
			continue
		}
		rec := lookup.Rec{CC: cc, RegisteredCC: cc}
		switch kind {
		case "ipv4":
			start, err := netip.ParseAddr(f[3])
			if err != nil {
				continue
			}
			n, err := strconv.ParseUint(f[4], 10, 64)
			if err != nil || n == 0 {
				continue
			}
			end, ok := addOffset(start, n-1)
			if !ok {
				continue
			}
			for _, p := range prefixesBetween(start, end) {
				out = append(out, row(source, p.String(), rec))
				if max > 0 && len(out) >= max {
					return out, nil
				}
			}
		case "ipv6":
			start, err := netip.ParseAddr(f[3])
			if err != nil {
				continue
			}
			bitsN, err := strconv.Atoi(f[4])
			if err != nil || bitsN <= 0 || bitsN > start.BitLen() {
				continue
			}
			p := netip.PrefixFrom(start, bitsN).Masked()
			out = append(out, row(source, p.String(), rec))
			if max > 0 && len(out) >= max {
				return out, nil
			}
		}
	}
	return out, sc.Err()
}

func parseAWS(b []byte, max int) ([]lookup.SourceRow, error) {
	var doc struct {
		Prefixes []struct {
			Prefix string `json:"ip_prefix"`
		} `json:"prefixes"`
		V6 []struct {
			Prefix string `json:"ipv6_prefix"`
		} `json:"ipv6_prefixes"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	var out []lookup.SourceRow
	add := func(p string) {
		if !validPrefix(p) {
			return
		}
		out = append(out, row("cloud_ranges", p, lookup.Rec{ASN: 16509, Org: "Amazon.com, Inc.", Cloud: "aws", ASType: "hosting"}))
	}
	for _, p := range doc.Prefixes {
		add(p.Prefix)
		if max > 0 && len(out) >= max {
			return out, nil
		}
	}
	for _, p := range doc.V6 {
		add(p.Prefix)
		if max > 0 && len(out) >= max {
			return out, nil
		}
	}
	return out, nil
}

func parseGCP(b []byte, max int) ([]lookup.SourceRow, error) {
	var doc struct {
		Prefixes []struct {
			V4 string `json:"ipv4Prefix"`
			V6 string `json:"ipv6Prefix"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	var out []lookup.SourceRow
	for _, p := range doc.Prefixes {
		cidr := p.V4
		if cidr == "" {
			cidr = p.V6
		}
		if !validPrefix(cidr) {
			continue
		}
		out = append(out, row("cloud_ranges", cidr, lookup.Rec{ASN: 15169, Org: "Google Cloud", Cloud: "gcp", ASType: "hosting"}))
		if max > 0 && len(out) >= max {
			return out, nil
		}
	}
	return out, nil
}

func parseAzure(b []byte, max int) ([]lookup.SourceRow, error) {
	var doc struct {
		Values []struct {
			Properties struct {
				AddressPrefixes []string `json:"addressPrefixes"`
			} `json:"properties"`
		} `json:"values"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	var out []lookup.SourceRow
	seen := map[string]struct{}{}
	for _, v := range doc.Values {
		for _, p := range v.Properties.AddressPrefixes {
			if !validPrefix(p) {
				continue
			}
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, row("cloud_ranges", p, lookup.Rec{ASN: 8075, Org: "Microsoft Azure", Cloud: "azure", ASType: "hosting"}))
			if max > 0 && len(out) >= max {
				return out, nil
			}
		}
	}
	return out, nil
}

func parseCloudflare(b []byte) ([]lookup.SourceRow, error) {
	var out []lookup.SourceRow
	for _, line := range lines(b) {
		if !validPrefix(line) {
			continue
		}
		out = append(out, row("cloud_ranges", line, lookup.Rec{ASN: 13335, Org: "Cloudflare", Cloud: "cloudflare", ASType: "cdn", Flags: []string{"anycast"}}))
	}
	return out, nil
}

func parseCIDRList(b []byte, source string, rec lookup.Rec, max int) ([]lookup.SourceRow, error) {
	var out []lookup.SourceRow
	for _, line := range lines(b) {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		token := strings.TrimRight(fields[0], ";")
		if ip, err := netip.ParseAddr(token); err == nil {
			bitsN := 32
			if ip.Is6() {
				bitsN = 128
			}
			token = netip.PrefixFrom(ip, bitsN).String()
		}
		if !validPrefix(token) {
			continue
		}
		out = append(out, row(source, token, rec))
		if max > 0 && len(out) >= max {
			return out, nil
		}
	}
	return out, nil
}

func parseIP2ASN(b []byte, source string, max int) ([]lookup.SourceRow, error) {
	var out []lookup.SourceRow
	err := walkIP2ASN(bytes.NewReader(b), source, max, func(row lookup.SourceRow) error {
		out = append(out, row)
		return nil
	})
	return out, err
}

// walkIP2ASN streams a prefix-to-ASN table. max <= 0 keeps every prefix.
func walkIP2ASN(r io.Reader, source string, max int, emit func(lookup.SourceRow) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	n := 0
	stop := func() bool { return max > 0 && n >= max }
	for sc.Scan() {
		if stop() {
			return nil
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 2 {
			f = strings.Fields(line)
		}
		if len(f) < 2 {
			continue
		}
		if strings.Contains(f[0], "/") && validPrefix(f[0]) {
			asn, _ := strconv.Atoi(strings.TrimPrefix(f[1], "AS"))
			cc, org := "", ""
			if len(f) >= 3 {
				cc = f[2]
			}
			if len(f) >= 4 {
				org = strings.Join(f[3:], " ")
			}
			if err := emit(row(source, f[0], lookup.Rec{ASN: asn, CC: cc, Org: org, AnnouncedCC: cc})); err != nil {
				return err
			}
			n++
		} else if start, err1 := netip.ParseAddr(f[0]); err1 == nil && len(f) >= 3 {
			end, err2 := netip.ParseAddr(f[1])
			if err2 != nil {
				continue
			}
			asn, _ := strconv.Atoi(strings.TrimPrefix(f[2], "AS"))
			cc, org := "", ""
			if len(f) >= 4 {
				cc = f[3]
			}
			if len(f) >= 5 {
				org = strings.Join(f[4:], " ")
			}
			rec := lookup.Rec{ASN: asn, CC: cc, Org: org, AnnouncedCC: cc}
			for _, p := range prefixesBetween(start, end) {
				if stop() {
					return nil
				}
				if err := emit(row(source, p.String(), rec)); err != nil {
					return err
				}
				n++
			}
		}
	}
	return sc.Err()
}

func parseIPinfoLite(b []byte, source string, max int) ([]lookup.SourceRow, error) {
	r := csv.NewReader(bytes.NewReader(b))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	header, err := r.Read()
	if err != nil {
		return nil, err
	}
	col := map[string]int{}
	for i, h := range header {
		col[strings.ToLower(strings.TrimSpace(h))] = i
	}
	// A headerless file is treated as rows. Put the first record back when it is data.
	var pending [][]string
	_, hasNet := col["network"]
	_, hasStart := col["start_ip"]
	if !hasNet && !hasStart && len(header) > 0 {
		if _, err := netip.ParsePrefix(strings.TrimSpace(header[0])); err == nil || validIP(header[0]) {
			pending = append(pending, header)
		}
	}
	var out []lookup.SourceRow
	take := func(f []string) {
		get := func(names ...string) string {
			for _, n := range names {
				if i, ok := col[n]; ok && i < len(f) {
					return strings.TrimSpace(f[i])
				}
			}
			return ""
		}
		var prefixes []netip.Prefix
		if netw := get("network", "range", "prefix"); validPrefix(netw) {
			p, _ := netip.ParsePrefix(netw)
			prefixes = []netip.Prefix{p.Masked()}
		} else if len(f) >= 2 {
			s, e1 := netip.ParseAddr(strings.TrimSpace(f[0]))
			e, e2 := netip.ParseAddr(strings.TrimSpace(f[1]))
			if e1 == nil && e2 == nil {
				prefixes = prefixesBetween(s, e)
			} else if p, err := netip.ParsePrefix(strings.TrimSpace(f[0])); err == nil {
				prefixes = []netip.Prefix{p.Masked()}
			}
		}
		cc := strings.ToUpper(get("country_code", "country"))
		if len(cc) > 2 {
			cc = ""
		}
		asnText := strings.TrimPrefix(get("asn", "as"), "AS")
		asn, _ := strconv.Atoi(asnText)
		org := get("as_name", "org", "name")
		for _, p := range prefixes {
			out = append(out, row(source, p.String(), lookup.Rec{ASN: asn, CC: cc, Org: org}))
			if max > 0 && len(out) >= max {
				return
			}
		}
	}
	for _, f := range pending {
		take(f)
	}
	for {
		f, err := r.Read()
		if err != nil {
			break
		}
		take(f)
		if max > 0 && len(out) >= max {
			break
		}
	}
	return out, nil
}

func lines(b []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func validPrefix(s string) bool {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	return err == nil && p.IsValid()
}

func validIP(s string) bool {
	_, err := netip.ParseAddr(strings.TrimSpace(s))
	return err == nil
}
