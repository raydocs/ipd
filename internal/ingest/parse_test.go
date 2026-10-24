package ingest

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"ipd/internal/config"
	"ipd/internal/lookup"
)

func TestPrefixesBetween(t *testing.T) {
	one := prefixesBetween(netip.MustParseAddr("1.2.3.0"), netip.MustParseAddr("1.2.3.255"))
	if len(one) != 1 || one[0].String() != "1.2.3.0/24" {
		t.Fatal(one)
	}
	eight := prefixesBetween(netip.MustParseAddr("12.0.0.0"), netip.MustParseAddr("12.255.255.255"))
	if len(eight) != 1 || eight[0].String() != "12.0.0.0/8" {
		t.Fatal(eight)
	}
	host := prefixesBetween(netip.MustParseAddr("9.9.9.9"), netip.MustParseAddr("9.9.9.9"))
	if len(host) != 1 || host[0].String() != "9.9.9.9/32" {
		t.Fatal(host)
	}
}

func TestParseFeeds(t *testing.T) {
	dbip, err := parseDBIP([]byte("1.2.3.0,1.2.3.255,US\n8.8.8.0,8.8.8.255,AS,US,California,Mountain View,37.4,-122.1\n"), "dbip_lite", 0)
	if err != nil || len(dbip) != 2 || dbip[1].Rec.CC != "US" || dbip[1].Rec.City != "Mountain View" {
		t.Fatalf("%v %+v", err, dbip)
	}
	rir, err := parseRIR([]byte("ripencc|US|ipv4|12.0.0.0|16777216|19950901|allocated\n# skip\n"), "rir_delegated", 0)
	if err != nil || len(rir) != 1 || rir[0].Rec.Prefix != "12.0.0.0/8" || rir[0].Rec.RegisteredCC != "US" {
		t.Fatalf("%v %+v", err, rir)
	}
	aws, err := parseAWS([]byte(`{"prefixes":[{"ip_prefix":"3.5.0.0/16"}],"ipv6_prefixes":[{"ipv6_prefix":"2600:1f00::/40"}]}`), 0)
	if err != nil || len(aws) != 2 || aws[0].Rec.Cloud != "aws" {
		t.Fatalf("%v %+v", err, aws)
	}
	cf, err := parseCloudflare([]byte("# cf\n1.1.1.0/24\n"))
	if err != nil || len(cf) != 1 || cf[0].Rec.Cloud != "cloudflare" {
		t.Fatal(err, cf)
	}
	drop, err := parseCIDRList([]byte("; comment\n9.9.9.0/24 ; SBL1\n203.0.113.9\n"), "spamhaus_drop", lookup.Rec{Flags: []string{"malicious"}}, 0)
	if err != nil || len(drop) != 2 || drop[1].Rec.Prefix != "203.0.113.9/32" {
		t.Fatal(err, drop)
	}
	asn, err := parseIP2ASN([]byte("1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n8.8.8.0/24 15169\n"), "bgp", 0)
	if err != nil || len(asn) != 2 || asn[0].Rec.ASN != 13335 || asn[1].Rec.ASN != 15169 {
		t.Fatal(err, asn)
	}
	info, err := parseIPinfoLite([]byte("network,country,country_code,asn,as_name\n1.1.1.0/24,US,US,AS13335,Cloudflare\n"), "ipinfo_lite", 0)
	if err != nil || len(info) != 1 || info[0].Rec.ASN != 13335 || info[0].Rec.CC != "US" {
		t.Fatal(err, info)
	}
}

func TestUpdaterKeepsOtherSources(t *testing.T) {
	dir := t.TempDir()
	eng := lookup.New()
	if eng.Lookup(netip.MustParseAddr("24.1.2.3")).ASN == 0 {
		t.Fatal("fixture missing")
	}
	u := &updater{
		cfg:  &config.Config{DataDir: dir},
		eng:  eng,
		logf: func(string) {},
		get: func(ctx context.Context, raw string, max int64) ([]byte, error) {
			switch {
			case strings.Contains(raw, "amazonaws"):
				return []byte(`{"prefixes":[{"ip_prefix":"3.5.0.0/16"}]}`), nil
			case strings.Contains(raw, "cloudflare.com/ips-v4"):
				return []byte("1.1.1.0/24\n"), nil
			default:
				return nil, errSkip(raw)
			}
		},
	}
	fr := u.cloud(context.Background())
	if fr.Rows < 2 {
		t.Fatal(fr)
	}
	if eng.Lookup(netip.MustParseAddr("24.1.2.3")).ASN == 0 {
		t.Fatal("merge wiped unrelated fixture rows")
	}
	if eng.Lookup(netip.MustParseAddr("3.5.1.1")).Cloud != "aws" {
		t.Fatalf("aws %+v", eng.Lookup(netip.MustParseAddr("3.5.1.1")))
	}
	b, err := readSnapshotFile(dir)
	if err != nil || !strings.Contains(b, "3.5.0.0/16") {
		t.Fatal(err, b)
	}
}

type skipErr string

func (e skipErr) Error() string { return string(e) }

func errSkip(s string) error { return skipErr(s) }

func readSnapshotFile(dir string) (string, error) {
	snap, err := readFeedSnapshot(dir+"/feeds/cloud_ranges"+feedSnapshotSuffix, "cloud_ranges")
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, r := range snap.Rows {
		b.WriteString(r.Rec.Prefix)
		b.WriteByte('\n')
	}
	return b.String(), nil
}

func TestLoadSnapshot(t *testing.T) {
	dir := t.TempDir()
	src := lookup.New()
	u := &updater{cfg: &config.Config{DataDir: dir}, eng: src, logf: func(string) {}, get: func(ctx context.Context, raw string, max int64) ([]byte, error) {
		if strings.Contains(raw, "torbulk") {
			return []byte("185.220.101.50\n"), nil
		}
		return nil, errSkip(raw)
	}}
	got := u.list(context.Background(), "tor_exits", []string{"https://check.torproject.org/torbulkexitlist"}, lookup.Rec{Flags: []string{"tor"}}, "Tor", "https://check.torproject.org/torbulkexitlist")
	if len(got) != 1 || got[0].Rows != 1 {
		t.Fatal(got)
	}
	dst := lookup.New()
	if err := Load(dst, &config.Config{DataDir: dir}); err != nil {
		t.Fatal(err)
	}
	p := dst.Lookup(netip.MustParseAddr("185.220.101.50"))
	if !p.HasFlag("tor") {
		t.Fatalf("%+v", p)
	}
	_ = time.Now()
}
