package lookup

import "time"

// Bundled is the offline snapshot shipped with the binary. It is a curated
// sample of freely redistributable signals plus structural placeholders so
// lookup, scoring, and tests work with no network and no MaxMind file.
// `ipd ingest` replaces it with a fuller snapshot built from public feeds.
func Bundled() snapshot {
	updated := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	meta := []SourceMeta{
		{ID: "ipinfo_lite", Kind: "local", Version: "fixture-2026.10.23", UpdatedAt: updated, Frequency: "day", License: "CC BY-SA 4.0", Attribution: "IP address data powered by IPinfo", URL: "https://ipinfo.io/lite", Redistributable: true, Enabled: true},
		{ID: "dbip_lite", Kind: "local", Version: "fixture-2026.10", UpdatedAt: updated, Frequency: "month", License: "CC BY 4.0", Attribution: "IP Geolocation by DB-IP", URL: "https://db-ip.com", Redistributable: true, Enabled: true},
		{ID: "ip2location_lite", Kind: "local", Version: "fixture-2026.10", UpdatedAt: updated, Frequency: "month", License: "IP2Location LITE", Attribution: "This site or product includes IP2Location LITE data available from https://lite.ip2location.com", URL: "https://lite.ip2location.com", Redistributable: false, Enabled: true},
		{ID: "ip2region", Kind: "local", Version: "fixture-2026.10", UpdatedAt: updated, Frequency: "month", License: "Apache-2.0", Attribution: "ip2region https://github.com/lionsoul2014/ip2region", URL: "https://github.com/lionsoul2014/ip2region", Redistributable: true, Enabled: true},
		{ID: "cloud_ranges", Kind: "local", Version: "fixture-2026.10.23", UpdatedAt: updated, Frequency: "day", License: "provider terms, public ranges", Attribution: "Official cloud IP range publications (AWS, GCP, Azure, Cloudflare, and others)", Redistributable: true, Enabled: true},
		{ID: "peeringdb", Kind: "local", Version: "fixture-2026.10.23", UpdatedAt: updated, Frequency: "day", License: "PeeringDB AUP", Attribution: "Derived AS type from PeeringDB", URL: "https://www.peeringdb.com", Redistributable: true, Enabled: true},
		{ID: "rir_delegated", Kind: "local", Version: "fixture-2026.10.23", UpdatedAt: updated, Frequency: "day", License: "RIR delegated statistics", Attribution: "ARIN, RIPE, APNIC, LACNIC, AFRINIC delegated stats (derived)", Redistributable: true, Enabled: true},
		{ID: "geofeed", Kind: "local", Version: "fixture-2026.10.23", UpdatedAt: updated, Frequency: "week", License: "public RFC 8805", Attribution: "Operator geofeed (RFC 8805)", Redistributable: true, Enabled: true},
		{ID: "bgp", Kind: "local", Version: "fixture-2026.10.23", UpdatedAt: updated, Frequency: "day", License: "bgp.tools ToS / RIPE RIS / RouteViews", Attribution: "Derived from public BGP table data", URL: "https://bgp.tools", Redistributable: true, Enabled: true},
		{ID: "tor_exits", Kind: "local", Version: "fixture-2026.10.23", UpdatedAt: updated, Frequency: "hour", License: "Tor exit list", Attribution: "Tor Project exit list", URL: "https://check.torproject.org/torbulkexitlist", Redistributable: true, Enabled: true},
		{ID: "vpn_lists", Kind: "local", Version: "fixture-2026.10.23", UpdatedAt: updated, Frequency: "day", License: "mixed open lists (MIT and others)", Attribution: "Public VPN prefix lists", Redistributable: true, Enabled: true},
		{ID: "firehol", Kind: "local", Version: "fixture-2026.10.23", UpdatedAt: updated, Frequency: "day", License: "FireHOL / Spamhaus DROP / abuse.ch", Attribution: "FireHOL level1, Spamhaus DROP/EDROP, abuse.ch (per their terms)", Redistributable: true, Enabled: true},
		{ID: "apnic_eyeball", Kind: "local", Version: "fixture-2026.10", UpdatedAt: updated, Frequency: "month", License: "APNIC Labs", Attribution: "AS user population estimates by APNIC Labs", URL: "https://labs.apnic.net", Redistributable: true, Enabled: true},
		{ID: "rtt_matrix", Kind: "local", Version: "fixture-2026.10.23", UpdatedAt: updated, Frequency: "day", License: "own measurement", Attribution: "ipd probe RTT trilateration (self)", Redistributable: true, Enabled: true},
		{ID: "maxmind_geolite", Kind: "local", Version: "", UpdatedAt: time.Time{}, Frequency: "week", License: "MaxMind GeoLite2 EULA + CC BY-SA 4.0", Attribution: "This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com", URL: "https://www.maxmind.com", Redistributable: false, Enabled: false},
	}
	var rows []SourceRow
	add := func(source string, r Rec) {
		rows = append(rows, SourceRow{Source: source, Rec: r})
	}

	// Cloudflare DNS / CDN.
	add("ipinfo_lite", Rec{Prefix: "1.1.1.0/24", ASN: 13335, Org: "Cloudflare, Inc.", CC: "US", ASType: "cdn"})
	add("dbip_lite", Rec{Prefix: "1.1.1.0/24", ASN: 13335, Org: "Cloudflare", CC: "US", City: "Anycast", Lat: 0, Lon: 0})
	add("ip2location_lite", Rec{Prefix: "1.1.1.0/24", ASN: 13335, CC: "US", Region: "California"})
	add("cloud_ranges", Rec{Prefix: "1.1.1.0/24", ASN: 13335, Org: "Cloudflare", Cloud: "cloudflare", Flags: []string{"anycast"}})
	add("cloud_ranges", Rec{Prefix: "1.0.0.0/24", ASN: 13335, Org: "Cloudflare", Cloud: "cloudflare", Flags: []string{"anycast"}})
	add("cloud_ranges", Rec{Prefix: "104.16.0.0/12", ASN: 13335, Org: "Cloudflare", Cloud: "cloudflare", Flags: []string{"anycast"}})
	add("peeringdb", Rec{Prefix: "1.1.1.0/24", ASN: 13335, Org: "Cloudflare", ASType: "content"})
	add("bgp", Rec{Prefix: "1.1.1.0/24", ASN: 13335, Org: "Cloudflare, Inc.", AnnouncedCC: "US", PrefixAgeDays: 2000})
	add("rir_delegated", Rec{Prefix: "1.1.1.0/24", ASN: 13335, RegisteredCC: "AU", NetName: "APNIC-ANYCAST", Descr: "Cloudflare DNS"})
	add("geofeed", Rec{Prefix: "1.1.1.0/24", GeofeedCC: "US"})
	add("rtt_matrix", Rec{Prefix: "1.1.1.0/24", RTTRegion: "anycast"})

	// Google DNS.
	add("ipinfo_lite", Rec{Prefix: "8.8.8.0/24", ASN: 15169, Org: "Google LLC", CC: "US", ASType: "hosting"})
	add("dbip_lite", Rec{Prefix: "8.8.8.0/24", ASN: 15169, Org: "Google", CC: "US"})
	add("cloud_ranges", Rec{Prefix: "8.8.8.0/24", ASN: 15169, Cloud: "gcp", Org: "Google"})
	add("bgp", Rec{Prefix: "8.8.8.0/24", ASN: 15169, AnnouncedCC: "US", Org: "Google LLC"})
	add("peeringdb", Rec{Prefix: "8.8.8.0/24", ASN: 15169, ASType: "content", Org: "Google"})
	add("rir_delegated", Rec{Prefix: "8.8.8.0/24", RegisteredCC: "US", NetName: "GOOGLE"})
	add("geofeed", Rec{Prefix: "8.8.8.0/24", GeofeedCC: "US"})

	// Quad9.
	add("ipinfo_lite", Rec{Prefix: "9.9.9.0/24", ASN: 19281, Org: "Quad9", CC: "US"})
	add("bgp", Rec{Prefix: "9.9.9.0/24", ASN: 19281, AnnouncedCC: "US", Org: "Quad9"})
	add("dbip_lite", Rec{Prefix: "9.9.9.0/24", CC: "US", ASN: 19281})
	add("rir_delegated", Rec{Prefix: "9.9.9.0/24", RegisteredCC: "US"})
	add("peeringdb", Rec{Prefix: "9.9.9.0/24", ASN: 19281, ASType: "content"})

	// Comcast residential, native US.
	add("ipinfo_lite", Rec{Prefix: "24.1.0.0/16", ASN: 7922, Org: "Comcast Cable Communications, LLC", CC: "US", Region: "California", City: "San Francisco", ASType: "isp", RDNS: "c-24-1-2-3.hsd1.ca.comcast.net"})
	add("dbip_lite", Rec{Prefix: "24.1.0.0/16", ASN: 7922, CC: "US", Region: "California", City: "San Francisco", Lat: 37.77, Lon: -122.42})
	add("ip2location_lite", Rec{Prefix: "24.1.0.0/16", ASN: 7922, CC: "US", Region: "California", City: "San Francisco"})
	add("peeringdb", Rec{Prefix: "24.1.0.0/16", ASN: 7922, ASType: "cable", Org: "Comcast"})
	add("rir_delegated", Rec{Prefix: "24.1.0.0/16", ASN: 7922, RegisteredCC: "US", NetName: "COMCAST-CABLE", Descr: "DYNAMIC BROADBAND FTTH", RDNS: "c-24-1-2-3.hsd1.ca.comcast.net"})
	add("bgp", Rec{Prefix: "24.1.0.0/16", ASN: 7922, Org: "Comcast Cable Communications, LLC", AnnouncedCC: "US", UpstreamASN: 7922, UpstreamType: "isp", PrefixAgeDays: 4000})
	add("geofeed", Rec{Prefix: "24.1.0.0/16", GeofeedCC: "US"})
	add("apnic_eyeball", Rec{Prefix: "24.1.0.0/16", ASN: 7922, Eyeball: 30000000})
	add("rtt_matrix", Rec{Prefix: "24.1.0.0/16", RTTRegion: "us"})

	// T-Mobile.
	add("ipinfo_lite", Rec{Prefix: "172.58.0.0/15", ASN: 21928, Org: "T-Mobile USA, Inc.", CC: "US", ASType: "mobile"})
	add("dbip_lite", Rec{Prefix: "172.58.0.0/15", ASN: 21928, CC: "US"})
	add("peeringdb", Rec{Prefix: "172.58.0.0/15", ASN: 21928, ASType: "mobile", Org: "T-Mobile"})
	add("rir_delegated", Rec{Prefix: "172.58.0.0/15", RegisteredCC: "US", NetName: "TMO-MOBILE", Descr: "MOBILE WIRELESS"})
	add("bgp", Rec{Prefix: "172.58.0.0/15", ASN: 21928, AnnouncedCC: "US", Org: "T-Mobile USA"})
	add("geofeed", Rec{Prefix: "172.58.0.0/15", GeofeedCC: "US"})
	add("apnic_eyeball", Rec{Prefix: "172.58.0.0/15", ASN: 21928, Eyeball: 10000000})
	add("rtt_matrix", Rec{Prefix: "172.58.0.0/16", RTTRegion: "us"})

	// Business enterprise.
	add("ipinfo_lite", Rec{Prefix: "12.1.0.0/16", ASN: 7018, Org: "AT&T Services, Inc.", CC: "US", ASType: "business"})
	add("dbip_lite", Rec{Prefix: "12.1.0.0/16", ASN: 7018, CC: "US"})
	add("peeringdb", Rec{Prefix: "12.1.0.0/16", ASN: 7018, ASType: "enterprise", Org: "AT&T"})
	add("rir_delegated", Rec{Prefix: "12.1.0.0/16", RegisteredCC: "US", NetName: "ATT-ENTERPRISE", Descr: "ENTERPRISE BUSINESS"})
	add("bgp", Rec{Prefix: "12.1.0.0/16", ASN: 7018, AnnouncedCC: "US", Org: "AT&T"})
	add("geofeed", Rec{Prefix: "12.1.0.0/16", GeofeedCC: "US"})

	// Suspected fake residential: registered to a cable ISP, announced by a hoster, no rDNS.
	add("ipinfo_lite", Rec{Prefix: "76.100.50.0/24", ASN: 64512, Org: "Example Hosting LLC", CC: "US", ASType: "isp"})
	add("dbip_lite", Rec{Prefix: "76.100.50.0/24", ASN: 64512, CC: "US", City: "Los Angeles"})
	add("peeringdb", Rec{Prefix: "76.100.50.0/24", ASN: 7922, ASType: "cable", Org: "Example Cable"})
	add("rir_delegated", Rec{Prefix: "76.100.50.0/24", ASN: 7922, RegisteredCC: "US", NetName: "EXAMPLE-CABLE", Descr: "BROADBAND", Org: "Example Cable Communications"})
	add("bgp", Rec{Prefix: "76.100.50.0/24", ASN: 64512, Org: "Example Hosting LLC", AnnouncedCC: "US", UpstreamASN: 64512, UpstreamType: "hosting", PrefixAgeDays: 20, ChangedAt: "2026-10-01"})
	add("geofeed", Rec{Prefix: "76.100.50.0/24", GeofeedCC: "US", GeofeedChanged: true})
	add("rtt_matrix", Rec{Prefix: "76.100.50.0/24", RTTRegion: "lax-colo"})
	add("cloud_ranges", Rec{Prefix: "76.100.50.0/24", ASN: 64512, Org: "Example Hosting LLC"})

	// Broadcast sample on a documentation prefix: US registration, HK geofeed, RTT elsewhere.
	add("ipinfo_lite", Rec{Prefix: "203.0.113.0/24", ASN: 64512, Org: "Example Host", CC: "HK", City: "Hong Kong"})
	add("dbip_lite", Rec{Prefix: "203.0.113.0/24", ASN: 64512, CC: "HK", City: "Hong Kong", Lat: 22.32, Lon: 114.17})
	add("rir_delegated", Rec{Prefix: "203.0.113.0/24", RegisteredCC: "US", NetName: "EXAMPLE-HOST", Descr: "HOSTING SERVER"})
	add("bgp", Rec{Prefix: "203.0.113.0/24", ASN: 64512, Org: "Example Host", AnnouncedCC: "US", UpstreamType: "hosting"})
	add("peeringdb", Rec{Prefix: "203.0.113.0/24", ASN: 64512, ASType: "hosting"})
	add("geofeed", Rec{Prefix: "203.0.113.0/24", GeofeedCC: "HK", GeofeedChanged: true, ChangedAt: "2026-09-01"})
	add("rtt_matrix", Rec{Prefix: "203.0.113.0/24", RTTRegion: "lax"})
	add("cloud_ranges", Rec{Prefix: "203.0.113.0/24", ASN: 64512, Cloud: "example"})

	// Tor exit sample.
	add("tor_exits", Rec{Prefix: "185.220.101.0/24", Flags: []string{"tor"}, ASN: 60729})
	add("ipinfo_lite", Rec{Prefix: "185.220.101.0/24", ASN: 60729, Org: "Stiftung Erneuerbare Freiheit", CC: "DE", ASType: "hosting"})
	add("bgp", Rec{Prefix: "185.220.101.0/24", ASN: 60729, AnnouncedCC: "DE"})
	add("dbip_lite", Rec{Prefix: "185.220.101.0/24", CC: "DE", ASN: 60729})
	add("rir_delegated", Rec{Prefix: "185.220.101.0/24", RegisteredCC: "DE"})
	add("peeringdb", Rec{Prefix: "185.220.101.0/24", ASN: 60729, ASType: "hosting"})

	// Public VPN sample.
	add("vpn_lists", Rec{Prefix: "193.138.218.0/24", Flags: []string{"vpn", "proxy"}, ASN: 9009})
	add("ipinfo_lite", Rec{Prefix: "193.138.218.0/24", ASN: 9009, Org: "M247 Europe SRL", CC: "GB", ASType: "hosting"})
	add("bgp", Rec{Prefix: "193.138.218.0/24", ASN: 9009, AnnouncedCC: "GB", UpstreamType: "hosting"})
	add("dbip_lite", Rec{Prefix: "193.138.218.0/24", CC: "GB", ASN: 9009})
	add("peeringdb", Rec{Prefix: "193.138.218.0/24", ASN: 9009, ASType: "hosting"})
	add("rir_delegated", Rec{Prefix: "193.138.218.0/24", RegisteredCC: "GB", Descr: "HOSTING"})

	// FireHOL / malicious sample.
	add("firehol", Rec{Prefix: "45.155.205.0/24", Flags: []string{"malicious"}})
	add("ipinfo_lite", Rec{Prefix: "45.155.205.0/24", ASN: 211252, CC: "NL", ASType: "hosting", Org: "Delis LLC"})
	add("bgp", Rec{Prefix: "45.155.205.0/24", ASN: 211252, AnnouncedCC: "NL"})
	add("dbip_lite", Rec{Prefix: "45.155.205.0/24", CC: "NL"})
	add("peeringdb", Rec{Prefix: "45.155.205.0/24", ASN: 211252, ASType: "hosting"})

	// Geo disagreement sample (Vultr-like).
	add("ipinfo_lite", Rec{Prefix: "45.76.20.0/24", ASN: 20473, Org: "The Constant Company, LLC", CC: "US", City: "Los Angeles", ASType: "hosting"})
	add("dbip_lite", Rec{Prefix: "45.76.20.0/24", ASN: 20473, CC: "SG", City: "Singapore"})
	add("ip2location_lite", Rec{Prefix: "45.76.20.0/24", ASN: 20473, CC: "US"})
	add("cloud_ranges", Rec{Prefix: "45.76.20.0/24", ASN: 20473, Cloud: "vultr"})
	add("bgp", Rec{Prefix: "45.76.20.0/24", ASN: 20473, AnnouncedCC: "US", Org: "Choopa, LLC"})
	add("peeringdb", Rec{Prefix: "45.76.20.0/24", ASN: 20473, ASType: "hosting"})
	add("rir_delegated", Rec{Prefix: "45.76.20.0/24", RegisteredCC: "US", Descr: "HOSTING"})

	// AWS sample /24s used by the neighbour contamination test, plus a parent.
	for i := 0; i < 100; i++ {
		third := i
		cidr := prefix24(3, 1, third)
		add("cloud_ranges", Rec{Prefix: cidr, ASN: 16509, Org: "Amazon.com, Inc.", Cloud: "aws", CC: "US"})
		add("bgp", Rec{Prefix: cidr, ASN: 16509, AnnouncedCC: "US", Org: "Amazon.com, Inc.", UpstreamType: "hosting"})
		add("peeringdb", Rec{Prefix: cidr, ASN: 16509, ASType: "hosting", Org: "Amazon"})
		add("ipinfo_lite", Rec{Prefix: cidr, ASN: 16509, CC: "US", ASType: "hosting", Org: "Amazon.com, Inc."})
		add("rir_delegated", Rec{Prefix: cidr, RegisteredCC: "US", Descr: "AMAZON-HOSTING", NetName: "AMAZON"})
	}
	add("cloud_ranges", Rec{Prefix: "34.1.0.0/16", ASN: 15169, Cloud: "gcp", Org: "Google Cloud"})
	add("bgp", Rec{Prefix: "34.1.0.0/16", ASN: 15169, AnnouncedCC: "US"})
	add("ipinfo_lite", Rec{Prefix: "34.1.0.0/16", ASN: 15169, CC: "US", ASType: "hosting"})
	add("cloud_ranges", Rec{Prefix: "20.40.0.0/16", ASN: 8075, Cloud: "azure", Org: "Microsoft"})
	add("bgp", Rec{Prefix: "20.40.0.0/16", ASN: 8075, AnnouncedCC: "US"})
	add("ipinfo_lite", Rec{Prefix: "20.40.0.0/16", ASN: 8075, CC: "US", ASType: "hosting"})
	add("cloud_ranges", Rec{Prefix: "47.74.0.0/16", ASN: 45102, Cloud: "alibaba", Org: "Alibaba Cloud", CC: "SG"})
	add("bgp", Rec{Prefix: "47.74.0.0/16", ASN: 45102, AnnouncedCC: "SG", Org: "Alibaba"})
	add("ipinfo_lite", Rec{Prefix: "47.74.0.0/16", ASN: 45102, CC: "SG", ASType: "hosting", Org: "Alibaba Cloud"})
	add("dbip_lite", Rec{Prefix: "47.74.0.0/16", CC: "SG", ASN: 45102})
	add("peeringdb", Rec{Prefix: "47.74.0.0/16", ASN: 45102, ASType: "hosting"})

	// China Telecom home broadband, Shanghai.
	add("ip2region", Rec{Prefix: "114.80.0.0/16", CC: "CN", Region: "上海", City: "上海", Org: "电信", ASType: "isp"})
	add("ipinfo_lite", Rec{Prefix: "114.80.0.0/16", ASN: 4812, Org: "China Telecom (Group)", CC: "CN", ASType: "isp"})
	add("dbip_lite", Rec{Prefix: "114.80.0.0/16", ASN: 4812, CC: "CN", Region: "Shanghai", City: "Shanghai"})
	add("ip2location_lite", Rec{Prefix: "114.80.0.0/16", CC: "CN", Region: "Shanghai", City: "Shanghai", ASN: 4812})
	add("peeringdb", Rec{Prefix: "114.80.0.0/16", ASN: 4812, ASType: "isp", Org: "China Telecom"})
	add("rir_delegated", Rec{Prefix: "114.80.0.0/16", RegisteredCC: "CN", NetName: "CHINANET-SH", Descr: "DYNAMIC PPPOE BROADBAND", RDNS: "114-80-10-5.dyn.163data.com.cn"})
	add("bgp", Rec{Prefix: "114.80.0.0/16", ASN: 4812, Org: "China Telecom", AnnouncedCC: "CN", PrefixAgeDays: 3000})
	add("geofeed", Rec{Prefix: "114.80.0.0/16", GeofeedCC: "CN"})
	add("apnic_eyeball", Rec{Prefix: "114.80.0.0/16", ASN: 4812, Eyeball: 80000000})
	add("rtt_matrix", Rec{Prefix: "114.80.0.0/16", RTTRegion: "cn"})

	// China backbone prefixes used to label traceroute hops.
	backbones := []Rec{
		{Prefix: "59.43.0.0/16", ASN: 4809, Org: "China Telecom CN2", CC: "CN", AnnouncedCC: "CN", ASType: "nsp"},
		{Prefix: "202.97.0.0/16", ASN: 4134, Org: "China Telecom 163", CC: "CN", AnnouncedCC: "CN", ASType: "nsp"},
		{Prefix: "219.158.0.0/16", ASN: 4837, Org: "China Unicom 4837", CC: "CN", AnnouncedCC: "CN", ASType: "nsp"},
		{Prefix: "218.105.0.0/16", ASN: 9929, Org: "China Unicom 9929", CC: "CN", AnnouncedCC: "CN", ASType: "nsp"},
		{Prefix: "210.51.0.0/16", ASN: 10099, Org: "China Unicom 10099", CC: "CN", AnnouncedCC: "CN", ASType: "nsp"},
		{Prefix: "223.120.0.0/16", ASN: 58453, Org: "CMI", CC: "HK", AnnouncedCC: "HK", ASType: "nsp"},
		{Prefix: "223.118.0.0/16", ASN: 58807, Org: "CMIN2", CC: "HK", AnnouncedCC: "HK", ASType: "nsp"},
		{Prefix: "223.119.0.0/16", ASN: 58807, Org: "CMIN2", CC: "HK", AnnouncedCC: "HK", ASType: "nsp"},
		{Prefix: "221.176.0.0/16", ASN: 9808, Org: "China Mobile", CC: "CN", AnnouncedCC: "CN", ASType: "nsp"},
	}
	for _, b := range backbones {
		add("bgp", b)
		add("ipinfo_lite", Rec{Prefix: b.Prefix, ASN: b.ASN, Org: b.Org, CC: b.CC, ASType: "nsp"})
		add("rir_delegated", Rec{Prefix: b.Prefix, RegisteredCC: b.CC, NetName: b.Org})
		add("peeringdb", Rec{Prefix: b.Prefix, ASN: b.ASN, ASType: "nsp", Org: b.Org})
	}

	// IPv6 samples.
	add("ipinfo_lite", Rec{Prefix: "2606:4700:4700::/48", ASN: 13335, Org: "Cloudflare", CC: "US", ASType: "cdn"})
	add("cloud_ranges", Rec{Prefix: "2606:4700:4700::/48", ASN: 13335, Cloud: "cloudflare", Flags: []string{"anycast"}})
	add("bgp", Rec{Prefix: "2606:4700:4700::/48", ASN: 13335, AnnouncedCC: "US"})
	add("ipinfo_lite", Rec{Prefix: "2001:4860:4860::/48", ASN: 15169, Org: "Google", CC: "US"})
	add("bgp", Rec{Prefix: "2001:4860:4860::/48", ASN: 15169, AnnouncedCC: "US"})
	add("cloud_ranges", Rec{Prefix: "2001:4860::/32", ASN: 15169, Cloud: "gcp"})
	add("ipinfo_lite", Rec{Prefix: "240e::/20", ASN: 4134, Org: "China Telecom", CC: "CN"})
	add("bgp", Rec{Prefix: "240e::/20", ASN: 4134, AnnouncedCC: "CN"})

	return snapshot{Meta: meta, Rows: rows}
}

func prefix24(a, b, c int) string {
	return itoa(a) + "." + itoa(b) + "." + itoa(c) + ".0/24"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
