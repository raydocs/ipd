package lookup

import "sort"

func merge(ip string, hits []Hit) Profile {
	sort.Slice(hits, func(i, j int) bool { return hits[i].Source < hits[j].Source })
	p := Profile{IP: ip, Hits: hits, Flags: []string{}, AnnouncedBy: []int{}}
	if len(hits) == 0 {
		p.ASType = "unknown"
		return p
	}
	ccs := map[string]string{}
	types := map[string]string{}
	for _, h := range hits {
		r := h.Rec
		ccs[h.Source] = r.CC
		if r.ASType != "" {
			types[h.Source] = r.ASType
		}
		p.Flags = union(p.Flags, r.Flags)
		if r.Cloud != "" && p.Cloud == "" {
			p.Cloud = r.Cloud
			p.Flags = union(p.Flags, []string{"cloud:" + r.Cloud})
		}
		// Field precedence: bgp for ASN, peeringdb for type, ip2region for CN city,
		// ipinfo/dbip/ip2location for geo. First non-empty wins after priority pick.
	}
	p.ASN = pickASN(hits)
	p.Org = pickStr(hits, func(r Rec) string { return r.Org }, "bgp", "ipinfo_lite", "rir_delegated", "dbip_lite")
	p.CC = majorityCC(hits)
	p.Region = pickStr(hits, func(r Rec) string { return r.Region }, "ip2region", "dbip_lite", "ip2location_lite", "ipinfo_lite")
	p.City = pickStr(hits, func(r Rec) string { return r.City }, "ip2region", "dbip_lite", "ip2location_lite", "ipinfo_lite")
	p.Lat, p.Lon = pickGeo(hits)
	p.ASType = pickStr(hits, func(r Rec) string { return r.ASType }, "peeringdb", "ipinfo_lite", "bgp", "cloud_ranges")
	switch p.Cloud {
	case "":
	case "cloudflare":
		p.ASType = "cdn"
	default:
		p.ASType = "hosting"
	}
	p.NetName = pickStr(hits, func(r Rec) string { return r.NetName }, "rir_delegated", "ip2location_lite")
	p.Descr = pickStr(hits, func(r Rec) string { return r.Descr }, "rir_delegated", "ip2location_lite")
	p.RegisteredCC = pickStr(hits, func(r Rec) string { return r.RegisteredCC }, "rir_delegated", "geofeed")
	p.GeofeedCC = pickStr(hits, func(r Rec) string { return r.GeofeedCC }, "geofeed")
	p.GeofeedChanged = anyBool(hits, func(r Rec) bool { return r.GeofeedChanged })
	p.Eyeball = pickInt(hits, func(r Rec) int { return r.Eyeball }, "apnic_eyeball")
	p.UpstreamASN = pickInt(hits, func(r Rec) int { return r.UpstreamASN }, "bgp")
	p.UpstreamType = pickStr(hits, func(r Rec) string { return r.UpstreamType }, "bgp")
	p.AnnouncedCC = pickStr(hits, func(r Rec) string { return r.AnnouncedCC }, "bgp", "peeringdb")
	p.RDNS = pickStr(hits, func(r Rec) string { return r.RDNS }, "rir_delegated", "ipinfo_lite")
	p.PrefixAgeDays = pickInt(hits, func(r Rec) int { return r.PrefixAgeDays }, "bgp", "rir_delegated")
	p.RTTRegion = pickStr(hits, func(r Rec) string { return r.RTTRegion }, "rtt_matrix")
	p.ChangedAt = pickStr(hits, func(r Rec) string { return r.ChangedAt }, "bgp", "geofeed")
	p.Prefix = pickStr(hits, func(r Rec) string { return r.Prefix }, "bgp", "cloud_ranges", "ipinfo_lite")
	seenASN := map[int]struct{}{}
	for _, h := range hits {
		if h.Rec.ASN == 0 {
			continue
		}
		if _, ok := seenASN[h.Rec.ASN]; ok {
			continue
		}
		seenASN[h.Rec.ASN] = struct{}{}
		p.AnnouncedBy = append(p.AnnouncedBy, h.Rec.ASN)
	}
	p.Disagreements = disagreements(hits)
	if p.ASType == "" {
		p.ASType = "unknown"
	}
	return p
}

func disagreements(hits []Hit) []Disagreement {
	var out []Disagreement
	cc := map[string]any{}
	for _, h := range hits {
		if h.Rec.CC == "" {
			continue
		}
		cc[h.Source] = h.Rec.CC
	}
	if distinct(cc) > 1 {
		out = append(out, Disagreement{Field: "cc", Values: cc})
	}
	at := map[string]any{}
	for _, h := range hits {
		if h.Rec.ASType == "" {
			continue
		}
		at[h.Source] = h.Rec.ASType
	}
	if distinct(at) > 1 {
		out = append(out, Disagreement{Field: "as_type", Values: at})
	}
	return out
}

func distinct(m map[string]any) int {
	s := map[string]struct{}{}
	for _, v := range m {
		s[toString(v)] = struct{}{}
	}
	return len(s)
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func majorityCC(hits []Hit) string {
	counts := map[string]int{}
	var order []string
	for _, h := range hits {
		if h.Rec.CC == "" {
			continue
		}
		if counts[h.Rec.CC] == 0 {
			order = append(order, h.Rec.CC)
		}
		counts[h.Rec.CC]++
	}
	best, n := "", 0
	for _, cc := range order {
		if counts[cc] > n {
			best, n = cc, counts[cc]
		}
	}
	return best
}

func pickASN(hits []Hit) int {
	for _, src := range []string{"bgp", "ipinfo_lite", "dbip_lite", "ip2location_lite", "rir_delegated", "cloud_ranges"} {
		for _, h := range hits {
			if h.Source == src && h.Rec.ASN != 0 {
				return h.Rec.ASN
			}
		}
	}
	for _, h := range hits {
		if h.Rec.ASN != 0 {
			return h.Rec.ASN
		}
	}
	return 0
}

func pickStr(hits []Hit, get func(Rec) string, prefer ...string) string {
	for _, src := range prefer {
		for _, h := range hits {
			if h.Source == src {
				if v := get(h.Rec); v != "" {
					return v
				}
			}
		}
	}
	for _, h := range hits {
		if v := get(h.Rec); v != "" {
			return v
		}
	}
	return ""
}

func pickInt(hits []Hit, get func(Rec) int, prefer ...string) int {
	for _, src := range prefer {
		for _, h := range hits {
			if h.Source == src {
				if v := get(h.Rec); v != 0 {
					return v
				}
			}
		}
	}
	for _, h := range hits {
		if v := get(h.Rec); v != 0 {
			return v
		}
	}
	return 0
}

func pickGeo(hits []Hit) (float64, float64) {
	for _, src := range []string{"dbip_lite", "ip2location_lite", "ipinfo_lite", "ip2region"} {
		for _, h := range hits {
			if h.Source == src && (h.Rec.Lat != 0 || h.Rec.Lon != 0) {
				return h.Rec.Lat, h.Rec.Lon
			}
		}
	}
	return 0, 0
}

func anyBool(hits []Hit, get func(Rec) bool) bool {
	for _, h := range hits {
		if get(h.Rec) {
			return true
		}
	}
	return false
}

func union(a, b []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
