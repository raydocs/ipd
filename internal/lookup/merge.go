package lookup

import (
	"net/netip"
	"sort"
	"strconv"
)

func merge(ip string, hits []Hit) Profile {
	sort.Slice(hits, func(i, j int) bool { return hits[i].Source < hits[j].Source })
	p := Profile{IP: ip, Hits: hits, Flags: []string{}, AnnouncedBy: []int{}}
	if len(hits) == 0 {
		p.ASType = "unknown"
		p.Conflicts = []Conflict{}
		annotateAnycast(ip, &p)
		return p
	}
	for _, h := range hits {
		r := h.Rec
		p.Flags = union(p.Flags, r.Flags)
		if r.Cloud != "" && p.Cloud == "" {
			p.Cloud = r.Cloud
			p.Flags = union(p.Flags, []string{"cloud:" + r.Cloud})
		}
		// Field precedence: bgp for ASN, peeringdb for type, ip2region for CN city,
		// ipinfo/dbip/ip2location for geo. First non-empty wins after priority pick.
	}
	asnText, _ := weightedValue(hits, "asn", func(r Rec) string {
		if r.ASN == 0 {
			return ""
		}
		return strconv.Itoa(r.ASN)
	})
	p.ASN, _ = strconv.Atoi(asnText)
	p.Org = pickStr(hits, func(r Rec) string { return r.Org }, "bgp", "ipinfo_lite", "rir_delegated", "dbip_lite")
	p.CC, _ = weightedValue(hits, "cc", func(r Rec) string { return r.CC })
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
	p.Conflicts = collectConflicts(hits, p)
	p.Disagreements = disagreementsFrom(p.Conflicts)
	annotateAnycast(ip, &p)
	if p.ASType == "" {
		p.ASType = "unknown"
	}
	return p
}

// Weights prefer a measurement source over a registry hint. Equal weights
// break toward the earlier name in the preference list for that field.
func fieldWeight(field, source string) float64 {
	table := map[string]map[string]float64{
		"asn": {
			"bgp": 8, "ipinfo_lite": 5, "dbip_lite": 4, "ip2location_lite": 3,
			"cloud_ranges": 3, "rir_delegated": 2,
		},
		"cc": {
			"ipinfo_lite": 5, "dbip_lite": 5, "ip2location_lite": 4, "ip2region": 4,
			"geofeed": 3, "cloud_ranges": 2, "bgp": 2, "rir_delegated": 1,
		},
		"as_type": {"peeringdb": 6, "cloud_ranges": 5, "ipinfo_lite": 4, "bgp": 2},
		"city":    {"ip2region": 5, "dbip_lite": 4, "ip2location_lite": 4, "ipinfo_lite": 3},
	}
	if w, ok := table[field][source]; ok && w > 0 {
		return w
	}
	return 1
}

func preferOrder(field string) []string {
	switch field {
	case "asn":
		return []string{"bgp", "ipinfo_lite", "dbip_lite", "ip2location_lite", "cloud_ranges", "rir_delegated"}
	case "cc":
		return []string{"ipinfo_lite", "dbip_lite", "ip2location_lite", "ip2region", "geofeed", "bgp", "rir_delegated"}
	case "as_type":
		return []string{"peeringdb", "cloud_ranges", "ipinfo_lite", "bgp"}
	case "city":
		return []string{"ip2region", "dbip_lite", "ip2location_lite", "ipinfo_lite"}
	default:
		return nil
	}
}

func weightedValue(hits []Hit, field string, get func(Rec) string) (string, float64) {
	best, bestW := "", -1.0
	bestPref := 1 << 20
	pref := map[string]int{}
	for i, s := range preferOrder(field) {
		pref[s] = i
	}
	for _, h := range hits {
		v := get(h.Rec)
		if v == "" {
			continue
		}
		w := fieldWeight(field, h.Source)
		pi, ok := pref[h.Source]
		if !ok {
			pi = 1 << 20
		}
		if w > bestW || (w == bestW && pi < bestPref) {
			best, bestW, bestPref = v, w, pi
		}
	}
	if bestW < 0 {
		return "", 0
	}
	return best, bestW
}

func collectConflicts(hits []Hit, p Profile) []Conflict {
	var out []Conflict
	add := func(field, chosen string, chosenW float64, votes []Vote, note string) {
		if len(votes) == 0 {
			return
		}
		out = append(out, Conflict{Field: field, Chosen: chosen, ChosenWeight: chosenW, Note: note, Votes: votes})
	}
	if votes := votesFor(hits, "cc", func(r Rec) string { return r.CC }); conflicting(votes) {
		chosen, w := weightedValue(hits, "cc", func(r Rec) string { return r.CC })
		add("cc", chosen, w, votes, "country sources disagree")
	} else if reg := registryCountry(hits); reg != "" && reg != p.CC && p.CC != "" {
		votes = append(votes, Vote{Source: "rir_delegated#registered", Value: reg, Weight: fieldWeight("cc", "rir_delegated")})
		chosen, w := weightedValue(hits, "cc", func(r Rec) string { return r.CC })
		add("cc", chosen, w, votes, "registry country differs from geolocation")
	}
	if votes := votesFor(hits, "asn", func(r Rec) string {
		if r.ASN == 0 {
			return ""
		}
		return strconv.Itoa(r.ASN)
	}); conflicting(votes) {
		chosen, w := weightedValue(hits, "asn", func(r Rec) string {
			if r.ASN == 0 {
				return ""
			}
			return strconv.Itoa(r.ASN)
		})
		add("asn", chosen, w, votes, "ASN sources disagree")
	}
	if votes := votesFor(hits, "as_type", func(r Rec) string { return r.ASType }); conflicting(votes) {
		chosen, w := weightedValue(hits, "as_type", func(r Rec) string { return r.ASType })
		if p.ASType != "" {
			chosen = p.ASType
		}
		add("as_type", chosen, w, votes, "network type sources disagree")
	}
	if votes := votesFor(hits, "city", func(r Rec) string { return r.City }); conflicting(votes) {
		chosen, w := weightedValue(hits, "city", func(r Rec) string { return r.City })
		add("city", chosen, w, votes, "city sources disagree")
	}
	return out
}

func votesFor(hits []Hit, field string, get func(Rec) string) []Vote {
	var votes []Vote
	for _, h := range hits {
		v := get(h.Rec)
		if v == "" {
			continue
		}
		votes = append(votes, Vote{Source: h.Source, Value: v, Weight: fieldWeight(field, h.Source)})
	}
	sort.Slice(votes, func(i, j int) bool {
		if votes[i].Source == votes[j].Source {
			return votes[i].Value < votes[j].Value
		}
		return votes[i].Source < votes[j].Source
	})
	return votes
}

func conflicting(votes []Vote) bool {
	if len(votes) < 2 {
		return false
	}
	first := votes[0].Value
	for _, v := range votes[1:] {
		if v.Value != first {
			return true
		}
	}
	return false
}

func registryCountry(hits []Hit) string {
	for _, h := range hits {
		if h.Source == "rir_delegated" && h.Rec.RegisteredCC != "" {
			return h.Rec.RegisteredCC
		}
	}
	return ""
}

func disagreementsFrom(conflicts []Conflict) []Disagreement {
	var out []Disagreement
	for _, c := range conflicts {
		if c.Field != "cc" && c.Field != "as_type" && c.Field != "asn" {
			continue
		}
		vals := map[string]any{}
		for _, v := range c.Votes {
			vals[v.Source] = v.Value
		}
		if len(vals) > 1 {
			out = append(out, Disagreement{Field: c.Field, Values: vals})
		}
	}
	return out
}

// cloudflareDNS is announced by AS13335 and omitted from the published proxy
// list at https://www.cloudflare.com/ips-v4.
var cloudflareDNS = []netip.Prefix{
	netip.MustParsePrefix("1.1.1.0/24"),
	netip.MustParsePrefix("1.0.0.0/24"),
}

// knownAnycast is public DNS anycast that should not be scored as a single site.
var knownAnycast = append(append([]netip.Prefix{}, cloudflareDNS...),
	netip.MustParsePrefix("8.8.8.0/24"),
	netip.MustParsePrefix("8.8.4.0/24"),
	netip.MustParsePrefix("9.9.9.0/24"),
	netip.MustParsePrefix("149.112.112.0/24"),
	netip.MustParsePrefix("208.67.222.0/24"),
	netip.MustParsePrefix("208.67.220.0/24"),
)

func annotateAnycast(ip string, p *Profile) {
	addr, err := netip.ParseAddr(ip)
	omitted := false
	known := false
	if err == nil {
		for _, pfx := range cloudflareDNS {
			if pfx.Contains(addr) {
				omitted = true
				known = true
				break
			}
		}
		if !known {
			for _, pfx := range knownAnycast {
				if pfx.Contains(addr) {
					known = true
					break
				}
			}
		}
	}
	flagged := false
	for _, h := range p.Hits {
		if has(h.Rec.Flags, "anycast") {
			flagged = true
			break
		}
	}
	if !known && !flagged {
		if p.Conflicts == nil {
			p.Conflicts = []Conflict{}
		}
		return
	}
	p.Anycast = true
	p.Flags = union(p.Flags, []string{"anycast"})
	note := "known anycast"
	if omitted && !flagged {
		note = "known anycast prefix omitted from Cloudflare's published ranges"
	} else if omitted {
		note = "anycast; Cloudflare's published proxy ranges omit this prefix"
	}
	p.Conflicts = append(p.Conflicts, Conflict{
		Field: "anycast", Chosen: "anycast", ChosenWeight: 5, Anycast: true, Note: note,
		Votes: []Vote{{Source: "known_anycast", Value: "anycast", Weight: 5}},
	})
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
