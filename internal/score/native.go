package score

import (
	"strings"

	"ipd/internal/lookup"
	"ipd/internal/version"
)

// Native is the native-vs-broadcast verdict.
type Native struct {
	Verdict           string   `json:"verdict"`
	RegisteredCC      string   `json:"registered_cc"`
	AnnouncedCC       string   `json:"announced_cc"`
	GeofeedCC         string   `json:"geofeed_cc"`
	RTTInferredRegion string   `json:"rtt_inferred_region"`
	ChangedAt         string   `json:"changed_at"`
	Evidence          []string `json:"evidence"`
	Confidence        float64  `json:"confidence"`
	ModelVersion      string   `json:"model_version"`
}

// ClassifyNative decides native, broadcast, or abstain.
func ClassifyNative(p lookup.Profile) Native {
	n := Native{
		RegisteredCC:      p.RegisteredCC,
		AnnouncedCC:       p.AnnouncedCC,
		GeofeedCC:         p.GeofeedCC,
		RTTInferredRegion: p.RTTRegion,
		ChangedAt:         p.ChangedAt,
		ModelVersion:      version.ModelNative,
	}
	if p.RegisteredCC == "" || p.CC == "" {
		n.Verdict = "abstain"
		n.Confidence = 0.3
		n.Evidence = []string{"missing registry or geo country; 无法判定"}
		return n
	}
	rttCC := rttCountry(p.RTTRegion)
	geo := p.CC
	aligned := p.RegisteredCC == geo && (p.AnnouncedCC == "" || p.AnnouncedCC == geo)
	geofeedOK := p.GeofeedCC == "" || p.GeofeedCC == geo
	rttOK := rttCC == "" || rttCC == geo || rttCC == "ANY"
	broadcast := p.RegisteredCC != geo ||
		p.GeofeedChanged ||
		(p.GeofeedCC != "" && p.GeofeedCC != geo) ||
		(p.AnnouncedCC != "" && p.AnnouncedCC != geo) ||
		(rttCC != "" && rttCC != "ANY" && rttCC != geo)
	if aligned && geofeedOK && !p.GeofeedChanged && rttOK && p.AnnouncedCC != "" {
		n.Verdict = "native"
		n.Confidence = 0.9
		n.Evidence = []string{
			"registered_cc=" + p.RegisteredCC,
			"geo_cc=" + geo,
			"announced_cc=" + p.AnnouncedCC,
			"geofeed consistent",
		}
		return n
	}
	if broadcast {
		n.Verdict = "broadcast"
		n.Confidence = 0.84
		n.Evidence = []string{}
		if p.RegisteredCC != geo {
			n.Evidence = append(n.Evidence, "registered_cc "+p.RegisteredCC+" != geo "+geo)
		}
		if p.GeofeedCC != "" && p.GeofeedCC != geo {
			n.Evidence = append(n.Evidence, "geofeed_cc "+p.GeofeedCC+" != geo "+geo)
		}
		if p.GeofeedChanged {
			n.Evidence = append(n.Evidence, "geofeed recently rewritten")
		}
		if p.AnnouncedCC != "" && p.AnnouncedCC != geo {
			n.Evidence = append(n.Evidence, "announcer country "+p.AnnouncedCC+" != geo "+geo)
		}
		if rttCC != "" && rttCC != geo {
			n.Evidence = append(n.Evidence, "rtt region "+p.RTTRegion+" implies "+rttCC+" != geo "+geo)
		}
		return n
	}
	n.Verdict = "abstain"
	n.Confidence = 0.4
	n.Evidence = []string{"not enough agreement to call native or broadcast; 无法判定"}
	return n
}

func rttCountry(region string) string {
	r := strings.ToLower(strings.TrimSpace(region))
	r = strings.TrimSuffix(r, "-colo")
	switch r {
	case "", "anycast":
		return ""
	case "lax", "sjc", "sea", "nyc", "buf", "us", "losangeles":
		return "US"
	case "hk", "hkg":
		return "HK"
	case "sg", "sin":
		return "SG"
	case "jp", "tyo", "nrt", "hnd":
		return "JP"
	case "cn", "shanghai", "beijing", "guangzhou":
		return "CN"
	case "eu", "fra", "ams", "lhr":
		return "EU"
	default:
		if len(r) == 2 {
			return strings.ToUpper(r)
		}
		return ""
	}
}
