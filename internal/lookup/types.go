package lookup

import "time"

// SourceMeta is the public description of one dataset.
type SourceMeta struct {
	ID              string    `json:"id"`
	Kind            string    `json:"kind"` // local or online
	Version         string    `json:"version"`
	Rows            int       `json:"rows"`
	UpdatedAt       time.Time `json:"updated_at"`
	Frequency       string    `json:"frequency"`
	License         string    `json:"license"`
	Attribution     string    `json:"attribution"`
	URL             string    `json:"url,omitempty"`
	Redistributable bool      `json:"redistributable"`
	Enabled         bool      `json:"enabled"`
	Stale           bool      `json:"stale"`
}

// Rec is one prefix observation from a single source.
type Rec struct {
	Prefix         string
	ASN            int
	Org            string
	CC             string
	Region         string
	City           string
	Lat            float64
	Lon            float64
	ASType         string
	Flags          []string
	NetName        string
	Descr          string
	RegisteredCC   string
	GeofeedCC      string
	GeofeedChanged bool
	Eyeball        int
	UpstreamASN    int
	UpstreamType   string
	AnnouncedCC    string
	RDNS           string
	PrefixAgeDays  int
	RTTRegion      string
	ChangedAt      string
	Cloud          string
}

// Hit is a longest-prefix match from one source.
type Hit struct {
	Source string
	Rec    Rec
}

// Profile is the merged view of every source that matched an address.
type Profile struct {
	IP             string
	Hits           []Hit
	ASN            int
	Org            string
	CC             string
	Region         string
	City           string
	Lat            float64
	Lon            float64
	ASType         string
	Flags          []string
	NetName        string
	Descr          string
	RegisteredCC   string
	GeofeedCC      string
	GeofeedChanged bool
	Eyeball        int
	UpstreamASN    int
	UpstreamType   string
	AnnouncedCC    string
	AnnouncedBy    []int
	RDNS           string
	PrefixAgeDays  int
	RTTRegion      string
	ChangedAt      string
	Cloud          string
	Prefix         string
	Reserved       bool
	Disagreements  []Disagreement
	Conflicts      []Conflict
	Anycast        bool
}

// Disagreement records a field where sources do not agree.
type Disagreement struct {
	Field  string         `json:"field"`
	Values map[string]any `json:"values"`
}

// Vote is one source's weighted value inside a conflict.
type Vote struct {
	Source string  `json:"source"`
	Value  string  `json:"value"`
	Weight float64 `json:"weight"`
}

// Conflict is the explicit disagreement section. Anycast prefixes are included
// even when every geo source happens to agree, because agreement on a country
// is not evidence for an anycast address.
type Conflict struct {
	Field        string  `json:"field"`
	Chosen       string  `json:"chosen"`
	ChosenWeight float64 `json:"chosen_weight"`
	Anycast      bool    `json:"anycast,omitempty"`
	Note         string  `json:"note,omitempty"`
	Votes        []Vote  `json:"votes"`
}

// HasFlag reports whether the merged profile carries a flag.
func (p Profile) HasFlag(prefix string) bool {
	for _, f := range p.Flags {
		if f == prefix || (len(f) > len(prefix) && f[:len(prefix)] == prefix) {
			return true
		}
	}
	return false
}

// FlagValue returns the part after "key:" or "".
func (p Profile) FlagValue(key string) string {
	pfx := key + ":"
	for _, f := range p.Flags {
		if len(f) > len(pfx) && f[:len(pfx)] == pfx {
			return f[len(pfx):]
		}
	}
	return ""
}
