package route

import "gopkg.in/yaml.v3"
import "ipd/data"

// Target is one China traceroute destination.
type Target struct {
	Province string `yaml:"province" json:"province"`
	Carrier  string `yaml:"carrier" json:"carrier"`
	IP       string `yaml:"ip" json:"ip"`
	Name     string `yaml:"name" json:"name"`
	Core     bool   `yaml:"core" json:"core"`
}

// Targets returns core (Beijing/Shanghai/Guangzhou × three carriers) or the full list.
func Targets(scope string) []Target {
	var doc struct {
		Targets []Target `yaml:"targets"`
	}
	if err := yaml.Unmarshal(data.CNTargets, &doc); err != nil {
		return nil
	}
	if scope == "full" {
		return doc.Targets
	}
	var core []Target
	for _, t := range doc.Targets {
		if t.Core {
			core = append(core, t)
		}
	}
	return core
}
