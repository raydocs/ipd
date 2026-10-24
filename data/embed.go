// Package data holds the published target lists and blocklist zones.
package data

import _ "embed"

//go:embed dnsbl.yaml
var DNSBL []byte

//go:embed poison.yaml
var Poison []byte

//go:embed cn_targets.yaml
var CNTargets []byte

//go:embed canary.yaml
var Canary []byte
