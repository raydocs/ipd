// Package models publishes the scoring weights. The YAML and JSON are the
// contract: the running service loads these bytes, and the files are the
// source users can audit.
package models

import _ "embed"

//go:embed purity.yaml
var PurityYAML []byte

//go:embed residential.json
var ResidentialJSON []byte
