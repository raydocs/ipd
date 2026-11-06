package nodes

// Only the node list and an explicitly runner-owned presentation object may
// occur at the top level. Every other global (even empty/default-looking ones)
// is unsupported. In particular do not silently reset trust, DNS/hosts, dialer
// interface/marks, or path-dependent policy to a different core/system default.
func runnerGlobals(doc map[string]any, nodes string) error {
	for key, value := range doc {
		switch key {
		case nodes:
		case "metadata":
			if !runnerObject(runnerFields{"name": runnerString, "description": runnerString})(value) {
				return ErrRunnerUnsupported
			}
		default:
			return ErrRunnerUnsupported
		}
	}
	return nil
}
