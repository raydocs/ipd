package app

import "ipd/internal/leak"

// CreateDNSSession issues a bounded bearer capability, not a browser test.
func (s *Service) CreateDNSSession() (Report, error) {
	if s.DNSSessions == nil {
		return Report{}, leak.ErrDisabled
	}
	session, err := s.DNSSessions.Issue()
	if err != nil {
		return Report{}, err
	}
	return Report{Verdict: "abstain", Summary: "DNS observation session issued; resolve the query names explicitly. No browser path has been tested.", Data: session, Sources: []Source{}, CachedAt: s.now()}, nil
}

// DNSSession reads only this session's authoritative observations. Absence is
// unknown, never safe; presence identifies a recursive source, not leak causality.
func (s *Service) DNSSession(token string) (Report, error) {
	if s.DNSSessions == nil {
		return Report{}, leak.ErrDisabled
	}
	result, err := s.DNSSessions.Result(token)
	if err != nil {
		return Report{}, err
	}
	summary := "No DNS observations; path unknown. This is not evidence of safety."
	if len(result.Observations) > 0 {
		summary = "Recursive DNS sources observed only; browser path and blocking/leak causality remain unknown."
	}
	return Report{Verdict: "abstain", Summary: summary, Data: result, Sources: []Source{}, CachedAt: s.now()}, nil
}
