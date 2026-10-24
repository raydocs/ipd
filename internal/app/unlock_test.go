package app

import (
	"context"
	"errors"
	"testing"

	"ipd/internal/unlock"
)

type unlockGetter func(string) unlock.Response

func (f unlockGetter) Get(_ context.Context, u string, _ map[string]string) unlock.Response {
	return f(u)
}

func TestUnlockAggregationPreservesUnknown(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ids    []string
		body   string
		status int
		err    error
		want   string
	}{
		{"all_fail", []string{"chatgpt", "claude"}, "", 0, errors.New("fixture timeout"), "abstain"},
		{"unknown", []string{"grok"}, "new page", 200, nil, "abstain"},
		{"mixed", []string{"meta_ai", "grok"}, "KadabraRootContainer", 200, nil, "abstain"},
		{"denied_and_unknown", []string{"grok", "apple"}, "not available in your region", 403, nil, "abstain"},
		{"denied", []string{"grok"}, "not available in your region", 403, nil, "blocked"},
		{"positive", []string{"meta_ai"}, "KadabraRootContainer", 200, nil, "ok"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSvc(t)
			s.Checks = &unlock.Engine{Get: unlockGetter(func(u string) unlock.Response {
				body := tc.body
				if tc.name == "denied_and_unknown" && u == "https://gspe1-ssl.ls.apple.com/pep/gcc" {
					body = "redesigned endpoint"
				}
				return unlock.Response{Status: tc.status, Body: body, FinalURL: u, Err: tc.err}
			})}
			rep := s.Unlock(context.Background(), tc.ids)
			if rep.Verdict != tc.want {
				t.Fatalf("want %s, got %+v", tc.want, rep)
			}
		})
	}
}

func TestGoogleRegionUnknownIsNotFalse(t *testing.T) {
	for _, mode := range []string{"missing", "failed", "empty", "partial"} {
		t.Run(mode, func(t *testing.T) {
			s := newSvc(t)
			s.Checks = nil
			if mode != "missing" {
				s.Checks = &unlock.Engine{Get: unlockGetter(func(u string) unlock.Response {
					r := unlock.Response{Status: 200, FinalURL: u}
					if mode == "failed" || mode == "partial" {
						r.Err = errors.New("fixture timeout")
					}
					if mode == "partial" && u == "https://www.google.com/" {
						r.Err = nil
						r.Body = `<form action="/search"><input name="q"></form>`
					}
					return r
				})}
			}
			rep := s.GoogleRegion(context.Background())
			data := rep.Data.(map[string]any)
			if rep.Verdict != "abstain" || data["sent_to_china"] != nil || data["google_tld"] != "" {
				t.Fatalf("unknown became definitive: %+v", rep)
			}
		})
	}
}

func TestGoogleRegionRecognizedPublicOutput(t *testing.T) {
	for _, tc := range []struct {
		name, googleURL, want string
		sent                  bool
	}{
		{"positive", "https://www.google.com/", "ok", false},
		{"china_redirect", "https://www.google.com.hk/", "risky", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSvc(t)
			s.Checks = &unlock.Engine{Get: unlockGetter(func(u string) unlock.Response {
				body := `<form action="/search"><input name="q"></form>`
				final := u
				switch u {
				case "https://www.google.com/":
					final = tc.googleURL
				case "https://www.youtube.com/premium":
					body = `"INNERTUBE_CONTEXT_GL":"US"`
				case "https://play.google.com/store":
					body = `{"country":"US"}`
				}
				return unlock.Response{Status: 200, Body: body, FinalURL: final}
			})}
			rep := s.GoogleRegion(context.Background())
			data := rep.Data.(map[string]any)
			if rep.Verdict != tc.want || data["sent_to_china"] != tc.sent || data["youtube_gl"] != "US" || data["play_region"] != "US" {
				t.Fatalf("%+v", rep)
			}
		})
	}
}
