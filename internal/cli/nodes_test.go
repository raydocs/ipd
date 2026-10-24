package cli

import (
	"context"
	"testing"

	"ipd/internal/app"
	"ipd/internal/config"
)

func TestNodesMeasureExplicitOffline(t *testing.T) {
	cfg := &config.Config{Offline: true}
	svc := &app.Service{Cfg: cfg}
	rep, err := dispatch(context.Background(), svc, cfg, globals{}, "nodes", []string{"--measure", "proxies: [{name: duplicate, type: http, server: 127.0.0.1, port: 1}]"})
	if err != nil {
		t.Fatalf("explicit local measurement flag must parse, even offline: %v", err)
	}
	d := rep.Data.(map[string]any)
	if rep.Verdict != "abstain" || d["measurement_reason"] != "offline" {
		t.Fatalf("unexpected offline report: %+v", rep)
	}
}

func TestNodesArgumentsAndDefaultAbstention(t *testing.T) {
	cfg := &config.Config{}
	svc := &app.Service{Cfg: cfg}
	source := "proxies: [{name: fixture-secret, type: ss, server: 192.0.2.1, port: 443, password: fixture-password}]"
	for _, args := range [][]string{{source}, {"--measure", source}, {source, "--measure"}} {
		rep, err := dispatch(context.Background(), svc, cfg, globals{}, "nodes", args)
		if err != nil || rep.Verdict != "abstain" {
			t.Fatalf("args=%v: %+v %v", args, rep, err)
		}
		d := rep.Data.(map[string]any)
		if len(args) == 1 && d["measurement_reason"] != "not_configured" {
			t.Fatal("default measurement was enabled")
		}
	}
	for _, args := range [][]string{nil, {"--measure"}, {"--measure", "--measure", source}, {"--measure", source, "extra"}, {"--endpoint", "https://127.0.0.1:1"}, {"--measure", "https://127.0.0.1:1"}} {
		if _, err := dispatch(context.Background(), svc, cfg, globals{}, "nodes", args); err == nil {
			t.Fatalf("accepted invalid args: %v", args)
		}
	}
	g, rest := parseGlobals([]string{"nodes", "--measure", "--offline", "--json", source})
	if !g.offline || g.format != "json" || len(rest) != 3 || rest[1] != "--measure" {
		t.Fatalf("globals consumed measurement option: %+v %v", g, rest)
	}
}
