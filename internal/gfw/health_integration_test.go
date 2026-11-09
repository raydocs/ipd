package gfw_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"ipd/internal/app"
	"ipd/internal/config"
	"ipd/internal/gfw"
	"ipd/internal/lookup"
	"ipd/internal/probe"
)

func TestServiceAnchorPriorityWiring(t *testing.T) {
	var low, high probe.Health
	for i := 0; i < 3; i++ {
		low.Observe("p", i != 0)
		high.Observe("p", true)
	}
	samples := []probe.Sample{
		{Network: "ct", ASN: 4134, City: "low", Healthy: true, ICMP: "ok", AnchorHealth: low.Snapshot("p")},
		{Network: "ct", ASN: 4134, City: "unknown", Healthy: true, ICMP: "ok"},
		{Network: "ct", ASN: 4134, City: "high", Healthy: true, ICMP: "ok", AnchorHealth: high.Snapshot("p")},
		{Network: "cu", ASN: 4837, City: "one", Healthy: true, ICMP: "ok"},
		{Network: "cu", ASN: 4837, City: "two", Healthy: true, ICMP: "ok"},
	}
	// Synthetic provider transport: exercise decode -> Sample -> service mapping
	// -> aggregation, with no external HTTP or measurements.
	var results []any
	for _, sm := range samples {
		id := fmt.Sprintf("%d/%s", sm.ASN, sm.City)
		if sm.AnchorHealth.Known {
			for i := 0; i < 3; i++ {
				probe.DefaultHealth.ObserveAnchor(id, fmt.Sprint(i), sm.City == "high" || i != 0)
			}
		}
		results = append(results, map[string]any{"probe": map[string]any{"asn": sm.ASN, "city": sm.City, "country": "CN"}, "result": map[string]any{"status": "finished", "stats": map[string]any{"avg": 1}}})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			fmt.Fprint(w, `{"id":"synthetic"}`)
			return
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"status": "finished", "results": results}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	service := &app.Service{Cfg: &config.Config{}, Look: lookup.New(), Vantage: probe.Globalping{BaseURL: server.URL, Client: server.Client(), MinInterval: -1}}
	report, err := service.GFW(context.Background(), "fixture.example.invalid", []int{80})
	if err != nil {
		t.Fatal(err)
	}
	r := report.Data.(gfw.Result)
	if r.Verdict != gfw.VerdictOK || len(r.Probes) != 5 || r.Probes[0].City != "high" || r.Probes[1].City != "low" || r.Probes[2].City != "unknown" || r.Probes[2].AnchorHealth.Known || r.Probes[2].AnchorHealth.Weight != nil {
		t.Fatalf("mapping/priority lost: %+v", r)
	}
	if !r.Probes[0].AnchorHealth.Known || *r.Probes[0].AnchorHealth.Weight != 1 {
		t.Fatal(r.Probes[0])
	}
}

func TestHistoryCannotManufactureVerdicts(t *testing.T) {
	one := 1.0
	h := probe.AnchorHistory{Known: true, Samples: 32, Weight: &one}
	fixtures := [][]gfw.Obs{
		nil,
		{{Network: "ct", Healthy: true, ICMP: "ok"}},
		{{Network: "ct", Healthy: true, ICMP: "ok"}, {Network: "cu", Healthy: true, ICMP: "ok"}},
		{{Network: "ct", Healthy: false, ICMP: "timeout"}, {Network: "cu", Healthy: false, ICMP: "timeout"}},
		{{Network: "ct", Healthy: true, ICMP: "timeout"}, {Network: "ct", Healthy: true, ICMP: "timeout"}},
	}
	for _, rows := range fixtures {
		baseline := gfw.Judge(rows, []int{80}, nil)
		weighted := append([]gfw.Obs(nil), rows...)
		for i := range weighted {
			weighted[i].AnchorHealth = h
		}
		got := gfw.Judge(weighted, []int{80}, nil)
		if got.Verdict != gfw.VerdictInsufficient || got.Verdict != baseline.Verdict || got.Confidence != baseline.Confidence || !reflect.DeepEqual(got.PerCarrier, baseline.PerCarrier) || len(got.Probes) != len(baseline.Probes) {
			t.Fatalf("weights changed gates: %+v => %+v", baseline, got)
		}
	}
}
