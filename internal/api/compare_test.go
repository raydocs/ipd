package api

import (
	"testing"
)

func TestComparisonHTTPContract(t *testing.T) {
	doc := contractDoc(t)
	svc, h := contractHandler(t, false)
	// Online process but no keys: exact opt-in still must not invoke a service.
	svc.Cfg.Offline = false
	svc.Cfg.ProviderKeys = nil
	for _, suffix := range []string{"", "?live=0", "?live=1", "?live=true"} {
		w := contractRequest(h, "GET", "/v1/ip/1.1.1.1/compare"+suffix, "", "application/json")
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		validateContractResponse(t, doc, "/v1/ip/{ip}/compare", "get", w)
		rep := decodeContractJSON(t, w)
		rows := object(t, rep["data"])["rows"].([]any)
		if len(rows) != 7 {
			t.Fatal(rows)
		}
		for _, r := range rows[:5] {
			reason := "live_opt_in_required"
			if suffix == "?live=1" {
				reason = "missing_key"
			}
			if object(t, r)["skipped"] != reason {
				t.Fatal(r)
			}
		}
	}
	for _, ip := range []string{"bad", "127.0.0.1", "192.0.2.1"} {
		w := contractRequest(h, "GET", "/v1/ip/"+ip+"/compare?live=1", "", "application/json")
		if w.Code != 400 {
			t.Fatal(w.Code)
		}
		validateContractResponse(t, doc, "/v1/ip/{ip}/compare", "get", w)
	}
}
