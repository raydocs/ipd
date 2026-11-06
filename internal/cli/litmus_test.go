package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLitmusOfflineContract(t *testing.T) {
	cliEnv(t)
	for _, lang := range []string{"zh", "en"} {
		code, out, errOut := invokeCLI(t, "", "litmus", "google_search", "--offline", "--json", "--lang", lang)
		if code != 10 || errOut != "" {
			t.Fatalf("code=%d stdout=%s stderr=%s", code, out, errOut)
		}
		var r map[string]any
		if json.Unmarshal([]byte(out), &r) != nil || r["reason"] != "offline" || r["challenge_observed"] != "abstain" || r["cf_bot_score"] != nil {
			t.Fatal(out)
		}
	}
}
func TestLitmusRejectsTargets(t *testing.T) {
	cliEnv(t)
	for _, id := range []string{"https://localhost/", "127.0.0.1", "google_search extra", "--url=secret"} {
		code, out, errOut := invokeCLI(t, "", "litmus", id, "--offline", "--json")
		if code != 2 || out != "" || strings.Contains(errOut, id) {
			t.Fatalf("code=%d out=%s err=%s", code, out, errOut)
		}
	}
}

func TestLitmusSchemaAndLanguage(t *testing.T) {
	cliEnv(t)
	var previous string
	for _, lang := range []string{"zh", "en"} {
		code, out, errOut := invokeCLI(t, "", "--json", "--lang="+lang, "litmus", "google_search", "--offline")
		if code != 10 || errOut != "" {
			t.Fatal(code, errOut)
		}
		var r map[string]any
		if err := json.Unmarshal([]byte(out), &r); err != nil {
			t.Fatal(err)
		}
		keys := []string{"source", "target", "url", "observed_at", "http_status", "scope", "provider_presence", "challenge_observed", "captcha_observed", "reason", "matched_markers", "cf_bot_score", "cf_bot_score_reason"}
		if len(r) != len(keys) {
			t.Fatal(r)
		}
		for _, key := range keys {
			if _, ok := r[key]; !ok {
				t.Fatal(key)
			}
		}
		if r["source"] != "public_http" || r["url"] != "https://www.google.com/search?q=ipd" || r["http_status"] != nil || r["scope"] != "single_response_known_markers_only" {
			t.Fatal(r)
		}
		delete(r, "observed_at")
		b, _ := json.Marshal(r)
		if previous != "" && string(b) != previous {
			t.Fatal("locale changed machine contract")
		}
		previous = string(b)
		code, out, errOut = invokeCLI(t, "", "litmus", "--help", "--lang", lang)
		if code != 0 || errOut != "" {
			t.Fatal(code, errOut)
		}
		if lang == "en" && !strings.Contains(out, "Usage:") || lang == "zh" && !strings.Contains(out, "用法") {
			t.Fatal(out)
		}
	}
}
