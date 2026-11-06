package api

import (
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// Real curl fixtures exercise inherited-environment side effects.
func TestCCReadOnlyWithTLSKeyLogging(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); fmt.Fprintln(w, "192.0.2.42") }))
	defer ts.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "fixture-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	keylog := filepath.Join(dir, "must-not-exist.keys")
	out, code := runCC(t, strings.Replace(ccScript, "@ORIGIN@", ts.URL, 1), dir, []string{"PATH=/opt/homebrew/opt/curl/bin:" + os.Getenv("PATH"), "CURL_CA_BUNDLE=" + ca, "SSLKEYLOGFILE=" + keylog})
	b, err := os.ReadFile(keylog)
	t.Logf("exit=%d requests=%d keylog_exists=%t keylog_bytes=%d observed=%t", code, calls.Load(), err == nil, len(b), strings.Contains(out, "terminal_observed_ip=192.0.2.42"))
	if err == nil {
		t.Fatal("read-only contract violated: curl wrote TLS key material")
	}
	if code != 0 || calls.Load() != 1 {
		t.Fatal("TLS fixture did not complete")
	}
}

func TestCCUppercaseHTTPProxy(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); fmt.Fprintln(w, "192.0.2.43") }))
	defer ts.Close()
	out, code := runCC(t, strings.Replace(ccScript, "@ORIGIN@", ts.URL, 1), t.TempDir(), []string{"HTTP_PROXY=http://user:PRIVATE_SENTINEL@127.0.0.1:1", "NO_PROXY=", "no_proxy="})
	t.Logf("exit=%d direct_requests=%d proxy_presence=%t credentials_printed=%t", code, calls.Load(), strings.Contains(out, "proxy_environment_set=true"), strings.Contains(out, "PRIVATE_SENTINEL"))
	if code != 3 || calls.Load() != 0 || !strings.Contains(out, "terminal_observed_ip=unknown") || strings.Contains(out, "PRIVATE_SENTINEL") {
		t.Fatal("uppercase HTTP_PROXY was reported present but curl connected directly")
	}
}
