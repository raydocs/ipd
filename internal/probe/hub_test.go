package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSignedTask(t *testing.T) {
	h := NewHub("tok")
	ts := httptest.NewServer(h)
	defer ts.Close()
	ws := "ws" + strings.TrimPrefix(ts.URL, "http") + "/agent"
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		_ = RunAgent(ctx, ws, "tok", "n1", func(p []byte) ([]byte, error) {
			return []byte(`{"echo":true}`), nil
		})
	}()
	deadline := time.Now().Add(3 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
		body, err := h.Dispatch(ctx, "n1", []byte(`{"ping":1}`))
		cancel()
		if err == nil && strings.Contains(string(body), "echo") {
			return
		}
		last = err
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatal(last)
}

func TestEnrollRejects(t *testing.T) {
	h := NewHub("secret")
	ts := httptest.NewServer(h)
	defer ts.Close()
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/agent/enroll", strings.NewReader(`{"token":"nope"}`))
	if err != nil {
		t.Fatal(err)
	}
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal(res.StatusCode)
	}
}
