package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRipeAtlasMeasure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/measurements/":
			if r.URL.Query().Get("key") != "k" {
				t.Fatalf("key %s", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"measurements":[42]}`))
		case r.URL.Path == "/measurements/42/results/":
			_, _ = w.Write([]byte(`[{"prb_id":7,"sent":3,"rcvd":3,"avg":8.5}]`))
		case r.URL.Path == "/probes/7/":
			_, _ = w.Write([]byte(`{"asn_v4":4134,"country_code":"CN"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	r := RipeAtlas{Key: "k", BaseURL: srv.URL, Client: srv.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := r.Measure(ctx, Query{Kind: KindPing, Carriers: []string{"ct"}, Target: "1.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Network != "ct" || got[0].ASN != 4134 || got[0].ICMP != "ok" {
		t.Fatalf("%+v", got)
	}
	if _, err := (RipeAtlas{}).Measure(ctx, Query{Target: "1.1.1.1"}); err == nil {
		t.Fatal("expected disabled")
	}
}

func TestBOCEMeasure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/node/list":
			_, _ = w.Write([]byte(`{"data":{"list":[{"id":11,"node_name":"上海电信","isp_name":"电信"},{"id":12,"node_name":"广州联通","isp_name":"联通"}]}}`))
		case r.URL.Path == "/task/create/ping":
			if r.URL.Query().Get("key") != "k" || r.URL.Query().Get("host") != "1.1.1.1" {
				t.Fatalf("%s", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"error_code":0,"data":{"id":"task1"}}`))
		case r.URL.Path == "/task/ping/task1":
			_, _ = w.Write([]byte(`{"data":[{"node_id":"11","avg":20,"loss":0},{"node_id":"12","avg":30,"loss":0}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	b := BOCE{Key: "k", BaseURL: srv.URL, Client: srv.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := b.Measure(ctx, Query{Kind: KindPing, Carriers: []string{"ct", "cu"}, Target: "1.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("%+v", got)
	}
	if _, err := (BOCE{}).Measure(ctx, Query{}); err == nil {
		t.Fatal("expected disabled")
	}
}
