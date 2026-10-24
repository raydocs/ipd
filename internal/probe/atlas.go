package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// RipeAtlas runs one-off measurements when IPD_RIPE_KEY is set.
type RipeAtlas struct {
	Key     string
	BaseURL string
	Client  *http.Client
}

func (r RipeAtlas) Name() string  { return "ripeatlas" }
func (r RipeAtlas) Enabled() bool { return r.Key != "" }

func (r RipeAtlas) Measure(ctx context.Context, q Query) ([]Sample, error) {
	if r.Key == "" {
		return nil, errDisabled("ripeatlas", "IPD_RIPE_KEY is not set")
	}
	base := strings.TrimRight(r.BaseURL, "/")
	if base == "" {
		base = "https://atlas.ripe.net/api/v2"
	}
	client := r.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	def := map[string]any{
		"target":      q.Target,
		"description": "ipd",
		"af":          4,
		"packets":     3,
	}
	switch q.Kind {
	case KindTrace, KindMTR:
		def["type"] = "traceroute"
		def["protocol"] = "ICMP"
		if q.MaxHops > 0 {
			def["max_hops"] = q.MaxHops
		}
	case KindDNS:
		def["type"] = "dns"
		def["query_argument"] = q.DNSName
		if def["query_argument"] == "" {
			def["query_argument"] = q.Target
		}
		def["query_type"] = "A"
	case KindTCP:
		def["type"] = "ping"
		def["protocol"] = "TCP"
		port := q.Port
		if port == 0 {
			port = 443
		}
		def["port"] = port
	default:
		def["type"] = "ping"
	}
	carriers := q.Carriers
	if len(carriers) == 0 && len(q.Countries) == 0 {
		carriers = []string{"ct", "cu", "cm"}
	}
	var probes []map[string]any
	for _, c := range carriers {
		if asn := primaryASN[c]; asn != 0 {
			probes = append(probes, map[string]any{"requested": 1, "type": "asn", "value": asn})
		}
	}
	for _, c := range q.Countries {
		probes = append(probes, map[string]any{"requested": 1, "type": "country", "value": strings.ToUpper(c)})
	}
	if q.Control > 0 {
		probes = append(probes, map[string]any{"requested": q.Control, "type": "country", "value": "US"})
	}
	if len(probes) == 0 {
		probes = append(probes, map[string]any{"requested": 1, "type": "country", "value": "US"})
	}
	payload := map[string]any{
		"definitions": []any{def},
		"probes":      probes,
		"is_oneoff":   true,
	}
	raw, _ := json.Marshal(payload)
	endpoint := base + "/measurements/?key=" + url.QueryEscape(r.Key)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("user-agent", "ipd/0.9")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ripeatlas %d: %s", resp.StatusCode, truncate(body))
	}
	var created struct {
		Measurements []int `json:"measurements"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		return nil, err
	}
	if len(created.Measurements) == 0 {
		return nil, fmt.Errorf("ripeatlas: empty measurement id")
	}
	id := created.Measurements[0]
	deadline := time.Now().Add(50 * time.Second)
	var last []byte
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		u := fmt.Sprintf("%s/measurements/%d/results/?key=%s", base, id, url.QueryEscape(r.Key))
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		req.Header.Set("user-agent", "ipd/0.9")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		last, _ = io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		resp.Body.Close()
		if resp.StatusCode < 300 && len(bytes.TrimSpace(last)) > 2 {
			samples, err := r.decode(ctx, client, base, q, last)
			if err != nil {
				return nil, err
			}
			if len(samples) > 0 {
				return samples, nil
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return nil, fmt.Errorf("ripeatlas: measurement %d created but results were not ready (%s)", id, truncate(last))
}

func (r RipeAtlas) decode(ctx context.Context, client *http.Client, base string, q Query, body []byte) ([]Sample, error) {
	var rows []map[string]any
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, err
	}
	var out []Sample
	for _, row := range rows {
		prb := intFrom(row["prb_id"])
		asn, cc := r.probeMeta(ctx, client, base, prb)
		netw := CarrierOfASN(asn)
		if cc != "" && cc != "CN" {
			netw = "control"
		}
		if netw == "" && cc == "CN" {
			netw = "ct"
		}
		s := Sample{
			Provider: "ripeatlas",
			Network:  netw,
			ASN:      asn,
			Country:  cc,
			Healthy:  true,
		}
		sent := floatFrom(row["sent"])
		rcvd := floatFrom(row["rcvd"])
		if sent > 0 {
			s.Loss = (sent - rcvd) / sent
		}
		s.RTTMS = floatFrom(row["avg"])
		if q.Kind == KindTCP {
			port := q.Port
			if port == 0 {
				port = 443
			}
			st := "ok"
			if rcvd == 0 {
				st = "timeout"
			}
			s.TCP = map[int]string{port: st}
		} else if q.Kind == KindTrace || q.Kind == KindMTR {
			s.Hops = ripeHops(row["result"])
			s.ICMP = "ok"
			if len(s.Hops) == 0 {
				s.ICMP = "timeout"
			}
		} else if q.Kind == KindDNS {
			s.DNSAddrs = ripeDNS(row["result"])
		} else {
			if rcvd == 0 && sent > 0 {
				s.ICMP = "timeout"
			} else {
				s.ICMP = "ok"
			}
		}
		out = append(out, s)
	}
	return out, nil
}

func (r RipeAtlas) probeMeta(ctx context.Context, client *http.Client, base string, id int) (asn int, cc string) {
	if id == 0 {
		return 0, ""
	}
	u := fmt.Sprintf("%s/probes/%d/?key=%s", base, id, url.QueryEscape(r.Key))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var doc struct {
		ASNv4       int    `json:"asn_v4"`
		CountryCode string `json:"country_code"`
	}
	_ = json.Unmarshal(b, &doc)
	return doc.ASNv4, doc.CountryCode
}

func ripeHops(v any) []Hop {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	var hops []Hop
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		ip := strFrom(m["from"])
		if ip == "" {
			ip = "*"
		}
		hops = append(hops, Hop{IP: ip, RTTMS: floatFrom(m["rtt"])})
	}
	return hops
}

func ripeDNS(v any) []string {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	ans, _ := m["answers"].([]any)
	var out []string
	for _, a := range ans {
		switch t := a.(type) {
		case string:
			out = append(out, t)
		case map[string]any:
			if s := strFrom(t["RDATA"]); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

func intFrom(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case string:
		n, _ := strconv.Atoi(t)
		return n
	default:
		return 0
	}
}

func floatFrom(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case int:
		return float64(t)
	case string:
		f, _ := strconv.ParseFloat(t, 64)
		return f
	default:
		return 0
	}
}

func strFrom(v any) string {
	s, _ := v.(string)
	return s
}

// BOCE runs a ping or traceroute when IPD_BOCE_KEY is set.
// The client speaks the public v3 task API. Node ids are chosen from the
// account's node list by carrier name (电信 / 联通 / 移动).
type BOCE struct {
	Key     string
	BaseURL string
	Client  *http.Client
}

func (b BOCE) Name() string  { return "boce" }
func (b BOCE) Enabled() bool { return b.Key != "" }

func (b BOCE) Measure(ctx context.Context, q Query) ([]Sample, error) {
	if b.Key == "" {
		return nil, errDisabled("boce", "IPD_BOCE_KEY is not set")
	}
	base := strings.TrimRight(b.BaseURL, "/")
	if base == "" {
		base = "https://api.boce.com/v3"
	}
	client := b.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	nodes, err := b.pickNodes(ctx, client, base, q)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("boce: node list had no matching probes")
	}
	kind := "ping"
	switch q.Kind {
	case KindTrace, KindMTR:
		kind = "traceroute"
	case KindDNS:
		kind = "dns"
	case KindHTTP:
		kind = "http"
	}
	ids := make([]string, 0, len(nodes))
	for _, n := range nodes {
		ids = append(ids, n.ID)
	}
	qurl := fmt.Sprintf("%s/task/create/%s?key=%s&node_ids=%s&host=%s",
		base, kind, url.QueryEscape(b.Key), url.QueryEscape(strings.Join(ids, ",")), url.QueryEscape(q.Target))
	body, err := b.get(ctx, client, qurl)
	if err != nil {
		return nil, err
	}
	var created struct {
		ErrorCode int    `json:"error_code"`
		Error     string `json:"error"`
		Data      struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		return nil, err
	}
	if created.ErrorCode != 0 && created.Data.ID == "" {
		return nil, fmt.Errorf("boce: %s", strings.TrimSpace(created.Error+" "+truncate(body)))
	}
	if created.Data.ID == "" {
		return nil, fmt.Errorf("boce: empty task id: %s", truncate(body))
	}
	deadline := time.Now().Add(45 * time.Second)
	var last []byte
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		u := fmt.Sprintf("%s/task/%s/%s?key=%s", base, kind, url.PathEscape(created.Data.ID), url.QueryEscape(b.Key))
		last, err = b.get(ctx, client, u)
		if err != nil {
			return nil, err
		}
		samples := decodeBOCE(last, nodes, q)
		if len(samples) > 0 {
			return samples, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return nil, fmt.Errorf("boce: task %s created but results were not ready (%s)", created.Data.ID, truncate(last))
}

type boceNode struct {
	ID      string
	Name    string
	Carrier string
}

func (b BOCE) pickNodes(ctx context.Context, client *http.Client, base string, q Query) ([]boceNode, error) {
	body, err := b.get(ctx, client, base+"/node/list?key="+url.QueryEscape(b.Key))
	if err != nil {
		return nil, err
	}
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	rawNodes := findNodeList(doc)
	want := map[string]bool{}
	carriers := q.Carriers
	if len(carriers) == 0 && len(q.Countries) == 0 {
		carriers = []string{"ct", "cu", "cm"}
	}
	for _, c := range carriers {
		want[c] = true
	}
	var out []boceNode
	seen := map[string]bool{}
	for _, n := range rawNodes {
		c := boceCarrier(n.Name + " " + n.ISP)
		if c == "" || (len(want) > 0 && !want[c]) || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, boceNode{ID: n.ID, Name: n.Name, Carrier: c})
	}
	return out, nil
}

type rawNode struct {
	ID   string
	Name string
	ISP  string
}

func findNodeList(v any) []rawNode {
	var out []rawNode
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case []any:
			for _, item := range t {
				m, ok := item.(map[string]any)
				if !ok {
					continue
				}
				id := strFrom(m["id"])
				if id == "" {
					id = strFrom(m["node_id"])
				}
				if id == "" {
					if n := intFrom(m["id"]); n != 0 {
						id = strconv.Itoa(n)
					}
				}
				if id == "" {
					continue
				}
				name := firstStr(m, "node_name", "name", "title")
				isp := firstStr(m, "isp_name", "isp", "operator")
				out = append(out, rawNode{ID: id, Name: name, ISP: isp})
			}
		case map[string]any:
			for _, child := range t {
				walk(child)
			}
		}
	}
	walk(v)
	return out
}

func firstStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s := strFrom(m[k]); s != "" {
			return s
		}
	}
	return ""
}

func boceCarrier(s string) string {
	switch {
	case strings.Contains(s, "电信") || strings.Contains(strings.ToLower(s), "telecom"):
		return "ct"
	case strings.Contains(s, "联通") || strings.Contains(strings.ToLower(s), "unicom"):
		return "cu"
	case strings.Contains(s, "移动") || strings.Contains(strings.ToLower(s), "mobile"):
		return "cm"
	default:
		return ""
	}
}

func (b BOCE) get(ctx context.Context, client *http.Client, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("user-agent", "ipd/0.9")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("boce %d: %s", resp.StatusCode, truncate(body))
	}
	return body, nil
}

func decodeBOCE(body []byte, nodes []boceNode, q Query) []Sample {
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}
	byID := map[string]boceNode{}
	for _, n := range nodes {
		byID[n.ID] = n
	}
	var rows []map[string]any
	collectRows(doc, &rows)
	var out []Sample
	for _, row := range rows {
		id := strFrom(row["node_id"])
		if id == "" {
			id = strconv.Itoa(intFrom(row["node_id"]))
		}
		n := byID[id]
		if n.ID == "" {
			continue
		}
		s := Sample{
			Provider: "boce",
			Network:  n.Carrier,
			City:     n.Name,
			Country:  "CN",
			Healthy:  true,
			RTTMS:    floatFrom(first(row, "avg", "rtt", "time")),
			Loss:     floatFrom(first(row, "loss", "packet_loss")),
		}
		if s.Loss > 1 {
			s.Loss = s.Loss / 100
		}
		switch q.Kind {
		case KindTCP:
			port := q.Port
			if port == 0 {
				port = 443
			}
			st := "ok"
			if s.Loss >= 1 {
				st = "timeout"
			}
			s.TCP = map[int]string{port: st}
		case KindTrace, KindMTR:
			s.ICMP = "ok"
		default:
			if s.Loss >= 1 {
				s.ICMP = "timeout"
			} else {
				s.ICMP = "ok"
			}
		}
		out = append(out, s)
	}
	return out
}

func first(m map[string]any, keys ...string) any {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			return v
		}
	}
	return nil
}

func collectRows(v any, out *[]map[string]any) {
	switch t := v.(type) {
	case []any:
		for _, item := range t {
			if m, ok := item.(map[string]any); ok {
				if _, ok := m["node_id"]; ok {
					*out = append(*out, m)
				}
			}
		}
	case map[string]any:
		if _, ok := t["node_id"]; ok {
			*out = append(*out, t)
		}
		for _, child := range t {
			collectRows(child, out)
		}
	}
}
