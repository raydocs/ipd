package nodes

import (
	"context"
	"strings"
	"testing"
	"time"
)

type fake struct{}

func (fake) Check(ctx context.Context, name, socks string) (string, string, string, string, error) {
	if strings.Contains(name, "down") {
		return "", "", "", "", errDown
	}
	return "1.1.1.1", "A", "yes", "yes", nil
}

type downErr string

func (e downErr) Error() string { return string(e) }

const errDown downErr = "down"

func TestFiftyNodes(t *testing.T) {
	var b strings.Builder
	b.WriteString("proxies:\n")
	for i := 0; i < 50; i++ {
		name := "n"
		if i%7 == 0 {
			name = "down"
		}
		b.WriteString("- {name: " + name + itoa(i) + ", type: ss, server: 198.51.100." + itoa(i%200) + ", port: 443}\n")
	}
	f, err := Parse(b.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Proxies) != 50 {
		t.Fatal(len(f.Proxies))
	}
	start := time.Now()
	out, yml, err := Run(context.Background(), f, fake{}, nil, nil, 8)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 3*time.Minute {
		t.Fatal("slow")
	}
	if len(out) != 50 {
		t.Fatal(len(out))
	}
	down := 0
	for _, o := range out {
		if strings.Contains(o.Name, "down") {
			down++
			if o.Error != "unreachable" {
				t.Fatal(o)
			}
		}
	}
	if down == 0 {
		t.Fatal("no down nodes")
	}
	f2, err := Parse(yml)
	if err != nil {
		t.Fatal(err)
	}
	if len(f2.Proxies) != 50 {
		t.Fatalf("renamed %d\n%s", len(f2.Proxies), yml)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func TestMihomoMissing(t *testing.T) {
	m := &Mihomo{Bin: "/nonexistent/mihomo"}
	_, err := m.Start(context.Background(), "nope")
	if err == nil {
		t.Fatal("expected missing binary")
	}
}
