package providers

import (
	"strings"
	"testing"
)

func TestUniqueJSON(t *testing.T) {
	for _, raw := range []string{`{"a":{"b":1},"c":{"b":2},"values":[null,true,1,"unicode ſ"]}`, `[{"x":1},{"x":2}]`, `{"a":1,"b":2}`} {
		if err := validateUniqueJSON([]byte(raw)); err != nil {
			t.Fatalf("valid JSON rejected: %v", err)
		}
	}
	for _, raw := range []string{`{"a":1,"\u0061":2}`, `{"x":{"p":1,"p":2}}`, `{"a":1} {"b":2}`, `{"a":`, `[1,2}`, strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66)} {
		if validateUniqueJSON([]byte(raw)) == nil {
			t.Fatal("ambiguous/malformed/deep JSON accepted")
		}
	}
}
