package mcp

import (
	"strings"
	"testing"
	"unicode/utf8"

	"ipd/internal/app"
)

func TestToOutSummaryUTF8(t *testing.T) {
	for _, tc := range []struct {
		name, summary, want string
	}{
		{"empty", "", ""},
		{"short", "short中文🙂", "short中文🙂"},
		{"ascii/exact", strings.Repeat("a", 600), strings.Repeat("a", 600)},
		{"ascii/over", strings.Repeat("a", 601), strings.Repeat("a", 600)},
		{"chinese/exact", strings.Repeat("中", 200), strings.Repeat("中", 200)},
		{"chinese/over", strings.Repeat("中", 201), strings.Repeat("中", 200)},
		{"chinese/offset-1", "a" + strings.Repeat("中", 200), "a" + strings.Repeat("中", 199)},
		{"chinese/offset-2", "aa" + strings.Repeat("中", 200), "aa" + strings.Repeat("中", 199)},
		{"emoji/exact", strings.Repeat("🙂", 150), strings.Repeat("🙂", 150)},
		{"emoji/offset-1", "a" + strings.Repeat("🙂", 150), "a" + strings.Repeat("🙂", 149)},
		{"emoji/offset-2", "aa" + strings.Repeat("🙂", 150), "aa" + strings.Repeat("🙂", 149)},
		{"emoji/offset-3", "aaa" + strings.Repeat("🙂", 150), "aaa" + strings.Repeat("🙂", 149)},
		{"mixed", "中文🙂" + strings.Repeat("中", 200), "中文🙂" + strings.Repeat("中", 196)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := toOut(app.Report{Summary: tc.summary, Data: map[string]any{"summary": tc.summary}})
			if err != nil {
				t.Fatal(err)
			}
			if out.SummaryMD != tc.want || !utf8.ValidString(out.SummaryMD) || len(out.SummaryMD) > 600 {
				t.Errorf("want intact prefix %q (%d bytes), got %q (%d bytes)", tc.want, len(tc.want), out.SummaryMD, len(out.SummaryMD))
			}
			if strings.HasPrefix(tc.summary, out.SummaryMD) && len(out.SummaryMD) < len(tc.summary) {
				_, next := utf8.DecodeRuneInString(tc.summary[len(out.SummaryMD):])
				if len(out.SummaryMD)+next <= 600 {
					t.Error("summary is not the longest UTF-8 prefix within 600 bytes")
				}
			}
			if out.Data["summary"] != tc.summary {
				t.Error("structured data was truncated")
			}
		})
	}
}
