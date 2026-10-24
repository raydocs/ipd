package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode"

	"ipd/internal/app"
	"ipd/internal/config"
	"ipd/internal/route"
	"ipd/internal/unlock"
)

// Main writes to process streams; keep these tests serial and use files to
// avoid pipe-buffer deadlocks on full JSON/help output.
func invokeCLI(t *testing.T, input string, args ...string) (int, string, string) {
	t.Helper()
	in, out, stderr := os.Stdin, os.Stdout, os.Stderr
	f, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := io.WriteString(f, input); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	capture := func(name string) *os.File {
		f, err := os.CreateTemp(t.TempDir(), name)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	o, e := capture("stdout"), capture("stderr")
	defer o.Close()
	defer e.Close()
	os.Stdin, os.Stdout, os.Stderr = f, o, e
	defer func() { os.Stdin, os.Stdout, os.Stderr = in, out, stderr }()
	code := Main(args)
	read := func(f *os.File) string {
		if _, err := f.Seek(0, 0); err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(f)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	return code, read(o), read(e)
}

func cliEnv(t *testing.T) {
	t.Helper()
	t.Setenv("IPD_LANG", "")
	t.Setenv("IPD_DATA_DIR", t.TempDir())
	t.Setenv("IPD_OFFLINE", "true")
	t.Setenv("IPD_SERVER", "")
	t.Setenv("IPD_PROXY", "")
	t.Setenv("IPD_MAXMIND_CITY", "")
	t.Setenv("IPD_LABELS_ENABLED", "true")
}

func TestEnglishCoreRegression(t *testing.T) {
	cliEnv(t)
	code, out, errOut := invokeCLI(t, "source evidence 原始\n", "report", "--lang=en")
	first := strings.SplitN(out, "\n", 2)[0]
	if code != 0 || errOut != "" || !strings.Contains(first, "Local report (not uploaded)") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	if !strings.Contains(out, "原始") {
		t.Fatalf("original evidence lost: %s", out)
	}
}

func TestLanguageSelection(t *testing.T) {
	for _, tc := range []struct {
		name, env, lang string
		args, rest      []string
	}{
		{name: "default", lang: "zh", args: []string{"help"}, rest: []string{"help"}},
		{name: "before", lang: "en", args: []string{"--lang", "en", "ai", "--cli"}, rest: []string{"ai", "--cli"}},
		{name: "after", lang: "en", args: []string{"gfw", "example.invalid", "--lang=en"}, rest: []string{"gfw", "example.invalid"}},
		{name: "between", lang: "en", args: []string{"label", "--lang", "en", "192.0.2.4", "原始标签"}, rest: []string{"label", "192.0.2.4", "原始标签"}},
		{name: "env", env: "en", lang: "en", args: []string{"help"}, rest: []string{"help"}},
		{name: "flag wins", env: "en", lang: "zh", args: []string{"help", "--lang=zh"}, rest: []string{"help"}},
		{name: "bad env overridden", env: "invalid", lang: "en", args: []string{"--lang=en"}},
		{name: "last wins", lang: "zh", args: []string{"--lang=en", "--lang", "zh"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("IPD_LANG", tc.env)
			g, rest, err := parseGlobals(tc.args)
			if err != nil || string(g.lang) != tc.lang || !reflect.DeepEqual(rest, tc.rest) {
				t.Fatalf("globals=%+v rest=%v err=%v", g, rest, err)
			}
		})
	}
}

func TestInvalidLanguage(t *testing.T) {
	cliEnv(t)
	for _, args := range [][]string{
		{"--lang"}, {"report", "--lang"}, {"--lang", "--help"},
		{"help", "--lang="}, {"--lang", "EN", "help"}, {"help", "--lang=fr"},
		{"--lang=fr", "--lang=en", "ingest"},
	} {
		code, out, errOut := invokeCLI(t, "", args...)
		if code != 2 || out != "" || !strings.Contains(errOut, "en or zh") {
			t.Errorf("args=%v code=%d out=%q err=%q", args, code, out, errOut)
		}
	}
	t.Setenv("IPD_LANG", "fr")
	code, out, errOut := invokeCLI(t, "", "version")
	if code != 2 || out != "" || !strings.Contains(errOut, "invalid IPD_LANG") {
		t.Fatalf("%d %q %q", code, out, errOut)
	}
}

func hasHan(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return unicode.Is(unicode.Han, r) }) >= 0
}

func TestEnglishHelpAndOwnedErrors(t *testing.T) {
	cliEnv(t)
	for _, args := range [][]string{{"--lang", "en", "help"}, {"--help", "--lang=en"}} {
		code, out, errOut := invokeCLI(t, "", args...)
		if code != 0 || errOut != "" || hasHan(out) || !strings.Contains(out, "--lang en|zh") {
			t.Fatalf("%d %q %q", code, out, errOut)
		}
	}
	for _, args := range [][]string{
		{"gfw"}, {"mail"}, {"nodes"}, {"label"}, {"watch"}, {"watch", "bogus"},
		{"watch", "add"}, {"watch", "rm"}, {"data"}, {"agent"}, {"unknown-command"},
	} {
		code, out, errOut := invokeCLI(t, "", append(args, "--lang=en")...)
		if code != 2 || out != "" || hasHan(errOut) || errOut == "" {
			t.Fatalf("%v: %d %q %q", args, code, out, errOut)
		}
	}
	code, out, errOut := invokeCLI(t, "", "help")
	if code != 0 || errOut != "" || !strings.Contains(out, "给 agent 用的") {
		t.Fatal("Chinese default changed")
	}
	code, out, errOut = invokeCLI(t, "", "gfw", "--lang=zh")
	if code != 2 || out != "" || errOut != "用法：ipd gfw <ip|主机>\n" {
		t.Fatalf("%d %q %q", code, out, errOut)
	}
}

func TestEnglishCoreCommands(t *testing.T) {
	cliEnv(t)
	t.Setenv("IPD_VANTAGE", "self")
	cases := []struct {
		args           []string
		input, summary string
	}{
		{[]string{"192.0.2.11"}, "", "IP risk assessment; purity score"},
		{[]string{"batch"}, "192.0.2.11\n192.0.2.12\n", "Batch IP assessment; 2 results"},
		{[]string{"leak"}, "", "DNS leak assessment; 0 resolver observations"},
		{[]string{"label", "192.0.2.11", "原始标签"}, "", "Label saved"},
		{[]string{"watch", "ls"}, "", "Watch list; 0 watches"},
		{[]string{"watch", "rm", "example-watch"}, "", "Watch deleted"},
		{[]string{"nodes", "proxies:\n  - name: original-node\n    type: socks5\n    server: 192.0.2.10\n    port: 1080\n"}, "", "Node assessment"},
	}
	for _, tc := range cases {
		t.Run(tc.args[0], func(t *testing.T) {
			// Verdict and exit code must not depend on output language.
			zhCode, zhOut, zhErr := invokeCLI(t, tc.input, tc.args...)
			enCode, enOut, enErr := invokeCLI(t, tc.input, append(tc.args, "--lang=en")...)
			first := strings.SplitN(enOut, "\n", 2)[0]
			if enCode != zhCode || enErr != zhErr || !strings.Contains(first, tc.summary) || hasHan(first) {
				t.Fatalf("zh=%d %q %q en=%d %q %q", zhCode, zhOut, zhErr, enCode, enOut, enErr)
			}
			if strings.SplitN(zhOut, " — ", 2)[0] != strings.SplitN(enOut, " — ", 2)[0] {
				t.Fatal("VERDICT changed")
			}
		})
	}
	code, out, errOut := invokeCLI(t, "", "ingest", "--lang=en")
	if code != 0 || errOut != "" || !strings.HasPrefix(out, "Wrote ") || hasHan(out) {
		t.Fatalf("%d %q %q", code, out, errOut)
	}
}

func TestSummaryBoundaryAndEvidencePreservation(t *testing.T) {
	original := app.Report{
		Verdict: "abstain", Summary: "回程没有跳数：upstream 原始错误\nsecond line",
		Data:        map[string]any{"note": "用法：ipd mail <主机>", "evidence": "标签已保存 原始", "ip": "192.0.2.27", "status": "cannot determine", "nested": map[string]any{"body": strings.Repeat("原始证据", 100)}},
		Sources:     []app.Source{{ID: "source-id", Attribution: "原始归属", License: "原始许可", Raw: map[string]any{"summary": "不翻译", "error": "原始错误"}}},
		Attribution: []string{"原始 attribution"}, CachedAt: time.Unix(1, 0).UTC(), SnapshotAt: time.Unix(2, 0).UTC(), SnapshotAgeSeconds: 42,
	}
	before, _ := json.Marshal(original)
	for _, cmd := range []string{"me", "check", "ai", "unlock", "leak", "route", "gfw", "mail", "nodes", "batch", "watch", "report", "label", "latency", "192.0.2.27"} {
		for _, format := range []string{"text", "md", "json"} {
			b, _ := renderLocalized(format, original, "en", cmd, nil)
			if format == "json" {
				var got map[string]json.RawMessage
				if err := json.Unmarshal(b, &got); err != nil {
					t.Fatal(err)
				}
				var want map[string]json.RawMessage
				_ = json.Unmarshal(before, &want)
				for key, val := range want {
					if key == "summary_md" {
						continue
					}
					var v1, v2 any
					_ = json.Unmarshal(val, &v1)
					_ = json.Unmarshal(got[key], &v2)
					if !reflect.DeepEqual(v1, v2) {
						t.Fatalf("%s changed: %s", key, b)
					}
				}
				var summary, raw string
				_ = json.Unmarshal(got["summary_md"], &summary)
				_ = json.Unmarshal(got["original_summary_md"], &raw)
				if hasHan(summary) || !strings.Contains(summary, "See data") || raw != original.Summary {
					t.Fatalf("bad summary: %s", b)
				}
			} else {
				lines := strings.SplitN(string(b), "\n", 5)
				if !strings.Contains(lines[0], "VERDICT: abstain") {
					t.Fatalf("verdict changed: %s", b)
				}
				summary := lines[0]
				if format == "md" {
					summary = lines[2]
				}
				if hasHan(summary) || !strings.Contains(summary, "See data") {
					t.Fatalf("not English: %s", b)
				}
				if !strings.Contains(string(b), "original_summary_md") || !strings.Contains(string(b), "upstream 原始错误") {
					t.Fatal("original summary lost")
				}
			}
		}
	}
	after, _ := json.Marshal(original)
	if string(before) != string(after) {
		t.Fatal("input report mutated")
	}
	for _, format := range []string{"text", "md", "json"} {
		want, _ := render(format, original)
		got, _ := renderLocalized(format, original, "zh", "route", nil)
		if string(want) != string(got) {
			t.Fatalf("default changed in %s", format)
		}
	}
}

func TestOnlyOwnedTemplatesTranslate(t *testing.T) {
	const evidence = "用法：ipd mail <主机>"
	if got := locale("en").error(errors.New(evidence)); got != evidence {
		t.Fatalf("external error translated: %q", got)
	}
	if got := locale("en").error(cliError(evidence)); got != "Usage: ipd mail <host>" {
		t.Fatal(got)
	}
	raw := "标签已保存 %s 原始错误"
	got := locale("en").error(cliError("未知命令 %s\n%s", raw, "help"))
	if got != "Unknown command "+raw+"\nhelp" {
		t.Fatal("placeholder evidence changed: " + got)
	}
	if got := locale("en").originalProgress(raw); !strings.HasSuffix(got, raw) || !strings.HasPrefix(got, "Data update (original progress): ") {
		t.Fatal(got)
	}
	for template, en := range englishMessages {
		if got := locale("zh").text(template); got != template {
			t.Fatalf("default template changed: %s", template)
		}
		if hasHan(en) {
			t.Fatalf("not English: %s", en)
		}
	}
}

func TestNestedTemplatesAndWrappedErrors(t *testing.T) {
	cause := errors.New("filesystem 原始错误")
	err := cliError("保存 SVG: %w", cause)
	if !errors.Is(err, cause) {
		t.Fatal("wrapped cause lost")
	}
	if got := locale("en").error(err); got != "Save SVG: "+cause.Error() {
		t.Fatal(got)
	}
	if got := locale("zh").error(err); got != "保存 SVG: "+cause.Error() {
		t.Fatal(got)
	}
	unknown := "原始参数"
	err = cliError("未知 latency 参数 %s\n%s", unknown, messageText(latencyUsageZH))
	if got := locale("en").error(err); got != "Unknown latency argument "+unknown+"\n"+latencyUsageEN {
		t.Fatal(got)
	}
	external := fmt.Errorf("external 原始 prefix: %w", cliError("用法：ipd mail <主机>"))
	if got := locale("en").error(external); got != external.Error() {
		t.Fatal("external prefix discarded: " + got)
	}
}

type localeGetter struct{}

func (localeGetter) Get(_ context.Context, url string, _ map[string]string) unlock.Response {
	return unlock.Response{Status: 200, Body: "ip=192.0.2.37\nloc=ZZ\noriginal 原始 evidence", FinalURL: url}
}

func TestEnglishServiceResults(t *testing.T) {
	cliEnv(t)
	cfg := config.FromEnv()
	svc := app.New(cfg, nil)
	svc.Checks = &unlock.Engine{Get: localeGetter{}}
	svc.Egress = func(context.Context) (string, string) { return "192.0.2.37", "" }
	svc.Tracer = func(context.Context, string) ([]route.Hop, error) { return nil, errors.New("external 路由证据") }
	for _, cmd := range []string{"me", "ai", "unlock", "check", "route"} {
		rep, err := dispatch(context.Background(), svc, cfg, globals{lang: "en"}, cmd, nil)
		if err != nil {
			t.Fatalf("%s: %v", cmd, err)
		}
		original, _ := json.Marshal(rep)
		body, _ := renderLocalized("json", rep, "en", cmd, nil)
		var got struct {
			app.Report
			OriginalSummary string `json:"original_summary_md"`
		}
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		if got.Verdict != rep.Verdict || app.ExitCode(got.Verdict) != app.ExitCode(rep.Verdict) || hasHan(got.Summary) || got.OriginalSummary != rep.Summary {
			t.Fatalf("%s: %s", cmd, body)
		}
		data, _ := json.Marshal(rep.Data)
		var want any
		if err := json.Unmarshal(data, &want); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(want, got.Data) {
			t.Fatalf("%s data changed", cmd)
		}
		after, _ := json.Marshal(rep)
		if string(original) != string(after) {
			t.Fatal("source report mutated")
		}
	}
}

func TestIncompleteExportMessagePreservesWarningAndCause(t *testing.T) {
	const template = "保存 SVG: %w; empty/partial export may remain (no path cleanup attempted)"
	cause := errors.New("filesystem 原始证据")
	wrapped := cliError(template, cause)
	if !errors.Is(wrapped, cause) {
		t.Fatal("cause lost")
	}
	if got := locale("en").error(wrapped); got != "Save SVG: "+cause.Error()+"; empty/partial export may remain (no path cleanup attempted)" {
		t.Fatal(got)
	}
	nested := cliError(template, cliError("latency 响应缺少 SVG"))
	if got := locale("en").error(nested); hasHan(got) || got != "Save SVG: Latency response is missing SVG; empty/partial export may remain (no path cleanup attempted)" {
		t.Fatal(got)
	}
	if got := locale("zh").error(nested); got != nested.Error() {
		t.Fatal("default changed")
	}
}

func TestNodeUnavailableOverviewDoesNotGuessReachability(t *testing.T) {
	rep := app.Report{Verdict: "abstain", Data: map[string]any{"nodes": []any{}, "count": 3, "measured_count": 0, "measurement_status": "unavailable", "reason": "原始原因"}}
	out, _ := renderLocalized("text", rep, "en", "nodes", nil)
	first := strings.SplitN(string(out), "\n", 2)[0]
	if !strings.HasPrefix(first, "VERDICT: abstain") || !strings.Contains(first, "measurement unavailable") || !strings.Contains(first, "0 nodes measured") || strings.Contains(first, "unreachable") || hasHan(first) {
		t.Fatal(first)
	}
}
