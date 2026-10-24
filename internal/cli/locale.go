package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"ipd/internal/app"
)

// Locale is invocation-local: it never changes the app, HTTP or MCP language.
type locale string

// Only trusted CLI templates enter this catalog. Never pass source evidence or
// an arbitrary error string to text; placeholders are interpolated afterwards.
var englishMessages = map[string]string{
	"标签已保存":                     "Label saved",
	"已删除 %s":                    "Deleted %s",
	"本地报告（未上传）":                 "Local report (not uploaded)",
	"一站式：%s。AI %s，解锁 %s，DNS %s": "Combined: %s. AI %s, unlocking %s, DNS %s",
	// PR9 templates are registered without enabling its command or SVG code.
	latencyUsageZH:                    latencyUsageEN,
	"--svg 只能指定一次":                    "--svg may only be specified once",
	"--svg 需要本地文件路径":                  "--svg requires a local file path",
	"未知 latency 参数 %s\n%s":            "Unknown latency argument %s\n%s",
	"保存 SVG: %w":                      "Save SVG: %w",
	"latency 响应缺少 SVG":                "Latency response is missing SVG",
	"用法：ipd gfw <ip|主机>":              "Usage: ipd gfw <ip|host>",
	"用法：ipd mail <主机>":                "Usage: ipd mail <host>",
	"用法：ipd nodes <订阅或 clash.yaml>":   "Usage: ipd nodes <subscription or clash.yaml>",
	"用法：ipd label <ip> <标签>":          "Usage: ipd label <ip> <label>",
	"用法：ipd watch add|ls|rm":          "Usage: ipd watch add|ls|rm",
	"用法：ipd watch add <ip> [webhook]": "Usage: ipd watch add <ip> [webhook]",
	"用法：ipd watch rm <id>":            "Usage: ipd watch rm <id>",
	"用法：ipd data update":              "Usage: ipd data update",
	"未知命令 %s\n%s":                     "Unknown command %s\n%s",
	"ipd agent 需要 --server 或 IPD_SERVER，指向 hub 的 http 地址": "ipd agent requires --server or IPD_SERVER pointing to the hub HTTP address",
	"已写入 %s，启用本地源 %d 个\n":                                 "Wrote %s; %d local sources enabled\n",
	"ipd %s 监听 http://%s （域名配置为 %s，未绑定公网）\n":              "ipd %s listening on http://%s (configured domain: %s; not bound to a public interface)\n",
	"%s 失败: %s\n":       "%s failed: %s\n",
	"%s %d 条%s\n":       "%s %d rows%s\n",
	"快照目录 %s\n":         "Snapshot directory %s\n",
	"读取数据快照: %v\n":      "Read data snapshot: %v\n",
	"data: %s 失败: %s\n": "data: %s failed: %s\n",
}

func (l locale) text(template string) string {
	if l == "en" {
		if template == helpText {
			return englishHelp
		}
		if en, ok := englishMessages[template]; ok {
			return en
		}
	}
	return template
}

// messageText marks a nested trusted CLI template, never an external value.
// This lets PR9's usage errors include localized help without translating args.
type messageText string

func (m messageText) String() string { return string(m) }

type messageError struct {
	template string
	args     []any
	original error
}

func (e *messageError) Error() string { return e.original.Error() }
func (e *messageError) Unwrap() error { return errors.Unwrap(e.original) }
func cliError(template string, args ...any) error {
	return &messageError{template: template, args: args, original: fmt.Errorf(template, args...)}
}
func (l locale) error(err error) string {
	msg, owned := err.(*messageError)
	if owned {
		args := append([]any(nil), msg.args...)
		for i, arg := range args {
			if text, ok := arg.(messageText); ok {
				args[i] = l.text(string(text))
			}
		}
		return fmt.Errorf(l.text(msg.template), args...).Error()
	}
	return err.Error() // external/app errors are evidence, not catalog keys
}
func (l locale) originalProgress(line string) string {
	if l == "en" {
		return "Data update (original progress): " + line
	}
	return line
}

// Build an English overview from command identity and structured counts only.
// Never parse/translate an upstream summary, free-form diagnosis or evidence.
func englishSummary(cmd string, args []string, rep app.Report) string {
	labels := map[string]string{
		"me": "Egress assessment", "check": "Combined network assessment",
		"ai": "AI environment assessment", "unlock": "Service availability assessment",
		"leak": "DNS leak assessment", "route": "Route assessment",
		"gfw": "Firewall reachability assessment", "mail": "Mail port reachability assessment",
		"nodes": "Node assessment", "batch": "Batch IP assessment",
		"watch": "Watch operation", "report": "Report operation", "label": "Label saved",
		// PR9 can use the same summary boundary without importing its implementation.
		"latency": "Latency assessment",
	}
	label := labels[cmd]
	if looksLikeIP(cmd) {
		label = "IP risk assessment"
	}
	if label == "" {
		label = "Command result"
	}
	// JSON is a read-only projection to handle typed app structs and remote maps
	// equally. The original data is still passed to the renderer unmodified.
	raw, _ := json.Marshal(rep.Data)
	var data map[string]any
	_ = json.Unmarshal(raw, &data)
	details := []string{}
	if purity, ok := data["purity"].(map[string]any); ok {
		if score, ok := purity["score"].(float64); ok {
			details = append(details, fmt.Sprintf("purity score %g", score))
		}
	}
	keys := []struct{ key, label string }{
		{"results", "results"}, {"per_service", "service results"}, {"fixes", "diagnostic fixes"},
		{"resolvers", "resolver observations"}, {"nodes", "node results"},
		{"watches", "watches"}, {"paths", "paths"}, {"rows", "probe results"},
		{"reachable_by", "reachable locations"},
	}
	for _, key := range keys {
		if rows, ok := data[key.key].([]any); ok {
			details = append(details, fmt.Sprintf("%d %s", len(rows), key.label))
		}
	}
	if cmd == "report" {
		shared := false
		for _, arg := range args {
			if arg == "--share" {
				shared = true
			}
		}
		if shared {
			label = "Shared report"
		} else {
			label = "Local report (not uploaded)"
		}
	}
	if cmd == "watch" && len(args) > 0 {
		switch args[0] {
		case "add":
			label = "Watch created"
		case "rm":
			label = "Watch deleted"
		case "ls":
			label = "Watch list"
		}
	}
	if len(details) > 0 {
		label += "; " + strings.Join(details, "; ")
	}
	return label + ". See data for original evidence; --json includes full sources and original_summary_md."
}

// Preserve every original report field except the localized summary. An
// additive CLI-only field preserves that summary too, including arbitrary
// upstream text/errors which must not be guessed at or silently discarded.
func renderLocalized(format string, rep app.Report, lang locale, cmd string, args []string) ([]byte, string) {
	if lang != "en" {
		return render(format, rep)
	}
	original := rep.Summary
	rep.Summary = englishSummary(cmd, args, rep)
	if format == "json" {
		b, _ := json.MarshalIndent(struct {
			app.Report
			OriginalSummary string `json:"original_summary_md"`
		}{rep, original}, "", "  ")
		return append(b, '\n'), "application/json; charset=utf-8"
	}
	b, mime := render(format, rep)
	raw, _ := json.Marshal(original)
	if format == "md" {
		b = append(b, []byte("\n## original_summary_md\n\n```json\n")...)
		b = append(b, raw...)
		b = append(b, []byte("\n```\n")...)
	} else {
		b = append(b, []byte("original_summary_md: ")...)
		b = append(b, raw...)
		b = append(b, '\n')
	}
	return b, mime
}

const englishHelp = `ipd — address intelligence and network quality for agents

  ipd                      Assess this machine's egress; conclusion first
  ipd 192.0.2.1            Explain IP purity, residential class and native status
  ipd check                Egress, AI, unlocking, leaks and return routes
  ipd ai [--cli]           Assess Claude / ChatGPT and other AI services
  ipd unlock [services…]   Check service availability
  ipd leak                 DNS leaks (use the browser page for WebRTC)
  ipd route [--return] [--claimed cn2gia] [target]
  ipd gfw <ip|host>        Firewall blocking versus congestion
  ipd mail <host>          Check mail port reachability
  ipd nodes <clash.yaml>   Batch nodes (subscriptions parsed locally only)
  ipd batch                Read IPs from standard input
  ipd watch add|ls|rm
  ipd report [--share]     Local report; only --share uploads, after redaction
  ipd label <ip> <label>   Requires IPD_LABELS_ENABLED=true
  ipd data update          Download free datasets and refresh local snapshots
  ipd serve | mcp | agent | ingest | version

Global: --lang en|zh --json --md --txt --offline --proxy URL --server URL -4 -6
Language: --lang overrides IPD_LANG; default zh. Flags work before or after the command.
Exit codes: 0 normal, 10 caveats, 20 poor; 2 invocation/operation error.
Use IPD_DOMAIN for the domain; all listen addresses are configurable.
serve updates data via IPD_DATA_UPDATE (on by default unless offline).
Peak sampling: IPD_PEAK; canaries: IPD_CANARY; both off by default.
English summaries are controlled overviews, not translations of source evidence.
data, sources and external errors remain original; --json includes full evidence.
`

// These constants only register translations for the separately implemented
// PR9 command. The base CLI must not advertise a command it does not implement.
const latencyUsageZH = `用法：ipd latency <target> [--svg <local-file>]
只保存本地自包含 SVG，不上传或开启分享；拒绝覆盖，权限 0600。
单次 ICMP 探针预算不变；--offline 不请求探针。无有效 RTT 返回 abstain（退出码 10）。
`
const latencyUsageEN = `Usage: ipd latency <target> [--svg <local-file>]
Save only a local self-contained SVG; no upload or sharing. Refuse overwrites; permissions 0600.
The single ICMP probe budget is unchanged; --offline makes no probe requests.
No valid RTT yields abstain (exit code 10).
`
