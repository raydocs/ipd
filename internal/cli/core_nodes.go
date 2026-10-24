package cli

import (
	"context"
	"errors"
	"strings"

	"ipd/internal/app"
	"ipd/internal/nodes"
)

const coreNodesHelp = `用法：ipd nodes [--measure --backend auto|mihomo|sing-box --mihomo-bin ABS --sing-box-bin ABS [--unlock IDs]] <本地文件或原生配置>
默认仅解析并 abstain；--measure 显式启动可信本地 core，默认只查询出口 IP，不评分纯净度。
--unlock 需 --measure；显式逗号分隔 1–4 个不同 ID：apple,meta_ai,netflix,claude,chatgpt。
服务观测复用同一存活节点；不保证账号安全、登录或实际播放。未知/重复/过量 ID 发包前拒绝。
测量仅接受有界本地正规文件或 inline Clash YAML / sing-box JSON；不转换、不下载、不请求远程订阅。
core 必须显式绝对路径；不兼容 backend 返回 unsupported。--offline 不启动进程或请求网络。
结果保留原始序号，不输出节点名/凭据/配置；不完整批次全部 unknown。出口观测也不代表安全。
`
const coreNodesHelpEN = `Usage: ipd nodes [--measure --backend auto|mihomo|sing-box --mihomo-bin ABS --sing-box-bin ABS [--unlock IDs]] <local-file-or-native-config>
Default: parse only and abstain. --measure explicitly starts trusted local cores for exit IP only, not purity scoring.
--unlock requires --measure: 1–4 distinct comma-separated IDs from apple,meta_ai,netflix,claude,chatgpt.
Service observations use the same live node; no account safety, login or playback claim. Unknown/duplicate/excess IDs are rejected before requests.
Measurement accepts bounded local regular files or inline native Clash YAML / sing-box JSON; no conversion, downloads or remote subscriptions.
Core paths must be explicit and absolute. Incompatible backends return unsupported. --offline starts no process and makes no network request.
Results preserve original indices, not names/credentials/configs; incomplete batches are all unknown. Observations do not imply safety.
`

func init() {
	// Keep this catalog registration separate from PR22's accepted latency work.
	englishMessages[coreNodesHelp] = coreNodesHelpEN
	englishMessages["节点解锁需要 1–4 个不同的受支持 ID（apple,meta_ai,netflix,claude,chatgpt）"] = "Node unlock requires 1–4 distinct supported IDs (apple,meta_ai,netflix,claude,chatgpt)"
	englishMessages["节点测量参数无效\n%s"] = "Invalid node measurement arguments\n%s"
	englishMessages["节点测量不支持该配置或 backend（unsupported）"] = "Node measurement: unsupported document or backend"
	englishMessages["节点测量需要显式绝对 core 路径"] = "Node measurement requires explicit absolute core paths"
	englishMessages["节点测量需要有界本地正规文件或原生配置"] = "Node measurement requires a bounded local regular file or native config"
}

func coreNodesCmd(ctx context.Context, svc *app.Service, args []string) (app.Report, error) {
	var opts app.CoreNodeOptions
	source := ""
	measure := false
	seen := map[string]bool{}
	bad := func() (app.Report, error) {
		return app.Report{}, cliError("节点测量参数无效\n%s", messageText(coreNodesHelp))
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		key, value, equals := strings.Cut(a, "=")
		switch key {
		case "--measure":
			if measure || equals {
				return bad()
			}
			measure = true
		case "--backend", "--mihomo-bin", "--sing-box-bin", "--unlock":
			if seen[key] {
				return bad()
			}
			seen[key] = true
			if !equals {
				if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
					return bad()
				}
				i++
				value = args[i]
			}
			if value == "" {
				return bad()
			}
			switch key {
			case "--unlock":
				opts.UnlockIDs = strings.Split(value, ",")
			case "--backend":
				if value != "auto" && value != "mihomo" && value != "sing-box" {
					return bad()
				}
				if value != "auto" {
					opts.Backend = nodes.Backend(value)
				}
			case "--mihomo-bin":
				opts.MihomoBin = value
			case "--sing-box-bin":
				opts.SingBoxBin = value
			}
		default:
			// Do not echo unknown arguments: they may contain subscription secrets.
			if strings.HasPrefix(a, "-") || source != "" {
				return bad()
			}
			source = a
		}
	}
	if source == "" || (!measure && len(seen) > 0) {
		return bad()
	}
	if !measure {
		return svc.Nodes(ctx, source, nil)
	}
	report, err := svc.CoreNodes(ctx, source, opts)
	switch {
	case errors.Is(err, app.ErrCoreNodesUnlock):
		return report, cliError("节点解锁需要 1–4 个不同的受支持 ID（apple,meta_ai,netflix,claude,chatgpt）")
	case errors.Is(err, app.ErrCoreNodesUnsupported):
		return report, cliError("节点测量不支持该配置或 backend（unsupported）")
	case errors.Is(err, app.ErrCoreNodesExecutable):
		return report, cliError("节点测量需要显式绝对 core 路径")
	case err != nil:
		return report, cliError("节点测量需要有界本地正规文件或原生配置")
	default:
		return report, nil
	}
}
