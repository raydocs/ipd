package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"ipd/internal/config"
	"ipd/internal/litmus"
)

func litmusCmd(cfg *config.Config, opts globals, args []string) int {
	usage := "用法：ipd litmus <google_search|cloudflare_home|akamai_home> [--offline] [--json]\n仅观察单次响应已知证据；非风险评分，Cloudflare Bot Score 不可获得。\n"
	if opts.lang == "en" {
		usage = "Usage: ipd litmus <google_search|cloudflare_home|akamai_home> [--offline] [--json]\nKnown evidence in one response only; not a risk score. Cloudflare Bot Score unavailable.\n"
	}
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Print(usage)
		return 0
	}
	if len(args) != 1 || !litmus.ValidID(args[0]) || opts.proxy != "" || opts.server != "" || opts.ipv != "" {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	r := (litmus.Engine{}).Check(context.Background(), args[0], cfg.Offline)
	if opts.format == "json" {
		_ = json.NewEncoder(os.Stdout).Encode(r)
	} else {
		label := "已知挑战证据（仅单次响应）"
		if opts.lang == "en" {
			label = "Known challenge evidence (single response only)"
		}
		fmt.Printf("%s: %s\nreason: %s\ncf_bot_score: unknown\n", label, r.ChallengeObserved, r.Reason)
	}
	// Evidence presence never means usable/clean/risky; this is not a risk verdict.
	return 10
}
