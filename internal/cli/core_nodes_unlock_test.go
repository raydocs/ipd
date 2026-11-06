package cli

import (
	"context"
	"strings"
	"testing"

	"ipd/internal/app"
	"ipd/internal/config"
)

// PR25 must fail this: explicit unlock is a new opt-in, not an unknown flag.
func TestCoreNodesUnlockOptInRegression(t *testing.T) {
	cfg := &config.Config{Offline: true}
	svc := app.New(cfg, nil)
	rep, err := coreNodesCmd(context.Background(), svc, []string{"--measure", "--unlock=apple,meta_ai", "--mihomo-bin=/not/executed", "proxies: []"})
	if err != nil || rep.Verdict != "abstain" {
		t.Fatalf("explicit offline unlock rejected: %v %+v", err, rep)
	}
	for _, lang := range []string{"en", "zh"} {
		if !strings.Contains(locale(lang).text(coreNodesHelp), "--unlock") {
			t.Fatal("unlock help missing")
		}
	}
}

func TestCoreNodesUnlockCLISelectionAndLocale(t *testing.T) {
	cfg := &config.Config{Offline: true}
	svc := app.New(cfg, nil)
	source := "proxies: []"
	for _, args := range [][]string{
		{"--unlock=apple", source},
		{"--measure", "--unlock", source},
		{"--measure", "--unlock=", source},
		{"--measure", "--unlock=apple", "--unlock=meta_ai", source},
		{"--measure", "--unlock=secret-unknown", source},
		{"--measure", "--unlock=apple,apple", source},
		{"--measure", "--unlock=apple,meta_ai,claude,chatgpt,netflix", source},
		{"--measure", "--unlock=apple,", source},
		{"--measure", "--unlock=APPLE", source},
		{"--measure", "--unlock=apple, meta_ai", source},
	} {
		_, err := coreNodesCmd(context.Background(), svc, args)
		if err == nil {
			t.Fatal("invalid unlock parameters accepted")
		}
		en, zh := locale("en").error(err), locale("zh").error(err)
		if !strings.HasPrefix(en, "Node unlock requires") && !strings.HasPrefix(en, "Invalid node measurement") {
			t.Fatalf("unowned English error: %s", en)
		}
		if !strings.HasPrefix(zh, "节点解锁需要") && !strings.HasPrefix(zh, "节点测量参数无效") {
			t.Fatalf("unowned Chinese error: %s", zh)
		}
		if strings.Contains(en, "secret-") || strings.Contains(zh, "secret-") {
			t.Fatal("selection echoed")
		}
	}
	for _, args := range [][]string{
		{"--measure", "--unlock", "apple,meta_ai", source},
		{"--measure", "--unlock=claude,chatgpt,netflix,apple", source},
	} {
		rep, err := coreNodesCmd(context.Background(), svc, args)
		if err != nil || rep.Verdict != "abstain" {
			t.Fatalf("valid selection: %v", err)
		}
	}
	for _, lang := range []string{"en", "zh"} {
		out, code := captureLatencyMain(t, []string{"--lang", lang, "nodes", "--help"})
		if code != 0 || !strings.Contains(out, "--unlock") || !strings.Contains(out, "apple,meta_ai") {
			t.Fatalf("missing owned help: %s", out)
		}
	}
}
