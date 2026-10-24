// Package cli is the ipd command line. Chinese is the default locale.
// The same binary serves HTTP, MCP, the probe agent, and the checks.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"ipd/internal/api"
	"ipd/internal/app"
	"ipd/internal/config"
	"ipd/internal/ingest"
	"ipd/internal/listen"
	"ipd/internal/mcp"
	"ipd/internal/privacy"
	"ipd/internal/probe"
	"ipd/internal/store"
	"ipd/internal/version"
)

// Main runs one invocation and returns the process exit code.
func Main(args []string) int {
	opts, rest, err := parseGlobals(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, opts.lang.error(err))
		return 2
	}
	cfg := config.FromEnv()
	if opts.offline {
		cfg.Offline = true
	}
	if opts.proxy != "" {
		cfg.Proxy = opts.proxy
	}
	if opts.server != "" {
		cfg.ServerURL = opts.server
	}
	if len(rest) == 0 {
		rest = []string{"me"}
	}
	cmd := rest[0]
	switch cmd {
	case "help", "-h", "--help":
		fmt.Fprint(os.Stdout, opts.lang.text(helpText))
		return 0
	case "latency":
		if len(rest) == 2 && (rest[1] == "--help" || rest[1] == "-h") {
			fmt.Fprint(os.Stdout, opts.lang.text(latencyHelp))
			return 0
		}
	case "version":
		fmt.Printf("ipd %s\n", version.Version)
		return 0
	case "serve":
		return serve(cfg, opts.lang)
	case "mcp":
		return runMCP(cfg)
	case "ingest":
		res, err := ingest.Run(context.Background(), cfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		fmt.Printf(opts.lang.text("已写入 %s，启用本地源 %d 个\n"), res.Note, res.Sources)
		if res.MaxMind != "" {
			fmt.Println(res.MaxMind)
		}
		return 0
	case "data":
		return dataCmd(cfg, rest[1:], opts.lang)
	case "agent":
		return runAgent(cfg, opts.lang)
	}
	db := openDB(cfg)
	defer func() {
		if db != nil {
			_ = db.Close()
		}
	}()
	svc := app.New(cfg, db)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rep, err := dispatch(ctx, svc, cfg, opts, cmd, rest[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, opts.lang.error(err))
		return 2
	}
	rep = svc.WithSnapshot(rep)
	body, _ := renderLocalized(opts.format, rep, opts.lang, cmd, rest[1:])
	fmt.Fprint(os.Stdout, string(body))
	return app.ExitCode(rep.Verdict)
}

type globals struct {
	lang    locale
	format  string
	offline bool
	proxy   string
	server  string
	ipv     string
}

func parseGlobals(args []string) (globals, []string, error) {
	g := globals{format: "text", lang: "zh"}
	var langValue string
	langSeen := false
	var langErr error
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		take := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch {
		case a == "--lang" || strings.HasPrefix(a, "--lang="):
			langSeen = true
			if a == "--lang" {
				if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
					langErr = fmt.Errorf("--lang requires en or zh")
					continue
				}
				langValue = take()
			} else {
				langValue = strings.TrimPrefix(a, "--lang=")
			}
			if langValue != "en" && langValue != "zh" {
				langErr = fmt.Errorf("invalid --lang %q: expected en or zh", langValue)
			}
		case a == "--json":
			g.format = "json"
		case a == "--md":
			g.format = "md"
		case a == "--txt":
			g.format = "text"
		case a == "--offline":
			g.offline = true
		case a == "--privacy":
			// default already on
		case a == "--proxy":
			g.proxy = take()
		case a == "--server":
			g.server = take()
		case a == "-4":
			g.ipv = "4"
		case a == "-6":
			g.ipv = "6"
		case strings.HasPrefix(a, "--proxy="):
			g.proxy = strings.TrimPrefix(a, "--proxy=")
		case strings.HasPrefix(a, "--server="):
			g.server = strings.TrimPrefix(a, "--server=")
		default:
			rest = append(rest, a)
		}
	}
	if !langSeen {
		langValue = os.Getenv("IPD_LANG")
		if langValue == "" {
			langValue = "zh"
		}
		if langValue != "en" && langValue != "zh" {
			langErr = fmt.Errorf("invalid IPD_LANG %q: expected en or zh", langValue)
		}
	}
	if langValue == "en" || langValue == "zh" {
		g.lang = locale(langValue)
	}
	return g, rest, langErr
}

func dispatch(ctx context.Context, svc *app.Service, cfg *config.Config, g globals, cmd string, args []string) (app.Report, error) {
	switch cmd {
	case "me":
		rep, err := svc.WhoAmI(ctx, discover(), g.ipv)
		return rep, err
	case "check":
		return check(ctx, svc, g.lang)
	case "ai":
		cli := false
		for _, a := range args {
			if a == "--cli" {
				cli = true
			}
		}
		return svc.AIEnv(ctx, cli), nil
	case "unlock":
		return svc.Unlock(ctx, args), nil
	case "leak":
		return svc.DNSLeak(ctx, 1), nil
	case "route":
		return routeCmd(ctx, svc, args)
	case "latency":
		return latencyCmd(ctx, svc, args)
	case "gfw":
		if len(args) == 0 {
			return app.Report{}, cliError("用法：ipd gfw <ip|主机>")
		}
		return svc.GFW(ctx, args[0], nil)
	case "mail":
		if len(args) == 0 {
			return app.Report{}, cliError("用法：ipd mail <主机>")
		}
		return svc.PortCheck(ctx, args[0], 25, "global")
	case "nodes":
		if len(args) == 0 {
			return app.Report{}, cliError("用法：ipd nodes <订阅或 clash.yaml>")
		}
		return svc.Nodes(ctx, args[0], nil)
	case "batch":
		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			return app.Report{}, err
		}
		var ips []string
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				ips = append(ips, line)
			}
		}
		return svc.Batch(ctx, ips)
	case "watch":
		return watchCmd(svc, args, g.lang)
	case "report":
		return reportCmd(svc, args, g.lang)
	case "label":
		if len(args) < 2 {
			return app.Report{}, cliError("用法：ipd label <ip> <标签>")
		}
		note := ""
		if len(args) > 2 {
			note = strings.Join(args[2:], " ")
		}
		if err := svc.Label(args[0], args[1], note); err != nil {
			return app.Report{}, err
		}
		return app.Report{Verdict: "ok", Summary: g.lang.text("标签已保存"), Data: map[string]any{"ip": args[0], "label": args[1]}, Sources: []app.Source{}}, nil
	default:
		if looksLikeIP(cmd) {
			if cfg.ServerURL != "" {
				return remote(ctx, cfg.ServerURL, "/v1/ip/"+cmd+"/risk")
			}
			return svc.Risk(ctx, cmd, !cfg.Offline)
		}
		return app.Report{}, cliError("未知命令 %s\n%s", cmd, g.lang.text(helpText))
	}
}

const latencyHelp = latencyUsageZH

func latencyCmd(ctx context.Context, svc *app.Service, args []string) (app.Report, error) {
	target, path := "", ""
	svgSeen := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--svg" || strings.HasPrefix(a, "--svg="):
			if svgSeen {
				return app.Report{}, cliError("--svg 只能指定一次")
			}
			svgSeen = true
			if a == "--svg" {
				if i+1 >= len(args) {
					return app.Report{}, cliError("--svg 需要本地文件路径")
				}
				i++
				path = args[i]
			} else {
				path = strings.TrimPrefix(a, "--svg=")
			}
			if strings.TrimSpace(path) == "" || strings.HasPrefix(path, "--") {
				return app.Report{}, cliError("--svg 需要本地文件路径")
			}
		case strings.HasPrefix(a, "-"):
			return app.Report{}, cliError("未知 latency 参数 %s\n%s", a, messageText(latencyHelp))
		default:
			if target != "" {
				return app.Report{}, cliError("%s", messageText(latencyHelp))
			}
			target = a
		}
	}
	if strings.TrimSpace(target) == "" {
		return app.Report{}, cliError("%s", messageText(latencyHelp))
	}
	// Reserve before measuring: existing paths (including symlinks/directories)
	// fail atomically, without spending another probe request or truncating data.
	var f *os.File
	if svgSeen {
		var err error
		f, err = os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return app.Report{}, cliError("保存 SVG: %w", err)
		}
		// The pathname can be replaced while Measure runs. Only close our fd:
		// even checking SameFile before Remove would leave an unlink TOCTOU.
		// Keeping our own empty/partial export is safer than deleting a new owner.
		defer f.Close()
		incomplete := func(err error) (app.Report, error) {
			return app.Report{}, cliError("保存 SVG: %w; empty/partial export may remain (no path cleanup attempted)", err)
		}
		rep, err := svc.Latency(ctx, target)
		if err != nil {
			return incomplete(err)
		}
		data, ok := rep.Data.(map[string]any)
		if !ok {
			return incomplete(cliError("latency 响应缺少 SVG"))
		}
		svg, ok := data["svg"].(string)
		if !ok || svg == "" {
			return incomplete(cliError("latency 响应缺少 SVG"))
		}
		if _, err := io.WriteString(f, svg); err != nil {
			return incomplete(err)
		}
		if err := f.Close(); err != nil {
			return incomplete(err)
		}
		return rep, nil
	}
	return svc.Latency(ctx, target)
}

func discover() string {
	c, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer c.Close()
	host, _, err := net.SplitHostPort(c.LocalAddr().String())
	if err != nil {
		return ""
	}
	return host
}

func check(ctx context.Context, svc *app.Service, lang locale) (app.Report, error) {
	me, err := svc.WhoAmI(ctx, discover(), "")
	if err != nil {
		me = app.Report{Verdict: "abstain", Summary: err.Error(), Data: map[string]any{}}
	}
	ai := svc.AIEnv(ctx, true)
	unlock := svc.Unlock(ctx, nil)
	leak := svc.DNSLeak(ctx, 1)
	ret, _ := svc.RouteReturn(ctx, "core", "")
	worst := me.Verdict
	for _, v := range []string{ai.Verdict, unlock.Verdict, leak.Verdict, ret.Verdict} {
		if app.ExitCode(v) > app.ExitCode(worst) {
			worst = v
		}
	}
	sum := fmt.Sprintf(lang.text("一站式：%s。AI %s，解锁 %s，DNS %s"), worst, ai.Verdict, unlock.Verdict, leak.Verdict)
	return app.Report{
		Verdict: worst,
		Summary: sum,
		Data: map[string]any{
			"me": me.Data, "ai": ai.Data, "unlock": unlock.Data, "leak": leak.Data, "route_return": ret.Data,
		},
		Sources:  append(append([]app.Source{}, me.Sources...), ai.Sources...),
		CachedAt: time.Now().UTC(),
	}, nil
}

func routeCmd(ctx context.Context, svc *app.Service, args []string) (app.Report, error) {
	ret := false
	claimed := ""
	var target string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--return":
			ret = true
		case "--claimed":
			if i+1 < len(args) {
				i++
				claimed = args[i]
			}
		default:
			target = args[i]
		}
	}
	if ret || target == "" {
		return svc.RouteReturn(ctx, "core", claimed)
	}
	return svc.RouteForward(ctx, target, nil)
}

func watchCmd(svc *app.Service, args []string, lang locale) (app.Report, error) {
	if len(args) == 0 {
		return app.Report{}, cliError("用法：ipd watch add|ls|rm")
	}
	switch args[0] {
	case "ls":
		return svc.ListWatches()
	case "add":
		if len(args) < 2 {
			return app.Report{}, cliError("用法：ipd watch add <ip> [webhook]")
		}
		hook := ""
		if len(args) > 2 {
			hook = args[2]
		}
		return svc.CreateWatch(args[1], "risk", hook)
	case "rm":
		if len(args) < 2 {
			return app.Report{}, cliError("用法：ipd watch rm <id>")
		}
		if err := svc.DeleteWatch(args[1]); err != nil {
			return app.Report{}, err
		}
		return app.Report{Verdict: "ok", Summary: fmt.Sprintf(lang.text("已删除 %s"), args[1]), Data: map[string]any{"watch_id": args[1]}, Sources: []app.Source{}}, nil
	default:
		return app.Report{}, cliError("用法：ipd watch add|ls|rm")
	}
}

func reportCmd(svc *app.Service, args []string, lang locale) (app.Report, error) {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		return app.Report{}, err
	}
	body := string(raw)
	share := false
	for _, a := range args {
		if a == "--share" {
			share = true
		}
	}
	host, _ := os.Hostname()
	clean := privacy.Redact(body, []string{host})
	if !share {
		return app.Report{Verdict: "ok", Summary: lang.text("本地报告（未上传）"), Data: map[string]any{"body": clean, "shared": false}, Sources: []app.Source{}}, nil
	}
	return svc.Share(clean, []string{host})
}

func remote(ctx context.Context, base, path string) (app.Report, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+path, nil)
	if err != nil {
		return app.Report{}, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return app.Report{}, err
	}
	defer res.Body.Close()
	var rep app.Report
	if err := json.NewDecoder(res.Body).Decode(&rep); err != nil {
		return app.Report{}, err
	}
	return rep, nil
}

func render(format string, rep app.Report) ([]byte, string) {
	return api.Render(format, rep)
}

func looksLikeIP(s string) bool {
	if strings.Count(s, ".") == 3 || strings.Contains(s, ":") {
		return !strings.Contains(s, "/")
	}
	return false
}

func openDB(cfg *config.Config) *store.Store {
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return nil
	}
	db, err := store.Open(cfg.DataDir + "/ipd.db")
	if err != nil {
		return nil
	}
	return db
}

func runMCP(cfg *config.Config) int {
	db := openDB(cfg)
	svc := app.New(cfg, db)
	if err := mcp.ServeStdio(context.Background(), svc); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	return 0
}

func runAgent(cfg *config.Config, lang locale) int {
	base := cfg.ServerURL
	if base == "" {
		fmt.Fprintln(os.Stderr, lang.text("ipd agent 需要 --server 或 IPD_SERVER，指向 hub 的 http 地址"))
		return 2
	}
	ws := strings.TrimRight(base, "/")
	ws = strings.Replace(ws, "https://", "wss://", 1)
	ws = strings.Replace(ws, "http://", "ws://", 1)
	ws += "/agent"
	name, _ := os.Hostname()
	err := probe.RunAgent(context.Background(), ws, cfg.EnrollToken, name, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	return 0
}

func serve(cfg *config.Config, lang locale) int {
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	db, err := store.Open(cfg.DataDir + "/ipd.db")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	svc := app.New(cfg, db)
	hub := probe.NewHub(cfg.EnrollToken)
	srv := api.New(svc)
	srv.Hub = hub
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go aux(ctx, cfg, svc)
	go watchLoop(ctx, svc)
	go dataLoop(ctx, cfg, svc, lang)
	if cfg.Peak {
		go peakLoop(ctx, svc)
	}
	if cfg.Canary {
		go canaryLoop(ctx, svc)
	}
	fmt.Fprintf(os.Stderr, lang.text("ipd %s 监听 http://%s （域名配置为 %s，未绑定公网）\n"), version.Version, cfg.HTTPAddr, cfg.Domain)
	httpSrv := &http.Server{Addr: cfg.HTTPAddr, Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	return 0
}

func aux(ctx context.Context, cfg *config.Config, svc *app.Service) {
	go func() {
		err := listen.DNS{Addr: cfg.DNSAddr, OnQuery: func(name, client string) {}}.Serve(ctx)
		if err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "dns %s: %v\n", cfg.DNSAddr, err)
		}
	}()
	go func() {
		if err := listen.ServeSTUN(ctx, cfg.STUNAddr); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "stun %s: %v\n", cfg.STUNAddr, err)
		}
	}()
	go func() {
		err := listen.ServeTLS(ctx, cfg.TLSAddr, func(h listen.Seen) {
			svc.SaveFingerprint(app.Fingerprint{
				IP: h.IP, JA3: h.JA3, JA3Raw: h.JA3Raw, JA4: h.JA4,
				MSS: h.MSS, TTL: h.TTL, H2: h.H2, At: time.Now().UTC(),
			})
		})
		if err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "tls %s: %v\n", cfg.TLSAddr, err)
		}
	}()
}

func dataCmd(cfg *config.Config, args []string, lang locale) int {
	if len(args) == 0 || args[0] != "update" {
		fmt.Fprintln(os.Stderr, lang.text("用法：ipd data update"))
		return 2
	}
	db := openDB(cfg)
	if db != nil {
		defer db.Close()
	}
	svc := app.New(cfg, db)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	sum, err := ingest.Update(ctx, cfg, svc.Look, func(line string) {
		fmt.Fprintln(os.Stderr, lang.originalProgress(line))
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	failed := 0
	ok := 0
	for _, f := range sum.Feeds {
		switch {
		case f.Err != "":
			failed++
			fmt.Printf(lang.text("%s 失败: %s\n"), f.ID, f.Err)
		case f.Note != "" && f.Rows == 0:
			fmt.Printf("%s %s\n", f.ID, f.Note)
		default:
			ok++
			extra := ""
			if f.Note != "" {
				extra = " (" + f.Note + ")"
			}
			fmt.Printf(lang.text("%s %d 条%s\n"), f.ID, f.Rows, extra)
		}
	}
	fmt.Printf(lang.text("快照目录 %s\n"), sum.Dir)
	if ok == 0 && failed > 0 {
		return 2
	}
	return 0
}

func dataLoop(ctx context.Context, cfg *config.Config, svc *app.Service, lang locale) {
	if err := ingest.Load(svc.Look, cfg); err != nil {
		fmt.Fprintf(os.Stderr, lang.text("读取数据快照: %v\n"), err)
	}
	if cfg == nil || !cfg.DataUpdate {
		return
	}
	run := func() {
		cctx, cancel := context.WithTimeout(ctx, 12*time.Minute)
		defer cancel()
		sum, err := ingest.Update(cctx, cfg, svc.Look, func(line string) {
			fmt.Fprintln(os.Stderr, "data:", lang.originalProgress(line))
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "data update: %v\n", err)
			return
		}
		for _, f := range sum.Feeds {
			if f.Err != "" {
				fmt.Fprintf(os.Stderr, lang.text("data: %s 失败: %s\n"), f.ID, f.Err)
			}
		}
	}
	run()
	every := cfg.DataEvery
	if every <= 0 {
		every = 24 * time.Hour
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

func peakLoop(ctx context.Context, svc *app.Service) {
	every := 15 * time.Minute
	if svc.Cfg != nil && svc.Cfg.PeakEvery > 0 {
		every = svc.Cfg.PeakEvery
	}
	sample := func() {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := svc.PeakOnce(cctx); err != nil {
			fmt.Fprintf(os.Stderr, "peak: %v\n", err)
		}
	}
	sample()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sample()
		}
	}
}

func canaryLoop(ctx context.Context, svc *app.Service) {
	every := 24 * time.Hour
	if svc.Cfg != nil && svc.Cfg.CanaryEvery > 0 {
		every = svc.Cfg.CanaryEvery
	}
	run := func() {
		cctx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		alerts, obs := svc.CanaryOnce(cctx)
		fmt.Fprintf(os.Stderr, "canary: %v\n", obs)
		for _, a := range alerts {
			fmt.Fprintf(os.Stderr, "canary alert: %s\n", a)
		}
	}
	run()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

func watchLoop(ctx context.Context, svc *app.Service) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	post := func(url string, body []byte, sig string) error {
		req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(body)))
		if err != nil {
			return err
		}
		req.Header.Set("X-Ipd-Signature", sig)
		req.Header.Set("content-type", "application/json")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		res.Body.Close()
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = svc.RunDueWatches(ctx, post)
		}
	}
}

const helpText = `ipd — 给 agent 用的地址情报与网络质量

  ipd                      本机出口，第一行是结论
  ipd 1.2.3.4              查询并解释纯净度、住宅、原生
  ipd check                一站式：出口、AI、解锁、泄露、回程
  ipd ai [--cli]           Claude / ChatGPT 等是否安全
  ipd unlock [服务…]       解锁检测
  ipd leak                 DNS 泄露（WebRTC 请用浏览器页）
  ipd route [--return] [--claimed cn2gia] [目标]
  ipd latency <target> [--svg <local-file>]  本地延迟卡片（不覆盖、不上传）
  ipd gfw <ip|主机>        被墙还是仅仅拥塞
  ipd nodes <clash.yaml>   批量节点（订阅只在本机解析）
  ipd batch                从标准输入读 IP
  ipd watch add|ls|rm
  ipd report [--share]     报告；只有 --share 才上传，且先脱敏
  ipd label <ip> <标签>    需 IPD_LABELS_ENABLED=true
  ipd data update          下载免费数据集并刷新本地快照
  ipd serve | mcp | agent | ingest | version

全局：--lang en|zh（默认中文；覆盖 IPD_LANG） --json --md --txt --offline --proxy URL --server URL -4 -6
退出码：0 正常，10 有保留，20 差。域名用 IPD_DOMAIN，监听地址都可配置。
数据更新在 serve 里按 IPD_DATA_UPDATE 跑（默认：未离线时开启）。晚高峰采样 IPD_PEAK，金丝雀 IPD_CANARY，默认都关。
`
