# ipd

Agent-first IP intelligence and network-quality checks. The same verdict is available over curl, the CLI, and MCP. The first line is the verdict. When confidence is low, the result says it cannot decide, instead of guessing.

给 agent 用的地址情报和网络质量检查。同一份结论可以用 curl、命令行和 MCP 拿到。结论在第一行。置信度不够时写「无法判定」，不猜。

The default listen address is `127.0.0.1`. The public name is the config value `IPD_DOMAIN`. Share links and user-submitted labels are off unless you turn them on.

默认只听 `127.0.0.1`。域名是配置项 `IPD_DOMAIN`。分享链接和用户标签默认关闭。

License: [MIT](LICENSE). Dataset terms and third-party credits are in [docs/ATTRIBUTION.md](docs/ATTRIBUTION.md).

## English

Requires Go 1.26.

```sh
go test ./...
go build -o bin/ipd ./cmd/ipd
IPD_HTTP_ADDR=127.0.0.1:8787 IPD_OFFLINE=true ./bin/ipd serve
```

`IPD_OFFLINE=true` uses the built-in sample snapshot and does not call online providers or DNSBL. `ipd data update` still downloads public datasets that need no key. GeoLite2 needs `IPD_MAXMIND_KEY`. IPinfo Lite needs `IPD_IPINFO_TOKEN`. Paid adapters stay disabled when their key is empty.

### curl

```sh
curl -sS http://127.0.0.1:8787/
curl -sS -H 'Accept: application/json' http://127.0.0.1:8787/v1/ip/1.1.1.1
curl -sS http://127.0.0.1:8787/v1/ip/8.8.8.8.md
curl -sS http://127.0.0.1:8787/v1/ip/9.9.9.9.txt
curl -sS 'http://127.0.0.1:8787/v1/ip/1.1.1.1?format=json'
curl -sS http://127.0.0.1:8787/llms.txt
curl -sS http://127.0.0.1:8787/openapi.json
```

The first line of text output matches `VERDICT:`. Use `Accept`, `?format=json|txt|md`, or a `.json` / `.txt` / `.md` suffix.

### CLI

```sh
./bin/ipd 1.1.1.1
./bin/ipd --json 24.1.2.3
./bin/ipd ai --offline
./bin/ipd gfw 1.1.1.1 --offline
./bin/ipd nodes ./some-clash.yaml
./bin/ipd mcp
./bin/ipd ingest
./bin/ipd data update
```

Exit codes: `0` ok, `10` caveat, `20` bad. Egress checks (AI, unlock, return path, leaks) must run on the egress machine. The server never fetches a URL you supply. `ipd data update` downloads DB-IP, RIR delegated stats, cloud ranges, Tor exits, FireHOL, ipsum, Spamhaus DROP, X4BNet, and a prefix-to-ASN table.

The `npx` wrapper in `npm/ipd-cli` only forwards to a local `ipd` binary.

### MCP

Streamable HTTP: `http://127.0.0.1:8787/mcp`. Tools that must run on the egress return `requires_egress_run` plus the matching CLI command.

stdio, which can run egress checks locally:

```sh
./bin/ipd mcp
```

Tools: `whoami`, `ip_lookup`, `ip_risk_explain`, `ip_batch`, `asn_lookup`, `prefix_neighbors`, `ip_history`, `gfw_check`, `google_region_check`, `route_forward`, `route_return`, `latency_map`, `port_check`, `unlock_check`, `ai_env_check`, `dns_leak_test`, `node_batch_check`, `job_get`, `sources_status`, `watch_create`, `watch_list`, `watch_delete`. Resources: `ipd://methodology`, `ipd://sources`. Prompts: `diagnose_ai_ban`, `vet_vps_before_buy`.

## 中文

需要 Go 1.26。

```sh
go test ./...
go build -o bin/ipd ./cmd/ipd
IPD_HTTP_ADDR=127.0.0.1:8787 IPD_OFFLINE=true ./bin/ipd serve
```

`IPD_OFFLINE=true` 使用内置样本快照，不访问在线情报源和 DNSBL。`ipd data update` 仍会下载免密钥的公开数据集。GeoLite2 要 `IPD_MAXMIND_KEY`，IPinfo Lite 要 `IPD_IPINFO_TOKEN`。没有密钥的付费适配器保持关闭。

### curl

```sh
curl -sS http://127.0.0.1:8787/
curl -sS -H 'Accept: application/json' http://127.0.0.1:8787/v1/ip/1.1.1.1
curl -sS http://127.0.0.1:8787/v1/ip/8.8.8.8.md
curl -sS http://127.0.0.1:8787/v1/ip/9.9.9.9.txt
curl -sS 'http://127.0.0.1:8787/v1/ip/1.1.1.1?format=json'
curl -sS http://127.0.0.1:8787/llms.txt
curl -sS http://127.0.0.1:8787/openapi.json
```

文本第一行匹配 `VERDICT:`。也可以用 `Accept`、`?format=json|txt|md`，或后缀 `.json`、`.txt`、`.md`。

### 命令行

```sh
./bin/ipd 1.1.1.1
./bin/ipd --json 24.1.2.3
./bin/ipd ai --offline
./bin/ipd gfw 1.1.1.1 --offline
./bin/ipd nodes ./some-clash.yaml
./bin/ipd mcp
./bin/ipd ingest
./bin/ipd data update
```

退出码：`0` 正常，`10` 有保留，`20` 差。出口侧检查（AI、解锁、回程、泄露）要在出口那台机器上跑。服务器不会去抓你给的 URL。`ipd data update` 下载 DB-IP、RIR、云网段、Tor、FireHOL、ipsum、Spamhaus、X4BNet 和前缀到 ASN。

`npx` 包装在 `npm/ipd-cli`，它只转发到本机的 `ipd` 二进制。

### MCP

HTTP：`http://127.0.0.1:8787/mcp`（Streamable HTTP）。必须在出口执行的工具返回 `requires_egress_run`，并带上对应的 CLI。

stdio：

```sh
./bin/ipd mcp
```

工具包括 `whoami`、`ip_lookup`、`ip_risk_explain`、`ip_batch`、`asn_lookup`、`prefix_neighbors`、`ip_history`、`gfw_check`、`google_region_check`、`route_forward`、`route_return`、`latency_map`、`port_check`、`unlock_check`、`ai_env_check`、`dns_leak_test`、`node_batch_check`、`job_get`、`sources_status`、`watch_create`、`watch_list`、`watch_delete`。资源 `ipd://methodology`、`ipd://sources`。提示 `diagnose_ai_ban`、`vet_vps_before_buy`。

## Browser / 浏览器

Open `http://127.0.0.1:8787/`. WebRTC leak detection runs in the page. The upload is only the leak boolean and the candidate count.

打开 `http://127.0.0.1:8787/`。WebRTC 是否泄露在页面里判断，上传的只有是否泄露和候选条数。

## Configuration / 配置

| Variable | Default | Meaning |
|---|---|---|
| `IPD_DOMAIN` | `localhost` | Name written into llms.txt |
| `IPD_HTTP_ADDR` | `127.0.0.1:8787` | HTTP |
| `IPD_DNS_ADDR` | `127.0.0.1:5353` | DNS listener for leak tests |
| `IPD_STUN_ADDR` | `127.0.0.1:34780` | STUN |
| `IPD_TLS_ADDR` | `127.0.0.1:8443` | TLS handshake for JA3/JA4 and H2; SYN/MSS when privileged |
| `IPD_DATA_DIR` | `var/lib/ipd` | SQLite and downloaded snapshots |
| `IPD_SHARE_ENABLED` | `false` | Share links |
| `IPD_LABELS_ENABLED` | `false` | `ipd label` |
| `IPD_OFFLINE` | `false` | Local snapshot only; no online providers or DNSBL |
| `IPD_DATA_UPDATE` | `true` when not offline | Scheduled `ipd data update` inside `serve` |
| `IPD_DATA_UPDATE_INTERVAL` | `24h` | Refresh interval |
| `IPD_DBIP_CITY` | `false` | DB-IP city lite instead of country lite |
| `IPD_MAXMIND_KEY` | empty | Download GeoLite2-City when set |
| `IPD_IPINFO_TOKEN` | empty | Download IPinfo Lite and use it online when set |
| `IPD_PEAK` | `false` | Peak-hour sampler |
| `IPD_PEAK_INTERVAL` | `15m` | Sample interval |
| `IPD_PEAK_TARGET` | `1.1.1.1:443` | Local TCP target |
| `IPD_CANARY` | `false` | Daily unlock canary |
| `IPD_CANARY_INTERVAL` | `24h` | Canary interval |
| `IPD_CANARY_PROBE` | empty | Alert only for this id in `canary.yaml` |
| `IPD_VANTAGE` | `globalping` | China vantage. `ripeatlas` / `boce` need a key |
| `IPD_RIPE_KEY` / `IPD_BOCE_KEY` | empty | Empty disables that vantage |
| `IPD_POW` | `false` | Proof of work before heavy probes |
| `IPD_*_KEY` | empty | Empty disables that online source |

Paid adapters are compiled in and do not call out without a key.

## Tests / 测试

```sh
go test ./...
node --test web/judge.test.mjs
```

Local lookup p95/p99 limits live in `TestLookupLatency` (20ms / 50ms). A ten-minute, 200 rps sample:

```sh
IPD_LONG_BENCH=1 go test ./internal/lookup/ -run TestLookupLatencyLong
```

GitHub Actions runs `go test ./...` and `node --test web/judge.test.mjs`.

Deploy notes, systemd, Docker, a Caddy snippet, and the probe installer are in `DEPLOY.md`. Those files are not applied to any server by this repository.
