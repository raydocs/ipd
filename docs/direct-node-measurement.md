# CLI 显式测量本地 Clash HTTP / SOCKS5 出口

## 成功标准与使用

默认 `ipd nodes local.yaml` 仍调用原来的 `Service.Nodes`，没有 checker 就 `abstain`。
本功能是独立的 **CLI opt-in**，不改变 MCP、HTTP、订阅读取器、改名、AI、解锁或路由路径。

```sh
ipd nodes --measure local.yaml --json
ipd nodes --measure 'proxies: [{name: local, type: http, server: 127.0.0.1, port: 7890}]' --json
ipd nodes --measure local.yaml --offline --json
```

只接受本地常规文件或内联 Clash YAML（最多 2 MiB）；拒绝远程 URL、URI/base64 订阅。
不启动/下载 mihomo，不下载订阅，不修改文件，不写改名配置，不上传报告。
`--measure` 可放在 source 前后，只能出现一次；source 必须恰好一个。
离线优先：`--offline` / `IPD_OFFLINE` 下只解析，节点为 `skipped/offline`，不发任何请求。
`--proxy`、`IPD_PROXY`、`--server` 及环境代理不参与本路径的传输选择。

## 网络与认证边界

仅支持 Clash `type: http` 和 `type: socks5`，从各自的 `server`、`port`、
可选字符串 `username` / `password` 创建独立 transport、连接及代理认证。
HTTP 使用 CONNECT，SOCKS5 使用 TCP CONNECT（支持用户名/密码认证）；不是 UDP 探测。
`http` 的 `tls: true` 使用验证证书的 HTTPS 代理；SOCKS5 TLS 包装不支持。
`skip-cert-verify: true` 被拒绝，不提供 TLS 绕过。
没有环境代理读取、连接共享、重定向跟随或失败后的直连回退；认证只发送给代理。
HTTP Basic 和 SOCKS5 密码认证在未加密的代理连接上不是秘密传输，请只使用可信的代理通道。

固定 HTTPS 端点为 `https://api64.ipify.org?format=json`，预期响应形如
`{"ip":"192.0.2.10"}`；格式依据 [ipify 官方 Universal IPv4/IPv6 API 文档](https://www.ipify.org/)。
用户不能指定端点 URL 或信任根；TLS 验证保持开启。测试包内部才能注入 loopback HTTPS endpoint/roots。
本次仅查阅官方文档，没有向生产出口端点、真实代理或真实服务发送测量请求。
启用实测后，代理会收到目的地址，ipify 会看到代理出口；代理主机名可能由本地 DNS 解析。
端点 IP 查询不证明所有应用流量的出口、IPv4/IPv6 双栈能力或代理质量。

固定上限：32 节点，4 个 worker，单节点 8 秒，整批 45 秒（并服从调用者更早的 context 截止）。
超上限在发请求前整批拒绝，不悄悄截断；取消停止调度并等待 worker 退出，连接随请求取消关闭。
响应头最多 8 KiB，响应体最多 1 KiB；非 200、重定向、HTML、空 JSON、无效 IP 等均是未知。
校验 IP 字面量，拒绝 zone、私有、回环、链路本地、未指定和组播地址（IPv4-mapped 先归一化）；记录规范化 IP，不记录响应原文。

## 输出是观测，不是节点好坏

`scope: proxy_exit_ip_only`；节点用 **从 1 开始的输入位置 index** 对应配置，
不回显 name/server/Extra/凭据。重复名字仍是不同位置的独立观测。
仅输出 index、status、可选出口 IP、尝试开始时间、受控 error；从不输出原始网络/解析错误。
不生成 reachable/dead、纯净度、住宅、AI、TikTok、改名结果或 `renamed_yaml`。
`Sources` 的 ipify 仅表示尝试过固定端点；未知时不代表已获得有效观测。

| 节点 status | 含义 |
| --- | --- |
| `measured` | 经该节点通道得到有效 IP |
| `unknown` | 无观测；error 为 request_failed / timeout / canceled / endpoint_status / invalid_response / invalid_config |
| `unsupported` | ss/vmess 等协议或不支持的传输配置，没有假装测过 |
| `skipped` | offline，未发请求 |

全部观测成功：`ok/completed`。部分成功：`ok_with_caveats/partial`，保留已测 IP，
未测项仍未知。无成功观测：`abstain/unavailable`；永不因端点失败而声称全部 `blocked`。
`measured_count` 只统计有效 IP，时间仅在尝试请求时出现；未调度节点没有伪造测量时间。

## 确定性验证与旧行为反证

新增 CLI 回归 `TestNodesMeasureExplicitOffline` 在基线 9035290 的真实运行失败：
旧 dispatch 把 `--measure` 当 source，返回 `could not read node subscription`；不是编译失败反证。
本实现后该回归通过。
所有新增网络测试仅使用 loopback HTTP CONNECT、RFC1928/1929 最小 SOCKS5、HTTPS fixture。
同一 endpoint 经两个独立认证节点返回两个文档出口 IP，验证节点隔离、重复名、凭据不导出、
认证失败不直连、环境隔离、TLS 根校验、超时/取消释放连接、响应未知、离线、远程源拒绝、
32 节点边界和 4 并发上限。未进行真实代理/公网测量或评分。

## 与 PR9 / PR11 的逐段组合说明（未带入其提交）

1. `internal/cli/cli.go` 的 `dispatch`：本分支只把 `case "nodes"` 换为 `nodesCmd`；
   PR9 的 `case "latency"` 与 Main 的 latency help 分支应同时保留；无业务互相调用。
   PR11 修改 nodes 原用法错误的 `cliError` 行时，保留本分支整个 nodes 分发；
   后续本地化需把 `nodesCmd` 新用法/重复参数错误纳入其词典，不回退旧的 args[0] 逻辑。
2. `discover` 前 helper 插入点：保留 PR9 的 `latencyHelp/latencyCmd` 和本分支 `nodesCmd`，
   两段无共享状态，可按任意顺序排列，不能用一侧覆盖另一侧。
3. `helpText`：保留 PR9 latency 行和本分支 nodes --measure 行；
   PR11 的 `opts.lang.text(helpText)` 与 renderLocalized 保留，需补对应英文帮助词条。
4. `parseGlobals`：本分支不修改签名/实现。PR11 将返回值改成三项，组合时本分支
   `nodes_test.go` 最后一段调用必须接收/断言第三项 err；其他 nodes/dispatch 测试无需改签名。
5. 本分支不改 PR11 的 Main/render、locale、配置环境读取，也不添加翻译开关；
   新增测量摘要/受控代码仍是原始证据，组合翻译不得把 unknown 变成 blocked 或增加分数。
6. app/direct_nodes 独立于原 nodes/renamer，不能把 PR3/PR10 的 Nodes 输出或配置导出接进本路径。

父线程必须独立审查本 diff，并在 PR9/PR11 等候选组合上运行测试后再验收；本 Draft 不等于整合通过。
