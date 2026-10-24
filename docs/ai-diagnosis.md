# AIEnv：未知态、证据与修复顺序

`ipd ai --json`（可加 `--cli`）诊断的是**运行该命令的进程**，不是浏览器、账户状态或 IP 信誉。通过服务端调用时，观测属于服务端出口。服务可访问不等于账户正常；账户封禁也不能反推 IP 有问题。本实现不修改 Unlock、GoogleRegion 或路由探测。

## JSON 兼容性

`data.schema_version` 为 `ai-diagnosis-v1`。原有字段保留，但下列布尔值现在是 **`true | false | null`**：

- `per_service[].available`：`null` 是未知，绝不是“不可用”。
- `egress_consistency`、`ipv6_bypass`、`dns_leak`、`timezone_mismatch`：缺测或不支持比较时是 `null`。

消费者必须显式比较 `=== false` / `=== true`，不要用 `!value`、`Boolean(value)` 或默认值把 `null` 合并成失败/通过。Go 消费者应使用 `*bool` 等可空类型，不能继续把这些字段解码为普通 `bool`。

每个预期服务都保留一行，顺序固定。`status`、`evidence`、`method`、`region` 是原始检查器证据；没有检查器/结果时补一行 `status: "abstain"` 并解释缺失原因。新增字段：

- `availability`：`available | limited | unavailable | unknown`。
- `known`：是否有可判定的 availability。
- `assessment_reason`：解释派生判定，不覆盖原始证据。

`web_only`、`app_only`、`partial` 对应 `limited`，`available: true` 只表示部分表面可访问，不表示完整服务可用。`error`、字符串 `"abstain"`、空状态或未来未知状态都对应 `unknown / null`。不依赖 PR4 的 `unlock.Abstain` 常量，故本 PR 可单独编译，也能与 PR4 组合。

单纯 `yes` 不足以证明正向可用性：当前接受检查器的明确 positive-marker、Gemini positive-page 或 `web=yes app=yes` 证据。基线检查器的 `no block marker`、仅未跳转、仅 `web and app open` 均不足以证明可用性，保留原始 `yes`，但派生为未知。新增证据措辞需审核后扩展，默认保守未知。

`observations` 为每个比较提供 `{value, status, reason}`；`status` 是 `observed | unknown`，`reason` 说明比较范围和局限。顶层四个 nullable 布尔字段与其 `value` 相同。`--cli` 时另有 `cli_proxy_configured`，只表示环境变量是否设置，**不表示浏览器与 CLI 路径相同**。

## Verdict

优先顺序是：

1. `blocked`：至少一个服务有明确地域拒绝证据；不代表所有服务被封，不代表账户或 IP 被封禁。
2. `risky`：存在已观测的不一致、部分访问、一般拒绝或 CLI 配置检查项。
3. `abstain`：没有上述问题，但仍有未知服务或必需比较未知。
4. `safe`：七个服务都有足够正向证据，五个 trace 目标完整且同地址族内一致，IPv4/IPv6 国家比较、DNS 国家比较、支持的时区比较均已观测且未发现差异；请求 CLI 检查时变量也已配置。

已知问题不被其他未知项抹掉；未知项也不会因某服务拒绝就变成确定的泄漏结论。`safe` 仅表示这些有限探测通过，不承诺可登录、持续可用或账户解封。默认没有 DNS/双栈输入时不能输出 `safe`，这是有意的保守行为。

## 比较边界

- `traces` 保留五个固定目标的每次观测（包括缺失客户端、超时、HTTP 错误、无效地址、目标重定向），各有 `status/evidence`。错误响应中的 `ip=` 不参与一致性计算。
- 同地址族出现不同出口地址即记录不一致，但可能是出口轮转，应重复测量后确认代理规则。IPv4 和 IPv6 天然地址不同，不能仅因字符串不同就判定多出口。
- 未发现矛盾但 trace 不全时，一致性未知。五个目标完整时，一致性只表示**同地址族地址一致**，不证明相同路由，也不涵盖所有服务、浏览器或 CLI。
- `ipv6_bypass` 是 IPv4/IPv6 出口国家差异信号，不是已证实的代理绕过。未观测到 IPv6 不等于已禁用 IPv6。
- `dns_leak` 是解析器国家相对 IPv4 出口国家的差异信号，不是已证实的泄漏。无解析器、未知出口国家或仅有不完整且无差异的解析器样本时保持未知。
- `timezone_mismatch` 使用报告时钟进行粗略国家/UTC 偏移比较。只支持 CN/HK/SG、JP、US、GB、DE；未知国家或未覆盖国家保持未知，不能套用默认“无问题”。

## 稳定修复清单

按 `priority` 升序，同优先级按 `issue` 字典序；同一 `issue` 去重，结果与服务结果追加顺序无关。每项保留 `severity/issue/how`，新增整数 `priority`。未知项也会给出**采集/重试建议**，不伪装成已确诊故障。

| priority | 检查项 |
| --- | --- |
| 10 | 同族出口不一致 |
| 11 | IPv6 国家差异或 IPv6 观测缺失 |
| 12 | 出口/代理路径 trace 覆盖缺失 |
| 20 | 服务明确地域拒绝，按服务名稳定排序 |
| 30 / 31 / 32 | DNS / 时区 / CLI 环境 |
| 40 | 一般访问拒绝或部分访问，先区分账户、认证、限流等 |
| 50 | 服务证据缺失，检查超时/连接并重试 |

可执行的检查示例（请在**实际使用的进程和代理环境**运行）：

```sh
ipd ai --json
ipd ai --cli --json
curl -4 --max-time 8 https://claude.ai/cdn-cgi/trace
curl -6 --max-time 8 https://claude.ai/cdn-cgi/trace
ipd leak --json
date +%z
```

对 `traces[].url` 的其他目标重复 trace 请求，检查 HTTP 状态及 `ip=`。使用 HTTP/SOCKS 代理时，curl 的 `-4/-6` 可能只控制连接代理的地址族，并不强制代理的目标出口地址族；以实际 `ip=` 为准，必要时分开配置代理路径验证。不要把一次失败当作 IPv6 已禁用。

`ipd leak` 也需要解析器观测源；默认未注入 `Service.DNS` 时仍为未知，重跑命令不会凭空产生 DNS 样本。`IPD_EGRESS_IPV4` / `IPD_EGRESS_IPV6` 输入必须来自实际出口观测，配置值自身不证明代理生效。

先确认出口和代理路径，再核实明确地域拒绝，最后检查 DNS、时区与 CLI。没有测量时不应盲目换 IP；即使确认路径问题，修复建议也不能承诺解除账户封禁。
