# 场景证据第一增量（scenario-evidence-v1）

Risk JSON 新增 `data.scenario_assessments`；CLI JSON、HTTP Risk 与 MCP
`ip_risk_explain` 共享同一字段。已有 purity/residential/native、顶层 verdict、
summary、退出码均不改变；**旧 purity 的高分不代表任何场景可用**。
Unlock CLI/MCP stdio 也输出该数组，仅使用此次已经执行的检查，不增加请求。
AIEnv 的既有诊断 schema 不变，不将它的 safe 或布尔比较当作场景评分。

## 模型与范围

固定顺序：ai、social、streaming、ecommerce、email。前三者仅评估下列公开端点：

| 场景 | 必需检查（全部覆盖才能给分） |
| --- | --- |
| ai | claude, chatgpt, gemini, grok, copilot, meta_ai, perplexity |
| social | tiktok, reddit |
| streaming | netflix, prime |
| ecommerce | 未采集 checkout 证据，始终 abstain |
| email | 未采集投递证据，始终 abstain |

这是刻意有限的端点覆盖模型，不是整个行业、用户画像或业务适配评分。
Reddit 当前没有正向识别规则，故社交可能长期弃权；不放宽规则补分。
Risk 只查询目标 IP 情报，没有该 IP 的这些端点观测，所以五项全部
`score:null, abstained:true, coverage:0, confidence:0`。不把服务器本身的 Unlock
观测混入被查询 IP。DNSBL 的现有输出仅有 hits，错误被跳过，既无逐区完整性也无
可复用观测时间；空 hits 不证明未列黑，更不证明可发信。这个增量不消费 DNSBL 评分。

## 输入、时间与合成

内部输入 `ScenarioObservation` 保留 `source`、原始 `unlock.Result`、nullable
`observed_at`；输入只来自受信进程内采集器，不接受外部自报信誉。
来源必须是 unlock，服务 ID 必须匹配必需检查，证据措辞必须精确匹配既有检查器的
明确 marker/地域拒绝/双端点组合。未知状态、无 block marker、空响应等不得投票。
未采集的 litmus、Cloudflare Bot Score 等不生成正常值，也不在模型中假设存在。

Unlock 在本批已有检查开始时记录观测时间（保守批次下界），不是用报告时间刷新
旧观测。`assessed_at` 为评估时钟；时间未知、零、在未来、超过 24 小时均不能投票。
24 小时是版本化的保守工程窗口，不是经实验验证的服务稳定性保证。

每项权重为 1：端点地位相等，避免猜测商业重要性。明确正向 marker 计 100，
明确地域拒绝计 0，已识别的部分表面访问计 50；完整覆盖后取算术平均、四舍五入。
例：Netflix originals_only=50、Prime 明确正向=100，streaming=75；
Netflix 明确拒绝=0、Prime 正向=100，streaming=50。缺一个输入则不计算平均，
而是 null。50 是描述部分端点覆盖的 heuristic，不是“半数用户成功”。

`coverage` 为有效必需检查数/必需检查总数；`confidence` 同值，仅表示证据完整性，
不表示统计置信区间、经验准确率、预测禁封概率。所有同一检查的观测都保留；
相反票、未知与有效票混合均导致该检查 unknown，不能通过选最新/多数票掩盖矛盾。
跨场景输入忽略，不使用 purity/住宅类型推导场景分。合成测试仅验证规则，不宣传准确率。

## 检查优先级与消费方式

`checks` 包含 id、weight、status、reason、priority、observations。
优先级仅为人工检查顺序：明确拒绝 10，部分访问 20，缺测/矛盾/过期等 30，
已识别正向 40；同优先级按 id 字典序，原始观测按规范 JSON 顺序保留。
未知项的 reason 指向补采/核对时间与来源，而不是修复已确诊故障。

分数仅表示这批公开端点的有限证据；不声称账号 safe、实际登录/付款/发信/播放成功，
不代表 IP 信誉或未来可用性。即使端点得 100 也没有账号安全结论。
消费者必须检查 `abstained` 并显式处理 `score === null`，不能默认 null 为 0 或 100。
OpenAPI 的 ScenarioAssessment 描述可空分数及边界；旧 Risk 数据仍兼容。
MCP data 保留同样 null，不新增输入选项、网络采集、第三方 key 或迁移。

## 验证

```sh
go test ./internal/score ./internal/app ./internal/api ./internal/mcp
go test -race ./internal/score ./internal/app ./internal/api ./internal/mcp
go test -p 1 ./...
node --test web/judge.test.mjs
```

覆盖缺测、矛盾、过期、未知/未来时间、完整合成、场景隔离、稳定排序和 JSON/MCP null。
Risk 缺测回归测试在原始 main 实际运行失败，再恢复实现运行通过。
