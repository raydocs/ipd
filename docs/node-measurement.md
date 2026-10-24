# Clash 节点测量的能力边界

## 默认行为：仅解析，不是实测

目前 `Service.Nodes`（以及调用它的 CLI/MCP）**不具备开箱即用的节点实测能力**。
它能读取并解析 Clash YAML、代理 URI 或 base64 订阅，但不会启动 mihomo、分配监听端口，
也没有默认的节点出口/AI 解锁探测实现。仅安装 mihomo、提供订阅或设置环境变量都不能补齐这些能力；
本功能没有一个可启用真实测量的环境变量。

未注入测量实现时返回：

```json
{
  "verdict": "abstain",
  "data": {
    "count": 2,
    "measured_count": 0,
    "measurement_status": "unavailable",
    "measurement_reason": "not_configured"
  }
}
```

`count` 是解析得到的节点数，**不是成功探测数**。该响应不包含 `nodes`、`renamed_yaml`、
节点可达性、出口 IP 或 AI 成绩，不会给未测量节点添加 ❌ / unreachable，也不会回显原始订阅配置。
`Sources: local` 只表示本地解析/处理，不代表已经获得网络观测。

## 开发者注入契约

保留 `nodes.Checker` 接口与三个注入位置，优先级为：

1. `Service.Nodes` 的非 nil `checker` 参数；
2. `Service.SetNodeChecker` 设置的 checker；
3. 包级变量 `app.DefaultNodeCheck`（默认实现只报告能力缺失，设置为 nil 也会弃权）。

此路径不接入 runner，传给 checker 的 `socks` 是空字符串。
自定义 checker 必须自行按节点名定位实际可用的节点通道、执行真实探测，并确保结果来自对应节点；
**不能把空地址解释成应直接探测本机出口，也不能把缺少通道解释成节点已死**。
需要通道但没有通道时，应返回 `app.ErrNodeMeasurementUnavailable`（可使用 `%w` 包装）。
默认 checker 可直接调用，但同样返回该错误，不生成测量结果。

完整批次中，每个 checker 成功且返回非空出口 IP，才记录为 reachable，并使用其提供的成绩；
普通探测失败错误仍表示完成了一次负面探测。完整批次的 `measurement_status` 为 `completed`：
全部成功为 `ok`，部分失败为 `ok_with_caveats`，全部失败为 `blocked`。
注入者须区分探测失败与初始化/配置失败，后者应使用能力缺失错误，而不是任意普通错误。

以下情况都不是 dead 节点证据：

| measurement_reason | 含义 |
| --- | --- |
| `not_configured` | 没有真实 checker |
| `checker_unavailable` | checker 返回能力缺失错误 |
| `canceled` | 上下文或 checker 报告取消 |
| `timeout` | 上下文截止或 checker 返回超时错误（含 `Timeout() bool`） |
| `no_observation` | checker 无错误但也没有出口观测 |

只要批次中有上述不确定结果，就保守地对**整个批次**返回 `abstain` / `unavailable`，
不导出任何节点成绩或改名 YAML，即使另一些节点已测完。`measured_count` 只统计有结论的 checker 返回，
不表示这些结果已被导出；混合失败时 reason 为稳定选取的一个原因，不是逐节点诊断。
调用前已取消则不执行 checker；运行中取消后的批次也不发布测量结论。

## 输出与使用建议

订阅读取、解析及改名导出失败仅返回通用错误，不向错误或摘要附加 URL、查询 token、
密码、节点名或 checker 原始错误。未测量/不完整批次不回传原始配置。
完整测量批次仍保留现有 `renamed_yaml` 导出兼容性，**其中可能包含原有订阅凭据**；
不要将完整报告上传到公开日志、工单或聊天。该导出不是凭据脱敏功能。

当前建议是：把默认命令仅用作解析确认；实际节点可用性请在可信的本地 Clash/mihomo 客户端中验证。
若要程序化测量，需要开发并审计真正的节点通道与 checker 集成，不能依赖未知的环境变量。
本变更没有实现 mihomo 启动、端口开放、下载或远程订阅抓取安全重构；
通用错误脱敏不等于订阅 URL 已经过完整 SSRF/重定向安全验证。
