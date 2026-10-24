# 本地延迟卡片

```sh
ipd latency 192.0.2.10 --svg ./latency.svg
ipd latency 192.0.2.10 --svg=./another-card.svg --json
ipd latency 192.0.2.10 --offline --svg ./offline.svg
ipd latency --help
```

`192.0.2.10` 是文档保留地址，仅用于展示命令格式，不是实际探测目标。
选择你有权测量的目标后再运行在线命令。测试全部使用确定性 provider fixtures，
不测量公网。无需保存时可以省略 `--svg`。

## 保存与隐私边界

- `--svg` 只写本地文件，不上传、不创建分享链接、不启动 hosting，
  也不改变 `ShareEnabled`。卡片可由用户自行保存、离线打开或传送。
- 以排他创建方式打开文件，权限为 `0600`；已有文件、目录和符号链接均拒绝，
  不截断、不替换。父目录必须已存在。保存/参数错误退出 `2`。
- 保留正常报告输出：默认文本第一行仍是 `VERDICT:`；`--json` / `--md`
  保持原有格式。保存卡片不会把 `abstain` 或 caveat 变成成功退出码。
- 仅有内嵌 SVG 图形和文本，所有动态文本都按 XML 转义；没有脚本、事件处理器、
  外链、外部字体、图片、样式表或第三方资源。无效 XML 字符替换为 Unicode 替换字符。
- SVG 不嵌入顶层请求错误或逐样本 `sample.Error` 原文，只显示程序生成的受控
  `reason`（例如 provider 错误、探针不健康、测量跳过）。XML 转义防注入，不等于隐私脱敏。
- **JSON、默认文本和 Markdown 报告不是分享安全的脱敏结果。** 为保留诊断兼容性，
  `data.rows[].error` 仍是 provider 原始错误，可能带凭据 URL、内部主机名、本地路径或其他
  敏感内容；不要直接分享整个报告。SVG 不含这些原始错误并不意味着整体 JSON 已脱敏。
- **导出前核对目标与 provider 地理标签。** 目标来自用户输入，会原样作为卡片文本显示；
  来源和 provider 的国家/城市标签也会显示，不会自动匿名化。不要传入含账号、凭据、查询秘密
  的 URL、内部主机名或本地路径作为 target；当前实现不拒绝这些输入，也不承诺过滤其中的秘密。
  若目标或标签不可公开，请勿导出/分享该卡片。不是签名证书，也不证明长期网络质量。

## 证据与状态

卡片含目标、UTC 采集完成时间、来源、样本总数、有效 RTT / 失败 / 未知计数，
以及逐样本状态、RTT、丢包和失败/未知原因。UTC 时间是本进程采集完成时刻，
不是伪造的远端探针测量时间。城市/国家只是 provider 标签，没有地理坐标或地图推断。

- `valid`：健康探针、无错误，ICMP 为 `ok` 或 `loss`，RTT 有限且大于零，
  丢包比例有限且在 `[0,1)`。部分丢包也必须给 caveat。
- `failed`：健康探针明确报告错误、超时、reset、不可达、失败或 100% 丢包；
  不据此认定目标离线，也不把原始默认 `0` 显示为 `0 ms`。
- `unknown`：跳过、不健康/健康状态缺失、缺少或不支持的 ICMP 状态，
  或无效/缺失 RTT、无效丢包数。探针自身异常不能冒充目标网络失败。
- 丢包是独立的观测比例，不是失败/未知样本比。默认零缺少独立的存在标记，
  所以仅在有效 RTT 样本上接受零丢包；其他样本未知丢包显示 `unknown` / JSON `null`。
  健康且未跳过的样本若提供正的合法丢包比例，保留该观测。
- `loss_count` 是具有已知正丢包比例的样本数，不是丢失数据包数。

无有效 RTT（包括空结果、全部失败、禁用/缺少 provider、离线、provider 请求失败）
返回 `abstain`，退出 `10`。部分有效、部分失败/未知、正丢包或批次请求错误返回
`ok_with_caveats`，退出 `10`；全部有效且无上述保留才是 `ok`，退出 `0`。
provider 同时返回样本和错误时保留已有样本，但标记批次 caveat。
传输层与逐样本原始错误均可能含敏感信息；SVG 仅显示请求失败提示或受控样本原因，
不复制任一原始错误。`data.rows[].error` 仍保留逐样本原始证据，仅供诊断，不适合直接分享。

保留 `data.rows` 和 `data.svg`；逐行仍有 `probe/cc/city/asn/rtt_ms/loss`，
无有效 RTT 或未知丢包使用 `null` 而非虚假零。新增逐行 `status/reason/healthy/icmp/error`，
以及顶层 `target/measured_at/source/sample_count/valid_count/failed_count/unknown_count/loss_count/note`。

## 请求预算与验证

仍只调用一次现有 `KindPing` 查询，`Limit: 2, Control: 2`，不追加探针、重试、
地理查询或外部资源请求。`--offline` 完全不调用 provider，保存的是明确 abstain 的卡片。

```sh
go test ./internal/app ./internal/cli -run '^TestLatency' -count=1
go test ./...
node --test web/judge.test.mjs
```

专属回归覆盖成功、空、部分失败、全失败、丢包、缺失/非有限数值、预算、
离线/禁用/provider 错误、恶意目标/城市/国家/来源、含模拟秘密的样本错误不进入 SVG、合法惰性 XML、
CLI 保存内容/权限/退出码、已有文件/目录/符号链接保护和帮助。
