# 方法

英文短文在 MCP 资源 `ipd://methodology` 和 `GET /v1/methodology`。这里是同一套规则的中文说明。

纯净度从 100 分起算。扣分写在 `models/purity.yaml`，每一项都回到证据。没有付费改分。

住宅类型先走硬规则，再走 `models/residential.json` 里的树。产品路径是 `ClassifyObserved`：只有证据站得住才给类别，否则类别是 `cannot determine`（无法判定）。

算作证据的有四类，外加公开枚举：

- rDNS 形态：`dsl`、`dhcp`、`dyn`、`pool`、`ppp`、`hsd`、`ftth` 这类动态池主机名
- 前缀年龄：BGP 或 RIR 记录里的天数。不足 180 天记为年轻前缀
- 邻居信号：同一前缀上托管、代理、Tor 的占比，以及邻居里的端口类标记
- RIR 机构类型：`netname` / `descr` 里的 BROADBAND、DYNAMIC、MOBILE、HOSTING、ENTERPRISE

云厂商公开网段和 Tor 出口列表各算一条公开枚举，一条就够把地址定为 `hosting`。住宅类至少要两类对得上：例如动态 rDNS 再加 RIR 的宽带描述。只有「移动 ASN」或「国家码」时返回 `cannot determine`。置信度低于 0.70 同样弃权。树本身在概率低于 0.55 时仍是 `abstain`，产品路径把它说成 `cannot determine`。

留出的标注集在 `internal/score/testdata/residential_heldout.json`。标签来自可公开复核的来源（Cloudflare 公开 DNS 与其未收入 `ips-v4` 的任播段、Google Public DNS、Tor 出口列表、RIR 描述、动态 rDNS），不拿合成训练集当成绩。`TestResidentialHeldOut` 打印精度和弃权率。注册在接入商、却由托管商宣告，或前缀很新且没有 rDNS，标成 `isp_static`，并带 `suspected_fake_residential`。缺了这些对照时不猜伪家宽。

原生表示 RIR 国家、地理位置、宣告国家和 geofeed 一致，而且 RTT 没有把它放到别处。对不上是广播。材料不够是 abstain。

地理、国家和 ASN 按源加权合并。权重在 `internal/lookup/merge.go`。对不上的字段写进响应的 `conflicts`。`1.1.1.0/24` 和 `1.0.0.0/24` 是 Cloudflare 的 DNS 任播，公开的 `https://www.cloudflare.com/ips-v4` 代理列表不含它们；即使云网段feed没有这一行，也会标 `anycast`。

被墙：同一运营商至少两枚健康探针一致，并且至少两个运营商一致，才输出 `ip_blocked` 或 `port_blocked`。单次失败是 `insufficient_sample`。探针自身连不上（不是目标超时）会记入健康表，连续三次失败后不再参与表决。Globalping 匿名额度 250 次/小时、登录 500 次/小时，单次测量最多 50 个探针；超出额度同样返回 `insufficient_sample`，不再发请求。送中：Google 把这个出口送到 `google.cn` 或 `google.com.hk`。这是两件不同的事。

每次响应都带 `snapshot_age_seconds`，表示前缀快照（DB-IP 与 prefix-to-ASN，取更旧的一份）建成到现在的秒数。快照是可 mmap 的 `IPDS` 文件，写入用临时文件加重命名，查找不经过 40 万行上限。

WebRTC 候选地址在浏览器里比较。服务端只收 `leak` 和 `candidate_count`。

解锁检测采用三态证据：`yes` 只表示预期端点出现可识别的正向页面或结构化字段，`no` 只表示明确的地域拒绝；这不是登录后实际播放或模型调用的保证。未配置正向识别规则的服务即使返回 HTTP 200，也不会因「没有封锁标记」判定为可用。普通 HTTP 错误、改版、空响应、验证码/挑战页、非预期主机或路径跳转、读取中断及超限响应均为 `abstain`。403/451 也必须有地域拒绝证据才是 `no`，网络安全拦截、泛化的 unavailable 或 VPN 提示不等于地域拒绝。

ChatGPT 的网页与 App 端点必须分别识别；任一未知或失败，整体弃权，不能据另一侧推断 `app_only` / `web_only`。Netflix 的两个片目同理；TikTok 的 gzip 回退不能掩盖首请求失败。Claude / ChatGPT 的地域 trace 无法识别时也弃权。解锁汇总中只要有未知就返回 `abstain`，保留每项结果，不将错误计为封锁。

Google 地域检查要求 Google、YouTube 和 Play 三项响应均成功且可识别；普通页面内的 google.com.hk 链接不是送中跳转。只有精确匹配的 Google 本地主机跳转或已识别的 CN 地域证据才能报告送中；非中国地域证据冲突时弃权。无法判定时公开字段为 `sent_to_china: null`，而不是 `false`，且不补猜 google.com。这里不对被墙状态作判断。
