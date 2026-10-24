# 方法

英文短文在 MCP 资源 `ipd://methodology` 和 `GET /v1/methodology`。这里是同一套规则的中文说明。

纯净度从 100 分起算。扣分写在 `models/purity.yaml`，每一项都回到证据。没有付费改分。

住宅类型先走硬规则，再走 `models/residential.json` 里的树。胜出概率低于 0.55 时类别是 `abstain`，界面上写「无法判定」。注册在接入商、却由托管商宣告，或和机房放在一起，或没有 rDNS，标成 `isp_static`，并带 `suspected_fake_residential`。

原生表示 RIR 国家、地理位置、宣告国家和 geofeed 一致，而且 RTT 没有把它放到别处。对不上是广播。材料不够是 abstain。

被墙：中国探针到不了，海外对照到得了。送中：Google 把这个出口送到 `google.cn` 或 `google.com.hk`。这是两件不同的事。

WebRTC 候选地址在浏览器里比较。服务端只收 `leak` 和 `candidate_count`。
