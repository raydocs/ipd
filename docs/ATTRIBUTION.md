# 数据署名

每个 API 响应的 `attribution` 和 `sources` 来自下面这些公开来源。付费源在没有密钥时保持关闭，不出现在结果里。

| 源 | 许可 | 署名 |
|---|---|---|
| IPinfo Lite | CC BY-SA 4.0 | IP address data powered by IPinfo |
| DB-IP Lite | CC BY 4.0 | IP Geolocation by DB-IP |
| IP2Location LITE | IP2Location LITE | This product includes IP2Location LITE data available from https://lite.ip2location.com |
| ip2region | Apache-2.0 | ip2region |
| 云厂商公开网段 | 各厂商公布的范围 | AWS、GCP、Azure、Cloudflare 等官方 IP 范围 |
| PeeringDB | PeeringDB AUP | AS 类型来自 PeeringDB |
| RIR delegated | 各 RIR 统计 | ARIN、RIPE、APNIC、LACNIC、AFRINIC |
| Geofeed | RFC 8805 | 运营商 geofeed |
| BGP | bgp.tools / RIPE RIS / RouteViews | 公开 BGP 表的派生数据 |
| Tor 出口 | Tor Project | Tor exit list |
| VPN 公开列表 | 各列表自身许可 | 公开 VPN 前缀 |
| FireHOL / Spamhaus DROP / abuse.ch | 各自条款 | 只作恶意标记 |
| APNIC Labs eyeball | APNIC Labs | AS 用户规模估计 |
| MaxMind GeoLite2 | GeoLite2 EULA，不随仓库分发 | This product includes GeoLite2 data created by MaxMind |
| DNSBL | 各列表条款 | 见 `data/dnsbl.yaml` |
| Scamalytics、IPQS、AbuseIPDB、ipapi.is、proxycheck、IPinfo、GreyNoise、ipdata、ipregistry、IP2Location.io | 各自 API 条款 | 仅在配置了密钥时请求 |

仓库里的快照是可再分发信号的样本，用来离线查询和测试。`ipd data update` 会把 DB-IP Lite、RIR delegated-extended、云厂商网段、Tor 出口、FireHOL、ipsum、Spamhaus DROP、X4BNet，以及 bgp.tools 或 iptoasn 的前缀表下载到数据目录，不写进 git。GeoLite2 和 IPinfo Lite 只在配置了免费令牌时下载，GeoLite2 不随仓库分发。`ipd ingest` 只写清单。

Region Restriction Check 是 MIT，本仓库按公开的 HTTP 行为重写了解锁判断，没有复制它的代码。IPQuality、融合怪（ECS）和 NextTrace 是 AGPL/GPL，没有链接，也没有复制。mihomo 如果出现，只作为外部进程调用，不编进二进制。JA4 只实现了 BSD 风格说明里的基础指纹，没有 JA4+。
