# Draft：独立多源并列比较

验收边界：新增 `GET /v1/ip/{public-ip}/compare` 和页面最小入口；不接入 purity、
不更改 Risk/CLI/MCP 合并与 unknown 语义、不记录查询历史。页面使用 textContent 构造朴素并列表格并保留 JSON 文本，
`data.rows` 七行并列，`data.differences` 只包含明确的 country/ASN/proxy/vpn/tor 分歧，
不做投票、权重、综合风险分或安全结论。相同数字不代表相同风险。

## 已实现与明确缺口

- IPQS、AbuseIPDB：复用 `providers.All` HTTP 适配器；仅比较层使用固定官方 endpoint，
  不使用 legacy URL overrides，避免把凭据转交任意地址。白名单输出类型校验后的值，绝不输出 raw、
  请求 URL、上游消息或网络错误。5 秒 deadline、禁止所有重定向、1 MiB body 上限，
  非 2xx/null/错误 schema/字段类型异常为 error；429 不重试、不隐瞒为安全。
- Scamalytics：保留行与许可说明；本 Draft **未实现比较归一化**。
  有 key/live 时 `schema_adapter_pending`，不会调用 legacy adapter。
  Scamalytics 当前官方 v3 要用户名与分配的 API 节点，现配置不足；不猜账户信息。
- proxycheck：独立增量只接当前v3嵌套/布尔契约，不隐式兼容v2。见 [适配边界](proxycheck-comparison.md)。
- ipapi.is：后续独立增量接入 keyed 的有类型观察，详见 [适配器边界](ipapiis-comparison.md)。
- IPinfo Lite：复用 lookup 的逐源 hit 与 metadata，保留 version、更新时间、attribution、license。
  `fixture-*` 明确是仓库合成证据，不是线上数据库；无 hit 为 unknown，不拿 merged 值补足。
- GeoLite：本地 prefix hit 如存在则复用；未装文件为 unknown / `local_dataset_not_loaded`。
  当前 MMDB 只填合并视图，无独立源观察接口，已装文件但无逐源 hit 仍 unknown /
  `source_specific_mmdb_adapter_pending`，不把打开文件时间或其他源 country 当 GeoLite 证据。
  本 Draft 不下载/安装/授权数据库，不声称已完成七源接入。

## 调用与隐私

只有 query **精确** `live=1` 且非 offline、配置 key 才访问两项已支持服务。
默认 / `live=0` / `live=true` 均零调用；`IPD_OFFLINE=true` 永远覆盖 opt-in。
缺 key 即 `missing_key`（即便厂商支持匿名访问也不调用）。错误/跳过/缺字段都是 unknown，
不是 false。timestamp 在线是尝试时间，snapshot 是原 metadata 时间；未知为 null。
confidence 是来源性质，不是概率。scope 明示国家/ASN 与风险画像不同范围。

已有可选 env 名：`IPD_IPQS_KEY`、`IPD_ABUSEIPDB_KEY`、`IPD_SCAMALYTICS_KEY`、
`IPD_IPAPIIS_KEY`、`IPD_PROXYCHECK_KEY`、`IPD_IPINFO_TOKEN`、`IPD_MAXMIND_CITY`。
不需要买 key 或注册即可运行离线对比。默认页面 Risk 查询也显式 `live=0`；新比较入口的
未预选复选框说明第三方 IP 共享，不自动将本机地址提交比较。只接受公网字面量，拒绝域名/私网。
旧 Risk API 默认 live 行为和 raw 输出仍是既有契约，**不属于本比较 API 的保密保证**。
共享 HTTP helper 的安全加固同时作用于旧适配器（重定向拒绝、固定错误、超限拒绝）；
既有接口字段不变。生产许可适用范围、配额和账户权益须由使用者确认，本实现不替用户决定。

## 官方资料核对（2026-11-08，仅文档访问，无服务查询）

- [Scamalytics v3](https://docs.scamalytics.com/ip-fraud-risk-api/v3/)：URL 用户名、query key/IP，
  nested scamalytics score；免费账户 5,000 credits/月，测试模式也有额度限制。本实现不使用在线测试模式。
- [IPQS 请求格式](https://www.ipqualityscore.com/documentation/about-ipqs-apis/submitting-data-to-ipqs-apis)、
  [当前 IP 文档](https://www.ipqualityscore.com/documentation/proxy-detection-api/overview)：key 在 path，
  success/fraud_score、country_code、ASN 与布尔 proxy/vpn/tor。
  [官方介绍](https://www.ipqualityscore.com/about-us/)提及免费账户至多 1,000 lookups/月，实际权限以账户为准。
- [ipapi.is](https://ipapi.is/developers.html)、[匿名边界](https://ipapi.is/free-tier.html)：q/key 参数，
  is_proxy/is_vpn 等布尔与 location/asn 对象；匿名层配额与响应较少，不能当 keyed schema。
- [proxycheck](https://proxycheck.io/api/)：key query；v3 detection 嵌套布尔与 v2 yes/no 不同，
  匿名 100/日、免费注册 1,000/日，不因此自动使用匿名查询。
- [AbuseIPDB v2](https://docs.abuseipdb.com/)：GET check，Key header、ipAddress query；
  data.abuseConfidenceScore 为举报相关置信，countryCode 为国家；Standard check 1,000/日。
  默认查询窗口由厂商决定，不当实时“未发生滥用”证据。
- [GeoLite](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/)、
  [EULA](https://www.maxmind.com/en/geolite/eula)：免费数据不等于无限再分发，需遵守更新与许可约束。
- [IPinfo Lite 数据库](https://ipinfo.io/developers/ipinfo-lite-database)、
  [Lite API](https://ipinfo.io/developers/lite-api)：下载 CC BY-SA 4.0，country/ASN 范围；
  不能把 Lite 的地理/ASN 信息当代理阴性检测；本实现只复用本地 snapshot，不调 Lite API。

## 测试证据与交接

合成 httptest fixtures 只对两项实现的在线 schema 做正向、坏类型/null、异构 schema、
429/5xx、malformed、超限、timeout、redirect 拒绝；测试 transport 将官方请求重定向到本地
fixture，禁止真实服务访问。五项在线源验证无 opt-in / offline / 无 key 零调用。
分歧测试验证同分不同语义，不把缺源字段计入冲突。Node 使用无浏览器 DOM stub 检查
默认关闭、明确 opt-in 和 textContent 安全输出。其余Scamalytics完整 fixtures 与 GeoLite MMDB 逐源
接口为后续单元，不能用当前通过的测试声称它们完成。

旧代码回归实际执行：仅新增 `TestHTTPRejectsUnsafeResponses` 时，原 HTTP 接受 JSON null，
测试 FAIL（`unsafe response accepted`）；加固后 PASS。父线程需独立 review 与组合验收后
才考虑合并；本实现不委派、不 merge、不部署、不修改父 ROADMAP/PROGRESS。

本分支实际执行通过：`go test -race ./internal/providers ./internal/app ./internal/api -run 'TestCompar|TestHTTPReject' -count=1`、
`go test -p 1 ./...`、`node --test web/*.test.mjs`（2/2）、`git diff --check`。
没有真实服务调用、账号注册或 GUI/真实浏览器视觉验收；独立审查与父组合验收尚待执行。
