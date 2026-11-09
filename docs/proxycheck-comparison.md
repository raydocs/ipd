# proxycheck v3 比较适配器

独立增量，base最新main3a08322；依赖未合并已验收#32/#33（父91156cf）。
只补比较层，不改变legacy Risk的v2适配或评分/默认调用。

## 契约

- 可选环境变量IPD_PROXYCHECK_KEY；key/live/offline三重门控，缺key不匿名请求。
- 固定HTTPS proxycheck.io/v3单地址请求，复用已配置代理、超时、禁止重定向、大小限制；不支持自定provider URL。
- 顶层status仅ok/warning可含观察，warning保留受控provider_warning，不回显message。
  单地址返回必须唯一匹配查询IP，等价IPv6/mapped允许，zone/额外地址/重复等价地址拒绝。
- 只接受v3 detections对象。proxy/vpn/tor仅布尔；location.isocode和network.asn严格类型检查。
  缺失/null不填false。无可比观察为unknown，坏schema/error/denied为error；不猜v2 yes/no。
- 可选risk 0..100整数保留原意：检测基线与攻击历史，不是账号安全概率；
  不与其他源分数平均。source timestamp仍为本次尝试时间，不冒充last_updated。
- 不输出原始响应、operator/hostname、key、上游消息或网络错误，零注册、零真实key。

## 官方资料与验证边界

2026-11-08仅查阅[官方API文档](https://proxycheck.io/api/)及
[官方OpenAPI](https://proxycheck.io/resources/proxycheck-openapi.yaml)，未调用API。
当前v3以IP键组织结果，nested detections使用布尔；network ASN是AS前缀字符串，
location使用isocode。v2格式不同，不能互相猜测。风险分与检测置信含义不同。
不保证账号额度、真实服务schema稳定性、名单准确率或许可授权；没有key时不发匿名请求。

本地fixtures走生产CompareOnline/HTTP路径，覆盖正向、warning、身份/类型/unknown、
v2拒绝、凭据编码、quota/HTTP/redirect失败及来源分歧。
父91156cf新增回归实际FAIL（schema_adapter_pending，零调用）；修后窄测试/race通过。
日志 /tmp/ipd-batch-root-checks/proxycheck-*.log。全套、独立审查和组合验收另行记录。
真实provider/浏览器/线上未验证；分享功能不因本适配改变。
