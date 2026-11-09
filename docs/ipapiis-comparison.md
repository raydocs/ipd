# ipapi.is 比较适配器（依赖候选 #32）

本增量仅补齐比较层的 ipapi.is 行。base 为 main；代码依赖未合并 #32，
PR 包含该依赖历史，独立变更以 #32 的 93a6288 为起点。不改变 legacy Risk、purity、CLI 或默认调用。

## 请求与输出

- 复用已有可选环境变量 IPD_IPAPIIS_KEY；无 key 不请求。仍须显式 live=1，offline 覆盖它。
- 仅固定 HTTPS 官方 endpoint；复用比较层配置代理、安全客户端及超时/大小/重定向边界。
- 返回 IP 必须解析后与目标一致；拒绝 zone，等价 IPv6 与 mapped 地址规范化比较。
- country、ASN、proxy/vpn/tor 只输出有类型依据的标量；缺失/null 不变成 false。
  空观察为 unknown；畸形、错误、匿名契约为 error。非布尔 is_vpn 保守拒绝，不猜测 truthiness。
- 不输出 company、联系人、原始响应、上游错误消息或 key。忽略网络 abuser_score，
  不把它变成逐 IP 风险分；score 保持缺省。不同源事实才参与原有分歧展示。

## 官方契约及限制

2026-11-08 查阅 [官方文档](https://ipapi.is/developers.html)：
keyed 请求与匿名响应不同；API 接受 q/key，位置和 ASN 为嵌套对象，检测字段在顶层。
官方指出 VPN 检测可能返回非布尔 truthy 值；本增量仅接受已支持的布尔形态，
遇其他形态报未知错误而不是误报无 VPN。代理阴性不等于没有住宅代理。
未调用真实接口，不保证账号权限、额度、实时 schema 或检测准确率；不注册账号、不配置真实 key。

## 本地验证

合成 transport fixtures 经过生产 CompareOnline/HTTP/归一化路径，验证固定请求、key 编码、
零调用门控、类型/缺失/null、错误/限额/重定向/大小/取消、IPv6 身份与分歧。
新增回归在 93a6288 上实际失败（schema_adapter_pending，零次调用），修复后通过。
日志 /tmp/ipd-pr32-fix-20261108/ipapiis-{before,after}.log。
真实 API、浏览器、线上均未验证；独立审查与最终组合验收另行记录。
