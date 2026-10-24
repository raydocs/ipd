# 路由证据与弃权

- `RouteForward` / `direction=forward`：中国探针 → 指定目标；只调用 vantage provider。`sources[].raw` 保留 provider 原始测量（含健康、错误、RTT、hops）。海外 control 不参与中国路径判断。
- `RouteReturn` / `direction=return`：本进程 → 中国目标；只调用本地 tracer。`ClassifyPath` 不猜方向，标为 `unspecified`。一个方向不能证明另一个方向。
- `paths` 保留每条探针的 hop IP、ASN、RTT、rDNS 和错误；部分错误不丢弃已拿到的 hops。provider 整批错误写入 `data.error`。请求了但没有返回测量的运营商保留为未知路径。
- 空路径、全失败、全未知、混合/歧义分类为 `abstain`；部分路径有效、部分失败/缺失/未知为 `ok_with_caveats`。超时 `*` 或无效 hop 地址不能作为有效路由证据。命令失败或未到目的地址、原生 tracer 达到 hop 上限仍未到达，不被包装成成功。
- ASN / IP 模式仅说明观察到的骨干，不证明商业线路等级或全程质量。AS4809 / `59.43.0.0/16` 仅记 `cn2`，不能因“没看到 163”推成 GIA；同时看到 CN2/163 记 `mixed`，不推成 GT。重复相同证据也不能升级。没有 ASN 的模糊移动前缀不推成 CMIN2。
- rDNS 只保留供复核，不单独定线路。provider ASN 与本地库不一致时保留原 ASN，并以 `lookup_asn` 暴露冲突；前缀模式与 ASN 冲突则分类未知。
- 只有整批路径证据有效、声明为可比较的已知骨干类别时才核验声明，且只比较声明对应运营商；无运营商标签的手工路径按调用者给定的单路径比较。未知声明、GIA/GT 产品等级声明、证据不足都明确 `unverified`，绝不因 `claim_mismatch=false` 写成“声明相符”。确定不符返回 `risky`，只是已观察骨干不符，不代表欺诈认定。
- `ok` 只表示本批已观察骨干可分类、没有已知测量错误；不保证不可见的 hop、未来路由、SLA 或对向线路。回归测试注入 provider/tracer，不依赖公网路由稳定性。
