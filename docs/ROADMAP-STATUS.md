# ipd 路线图与当前状态

更新：2026-10-24。开工已 fetch；远端 main 为 `3a0832284585118d473a7fd08fb4c924831f760b`。
本文替代已关闭的 #12：历史验收不等于合并，合并也不等于真实网络或账号可用性认证。

## 已合并

#1–#11、#14 已由其他流程合并到 main；总控没有执行 PR 合并。
包括 P0 修复、测试跨平台、Clash 引用、解锁弃权、线路证据、MCP 契约、AI 未知态与建议、
数据原子替换、延迟 SVG、节点默认弃权、英文 CLI 和 HTTP 契约。
既有边界：默认节点路径没有全协议实测，延迟展示尚需语言层跟进，英文 CLI 不代表全站英文。

## 待合并候选（均以 main 为 base）

| PR | 内容 | 当前状态 |
| --- | --- | --- |
| [#13](https://github.com/raydocs/ipd/pull/13) | Raw trace 探针关联及 socket adapter | 已同步 main `2518c28`，冲突集成检查及 Go/Node/race 通过，已 Ready；未验证 Linux 实际 raw 收发 |
| [#15](https://github.com/raydocs/ipd/pull/15) | 远程订阅验证与固定连接 | 已同步 main `63db1a5`，冲突集成检查、Go/Node/race 与 CI 通过，已 Ready；不是全产品外连安全认证 |
| [#20](https://github.com/raydocs/ipd/pull/20) | 普通 feed last-good 单文件发布 | 两轮独立审查通过；同步 main `1ca8f3d` 无逻辑变更，Go/Node/race 通过，已 Ready；streamRows/断电/多 writer 不在保证内 |
| [#16](https://github.com/raydocs/ipd/pull/16)、[#18](https://github.com/raydocs/ipd/pull/18) | DNS 会话与编码路径日志隐私修复 | Draft；#16 必须包含 #18 修复才闭合已知缺口；真实 NS 委派/浏览器链路未验证 |
| [#17](https://github.com/raydocs/ipd/pull/17)、[#19](https://github.com/raydocs/ipd/pull/19) | HTTP/SOCKS5 出口测量与 YAML 原树校验 | Draft；#17 必须包含 #19 修复；真实代理与全协议尚未验证 |

#18/#19 已独立审查批准；第七轮含上述全部候选的临时组合通过 Go/Node 全套、11 个包 race、
构建与 Linux route 交叉编译。但旧组合不替代最新 main 同步后的复测，不能把未同步候选称为 Ready。

## 第八轮进行中

1. **可插拔外部核心 runner**：一套接口支持 mihomo/sing-box，不链接 GPL 核心。
   YAML/JSON 按格式及实际协议能力选择，允许强制指定，结果显示 backend；未知/不能可靠转换
   的配置明确 unsupported，不能运行失败后偷偷直连。仅本地子进程 mock，不连接真实机场。
   [Draft #23](https://github.com/raydocs/ipd/pull/23) `ebd6b24` 已提交，组合 Go/Node/nodes race 通过，但首轮独立审查 block：端点归属验证、全局信任/路径策略保真两项 P1，以及清理失败报告 P2 已提交修正 `937836f`；修正版组合测试通过，但第二轮仍 block：最终归属扫描期间子进程退出后，整批失效端点仍可能发布（P1）。该 P1 的批次同步门控修正 `8331260` 经额外聚焦独立审查 approve，旧版两端反例实败、新版普通/慢清理/race 与 100 轮状态压力通过；总控候选组合 Go/Node/nodes race 通过。仅验收 runner 增量，保持 Draft，真实核心与 Linux runtime 未验证。当前仅原生格式的 runner；跨格式配置转换明确 unsupported，自动协议转换及出口、纯净度和解锁接线仍待后续改进。
2. **latency 语言层跟进**：将 #9 帮助、英文输出与自有错误接入 #11 的 `cliError`/`messageText`，
   保留原始来源错误、SVG 权限/拒绝覆盖与只关闭原 fd 的安全边界。[Draft #22](https://github.com/raydocs/ipd/pull/22) `a25cced` 已提交，独立审查 approve，总控单分支及 main＋#13/#15/#20/#22 组合 Go/Node/相关 race 均通过，已验收；保持 Draft，未合并。

## 后续已批准优先级

按用户顺序推进：全协议节点检测；浏览器本地 AI 信号与可审计只读终端脚本；
可选多源与分歧；中国探针健康/历史权重；场景评分及挑战证据；UI/默认关闭分享；
历史/网段提醒与配置保留期；公开/合成分类评测。
无 key 优雅跳过，不注册账号、不写 key，不声称获得真实 Cloudflare Bot Score。

最终差距清单须逐项核对 IPLark、ip.cx、IPPure、ip.net.coffee、ping0、ipure.dev、ipjudge
公开资料；当前不是已经完成的竞品调查。缺少真实服务证据时保留未知，不用 mock 替代准确率证明。

## 流程约束

所有新 PR 指向开工 fetch 的 main，每项 Draft、独立审查与组合测试后验收。
#13/#15/#20 仅按用户授权同步 main 并转 Ready，不由总控合并。
不推 main、不 force-push、不 SSH/部署、绑定域名或改设置，不提交真实 IP、密码、邮箱或密钥。
每次状态更新注明证据；已关闭 #12 不再更新。

### main 基线跟进验收

#22 `a25cced` 已完成语言层跟进；独立审查覆盖英文/中文帮助、自有错误与错误链、
退出码、O_EXCL/0600/无路径删除及离线弃权。总控在 main `3a08322` 上叠加
#13 `2518c28`、#15 `63db1a5`、#20 `1ca8f3d` 与 #22，Go 全套、Node、七包 race 通过。
此次新组合不含尚未同步的 #16–#19，不能当作这些 Draft 的最新集成证据。

### 显式双核心出口观测候选

[Draft #25](https://github.com/raydocs/ipd/pull/25) `e0c7ae2` 依赖 #23，但 base 仍为 main。
新增 CLI 显式 `nodes --measure`、本地原生 YAML/JSON、backend 与核心绝对路径参数，
每节点独立认证代理/TLS 出口请求；结果只给原始序号/backend/受控观测状态，不导出配置凭据。
默认 Nodes/MCP/HTTP 不启动核心，离线不发包；即使出口观测完整也保持 abstain，不冒充安全结论。
总控组合 Go/Node/app/CLI/nodes race 通过，但首轮独立审查 block：JSON 标签经 YAML 解码导致节点身份错配、出口地址过滤不足两项 P2 已追加修正 `676aabf`，第二轮独立审查 approve，两项 P2 关闭；修正版组合 Go/Node/app/CLI/nodes race 通过，验收 `676aabf`，保持 Draft、未合并；真实 core、纯净度/解锁及跨格式转换仍未完成。
误含父汇总历史的初始 #24 已关闭，由 #25 替代，不计作成果或验收对象。

### 逐节点解锁候选：测试阻断

[Draft #26](https://github.com/raydocs/ipd/pull/26) `ba4dafc` 依赖 #23/#25，base main。
显式 `--unlock`、同节点 Getter、请求预算及受控输出已实现，但最终窄 race 与 Go 全套
均在两个 backend 的 `lose-owner` 回归失败：子进程活着却关闭 listener 后仍可能发布旧 positive。
未验收，也未将删测试或放宽检查作为解决办法。正在只读裁决 runner 持续归属验证的最小 API，
再独立修复并复测；网页、purity、转换及真实核心仍未完成。
