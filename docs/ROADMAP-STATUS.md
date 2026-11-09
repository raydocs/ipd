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
未验收，也未将删测试或放宽检查作为解决办法。只读裁决已完成：独立新增 runner 单次运行句柄，主动内核归属检查＋有界后台监视＋统一撤销信号；
先独立审查该增量，验收后再接入 app 并复测；网页、purity、转换及真实核心仍未完成。

### 持续归属检查的保证边界

runner 改进保持旧接口兼容，旧 handle 不可跨 run 复用；已观察到 owner 丢失/歧义/查询失败
立即整批撤销，不等待慢清理。app 后续须在拨号前后、请求/响应及结果采纳时主动校验，
并由撤销信号取消在途请求。用户态跨节点扫描不是同一瞬间的原子归属证明，也不能绝对认证
采样间快速重绑、检查与拨号之间接管或已建连接的接收者；不得用随机端口/密码回复代替服务端身份认证。

### runner 持续归属候选

[Draft #27](https://github.com/raydocs/ipd/pull/27) `f698099`，base main、依赖 #23。
新增单次 run 的 Check/CheckAll/Done/Err、不透明身份绑定、有界后台监视及单向整批撤销；
正常 Stop 与失败原因区分。原 lose-owner 旧版真实反证失败，子任务本地 race/Go/Node 通过。
独立审查 approve；总控 nodes race 通过，组合 Go 首跑遇到未修改的 PoW 随机负例失败，保留日志后一次复测通过，Node 通过，验收 runner API 增量。独立实测 24 节点约 48 次查询/1.5s，100ms ticker 不是整批延迟保证。没有修改 #26/app/CLI，也没有宣称
Linux runtime 或真实核心通过。用户态非原子及拨号窗口等边界仍适用。

#27 验收后，#26 开始接入 run handle：拨号/请求/响应/采纳主动检查、Done 取消在途连接、
发布前 CheckAll、失败清空整批结果。接线仍在进行，#26 尚未验收；不会以 API 存在替代应用回归通过。

### #26 持续归属接线返修

最新 `9dee41e` 已接入 #27 handle，新增每请求/拨号检查、Done 取消与主动关闭在途连接、
最终 CheckAll，区分正常 Stop。原 lose-owner 失败保留；子任务在未接线中间版再次反证失败，
修复后窄 race 通过。磁盘不足导致普通全量首次失败，去调试符号 `-ldflags=-w` 后全量通过，
不是删测试或 skip。当前开始完整 app/CLI 独立审查及总控候选组合，尚未验收；此前阻断
作为历史证据保留，不代表最新提交已经获批。真实核心/Linux runtime 与绝对接收者认证均未验证。

#26 总控本轮验证受到环境阻塞：定向测试在编译阶段报磁盘不足（可用约 146MiB），
未完成新的完整组合测试。独立审查首任务返回 Provider turn failed，无结论，已做一次有界
重试；若检查无法运行须明确标记未覆盖，不能以子任务旧日志替代总控最新组合验收。

### 当前验证阻塞（最新）

#26 有界重试的独立静态审查完成，未发现可确认 P1/P2；但独立 app/CLI 窄测的 fixture/CLI
链接同样报 `no space left on device`，review 结论 **block**，不能完整验收。
日志 `/tmp/ipd-pr26-review-bounded-retry.log`；总控编译失败另有保留记录。
需要先释放磁盘空间，再恢复窄测试、race、PR22 组合与 main 全候选组合；不反复重编译，
不删除共享缓存/其他线程文件，不拿作者历史通过日志替代本轮独立运行证据。
后续依赖测量链路的功能暂不继续堆叠；已有代码和失败测试保持在 Draft，未合并或部署。

## 2026-11-06 恢复验收

已 fetch：main 仍为 `3a08322`；所有开放 PR base 均为 main。GitHub 报告 #17/#19
CONFLICTING，其余 #13/#15/#16/#18/#20–#23/#25–#27 MERGEABLE；正式 reviewDecision 为空，
不把委派审查等同 GitHub review approval。#17/#19 冲突及旧节点方案兼容仍待处理。

#26 最新 `b81228e` 已验收：独立完整审查发现重复 Content-Encoding 误判 P2，补丁拒绝多字段
和不支持链；实际旧版反证失败，新版 73 组 fixture × 双 backend 的聚焦独立 race 通过。
本分支 Go/Node/app/CLI/nodes race 通过；基于 main 的 #13/#15/#20/#22/#23/#25/#26/#27
组合 Go/Node/七包 race 全通过。#22 帮助上下文冲突精确保留 locale 与节点帮助后复测。
证据位于 `/tmp/ipd-resume-20261106/`，独立审查 `/private/tmp/ipd-pr26-r2.AwxEd9/REVIEW.txt`。
先前磁盘阻塞是历史记录，现已解除；真实核心、Linux runtime、真实机场和线上服务仍未验证。
保持全部 PR 未合并；后续优先浏览器本地 AI 体检，终端只读脚本另开增量。

## #28 浏览器本地体检验收（2026-11-06）

Draft #28 `157bdcb` 已验收，未合并。两轮独立审查确认原三项 P2（字段类型、深层导入状态、
IP 规范化）闭环；R2 新发现 status/availability 矛盾后，总控限定修正并实际执行旧版失败、
新版状态对应矩阵通过，不启动第三轮一般审查。非法/矛盾证据保持 unknown，失败导入不提交状态。
最终组合：main `3a08322`＋#13/#15/#20/#22/#23/#25/#26/#27/#28；Node、Go 全套及
web/API/app/CLI/nodes/lookup/ingest/route/probe 九包 race 全通过。
证据 `/tmp/ipd-pr28-fix-20261106/`，独立审查 `/tmp/ipd-pr28-r2.3FlKJn/REVIEW.md`。
这仅代表代码与本地 Node/VM、Go 验证通过；未验证真实浏览器布局、辅助技术或线上服务。
没有新增上传/持久化，服务观察不能冒充浏览器路径或账号实际所见；缺测不报告 safe。
下一独立增量为 `/cc` 终端只读脚本，不塞进 #28。

## #29 只读终端脚本验收（2026-11-06）

Draft #29 `89d1e59` 已验收，未合并。可信 `IPD_CC_ORIGIN` 绑定生成 /cc 脚本，
仅同 origin /cc/ip 只读请求，peer 观察不冒充反代后真实用户或其他服务所见出口。
独立 R1 的 SSLKEYLOGFILE 写密钥、HTTP_PROXY 被忽略导致直连两项 P2 已修，旧版实际反证失败；
R2 无 P1/P2，25 项独立检查通过。总控补强 P3 断言，要求 exit=3、零请求、unknown、无凭据，
窄 race 通过。caller 环境不变，脚本内部清理密钥日志变量；uppercase HTTP_PROXY 返回 unknown。
分支和含 #28/节点候选的组合 Go/Node/API-config-web race 通过；最终追加仅测试断言。
证据 `/tmp/ipd-resume-20261106/pr29-*`。本地真实 sh/curl/TLS fixtures 不等于线上部署验证。
不安装、不写配置、不上传本机信号；HTTP 请求仍向服务器暴露 transport peer，不承诺外部日志为空。

## #30 场景证据评分验收（2026-11-06）

Draft #30 `6a1f3e0` 已验收，未合并。五场景版本化输出，不改既有 purity/residential。
缺测/未知时间/过期/冲突时 score=null、abstain，电商/邮件仍未采集。等权端点覆盖不是商业重要性、
账号安全或封号概率。独立 R1 发现子端点相反事实折叠为 limited 漏冲突，限定修正后 R2 approve；
96 矩阵、10 个 mock Getter 实际 Unlock 路径通过，旧生产反例实际失败。
总控分支与最新候选组合 Go/Node/score-app-API-MCP race 均通过。
证据 `/tmp/ipd-resume-20261106/pr30-*`、`/tmp/ipd-pr30-r2.T95HkB/`。
仅代码和本地合成测试通过，真实账号/服务可用性、预测准确率和线上效果未验证。

## #31 最新状态：组合阻塞，未验收（2026-11-07）

已 fetch，main 仍为 `3a08322`。确认 #31 远端原头 `ecef48c`；完整 R2 反例复跑发现
一项已记录的保守漏检（异域 base 加绝对 Google 表单），总控限定修正至 `55ba82b`。
完整 R2 HTML/HTTP/输出/资源反例 race 通过，四项 P2 边界闭环；分支 Go/Node/litmus-CLI race 通过。
CF Bot Score 仍为 null/unknown，真实公网挑战页未验证，未合并。

最终候选组合首跑在未修改的 sing-box cancel-live 就绪超时失败；一次有界复测 Go 全套及
Node 通过，但 nodes race 再次就绪超时（cancel-live/stop-live/fixture-late-exit）。
不放宽断言或超时，不继续空转；#31 整体验收仍阻塞，尚未启动多源比较 Draft。
日志 `/tmp/ipd-pr31-fix-20261106/resume-combo-go.log`、`resume-combo-go-retry.log`、
`resume-combo-node.log`、`resume-combo-race.log`；反例通过 `resume-r2-fixed.log`。
下一步须先在已有 #23/#27 runner 范围定位此生命周期就绪问题，独立复核后再恢复组合验收。

## #31 有界诊断完成并验收（2026-11-08）

验收 Draft #31 `55ba82b`，不合并。四项 P2 和完整 R2 反例、分支 Go/Node/race 通过；
之前最终组合 Go/Node 已通过，nodes race 的历史就绪超时另作有界诊断：
main（nodes 树无改）、#23 `8331260`、#25 `676aabf`、#26 `b81228e`、#27 `f698099`
串行各一次完整 nodes race 均通过；组合 nodes 全文件哈希与 #27 相同，组合 nodes race 再验通过。
没有放宽350ms测试预算或削弱断言。测试使用helper而非真实sing-box；本机负载约7。
此前各PR CI成功，但Ubuntu工作流不含race，不能证明Darwin race稳定。
结论限于：未复现历史失败、无#31 runner改动，证据支持无关的负载敏感抖动；唯一根因未证实。
日志 `/tmp/ipd-runner-diagnostic-20261108/`，原失败继续保留，不宣称修好了runner缺陷。
真实公网挑战页/账号/核心未验证，CF Bot Score保持null/unknown。下一独立Draft：可选key多源对比。

## #32 可选多源比较：限定实现与验证（2026-11-08）

Draft [#32](https://github.com/raydocs/ipd/pull/32)，head `93a6288`，base最新main `3a08322`。
七源并列合同不等于七源适配完成：IPQS、AbuseIPDB可显式live调用，IPinfo Lite复用本地快照；
Scamalytics、ipapi.is、proxycheck在线schema及GeoLite独立MMDB观察仍pending/unknown。
无key、offline、未opt-in不请求，不混合不同来源分数，不宣称未知等于安全。

两轮独立审查：原代理绕过、跨代来源配对、WebRTC出口污染、IPv6身份及mapped保留地址已闭环。
R2新增备用Transport清理与zone校验由总控限定修复；真实旧码反证连接残留6条，新码0条，
zone在Unmap前拒绝。隔离TLS子进程回归、全Go/全部Node及providers/app/api/lookup race通过。
最终候选组合仍复测中；尚未整体验收。日志 `/tmp/ipd-pr32-fix-20261108/r2-*.log`。
代码及本地测试不代表真实provider schema/额度/许可、真实key或公网验证；本阶段未调用真实服务。
