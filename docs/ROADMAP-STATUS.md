# ipd 改进与验收状态

更新：2026-10-24。基线为 [PR #1](https://github.com/raydocs/ipd/pull/1) 的
`cursor/p0-review-fixes-dd49`，起点提交 `19a0b16962a8d249179ce376db3847ba594c3fb4`。
本文记录代码审查与确定性测试，不是生产服务或真实账号可用性认证。

## 执行边界

- 每项改进由 T3 委派子任务在独立 worktree/分支实现，PR 均指向上述基线分支。
- 总控检查 diff、独立运行测试，发现缺口则退回原作者追加提交；没有合并任何 PR。
- 未向 main 推送，未 force-push，未 SSH、部署、绑定域名或修改仓库设置。
- 不需要真实服务器、账号或秘密作为测试输入；使用确定性夹具，不提交此类凭据。
- 各 PR 是同一基线上的并列改进，不是已合并的产品版本；后续采用时须复测组合。

## 改进清单

“通过”表示总控验收通过，不表示已合并。表中短 SHA 标识验收对象。

| 轮次 | 优先级 | 改进 / PR | 状态与边界 |
| --- | --- | --- | --- |
| 1 | P1 | [#2 跨平台测试](https://github.com/raydocs/ipd/pull/2) | 通过 `0511d997`；macOS 不再要求 Linux procfs/TCP_INFO，Linux 原断言保留 |
| 1 | P1 | [#3 Clash 重命名引用](https://github.com/raydocs/ipd/pull/3) | 通过 `7183dae`；组、直接规则、子规则及适用拨号引用一致；碰撞后结果名称与 YAML 一致 |
| 1 | P1 | [#4 解锁证据与弃权](https://github.com/raydocs/ipd/pull/4) | 通过 `3f2b012`；改版、挑战页、空响应和部分请求失败弃权，不保证实际登录/播放 |
| 1 | P1 | [#5 去程/回程证据](https://github.com/raydocs/ipd/pull/5) | 主修复通过 `2eda873`，首轮保留的 ICMP 关联缺口由第五轮 #13 处理；单独采用 #5 不包含该后续修复 |
| 2 | P1 | [#6 MCP 参数契约](https://github.com/raydocs/ipd/pull/6) | 通过 `6a24913`；13 组不支持的非默认参数明确拒绝，短摘要保持合法 UTF-8 |
| 2 | P1 | [#7 AI 诊断及修复顺序](https://github.com/raydocs/ipd/pull/7) | 通过 `a4cfde6`；未知不报 safe，按稳定优先级给检查建议，不把账号封禁归因于 IP |
| 2 | P1 | [#8 数据替换与新鲜度](https://github.com/raydocs/ipd/pull/8) | 通过 `c9fcb30`；并发/mmap 生命周期审查通过，disabled 源时钟修复已复测 |
| 3 | P2 | [#9 本地延迟 SVG 卡片](https://github.com/raydocs/ipd/pull/9) | 通过 `67e87d4`；原始错误不进入 SVG，文件清理竞态已修，第二轮独立安全审查 approve |
| 3 | P1 | [#10 节点测量未知态](https://github.com/raydocs/ipd/pull/10) | 通过 `9035290`；未配置实测能力时 abstain，不伪造整批 unreachable 或导出订阅凭据 |
| 4 | P2 | [#11 英文 CLI 展示](https://github.com/raydocs/ipd/pull/11) | 通过 `c5e4e25`；默认中文兼容，英文选项不翻译机器字段或原始证据 |
| 5 | P2 | [#13 Raw traceroute 报文关联](https://github.com/raydocs/ipd/pull/13) | 通过 `542e27b`；关联当前探针并修复 ICMP socket 包装 panic，第二轮独立审查 approve |
| 5 | P2 | [#14 HTTP OpenAPI 契约](https://github.com/raydocs/ipd/pull/14) | 通过 `c173c78`；参数、媒体与同步 job 语义补齐；nullable/MCP 400 返修后第二轮独立审查 approve |
| 5 | P1 | [#15 远程订阅安全读取](https://github.com/raydocs/ipd/pull/15) | 通过 `11b7e23`；独立安全审查 approve；全地址校验、每跳验证、固定地址连接与严格限额 |
| 6 | P1 | [#16 权威 DNS 观测会话](https://github.com/raydocs/ipd/pull/16) | Draft `32c6f99`，叠加 #14；第二轮 block：编码路径日志泄漏 P2、过时参数说明 P3 未闭环，未验收 |
| 6 | P1 | [#17 HTTP/SOCKS5 节点出口实测](https://github.com/raydocs/ipd/pull/17) | Draft `773ea38`，叠加 #10；第二轮 approve-with-fixes，YAML 别名键覆盖 P2 未闭环，不作完全验收 |

## 第六轮取舍与信号质量

继续优先补真实采集链路：#16 是默认关闭、短期 token 隔离的后端 DNS 会话，#17 是
CLI 显式选择的本地 HTTP/SOCKS5 出口 IP 测量，不是全协议 Clash runner 或浏览器测试。
必要依赖分别为 #14 的 HTTP 契约与 #10 的默认未知态；两个 Draft PR 仅包含各自增量。

X 搜索证据受限：现有搜索客户端认证失败（未重新登录或扫描浏览器 cookie），原始帖网页返回 403。
[2026-10-20 的二手文章](https://www.yokon.uk/posts/claude-anti-ban) 标注来源为
[X 原帖](https://x.com/Rivoclass/status/2111754234320613717)，反映网页、CLI、DNS 和 IPv6 路径
难以区分的使用困惑；原帖未独立核验，不算近期 X 全量样本，更不能证明其中封号因果主张。
这类需求信号与 [ip.cx 的 DNS 观测入口](https://ip.cx/dnsleak)、
[IPPure 的泄漏及多出口功能说明](https://ippure.com/en/faq) 一起用于选题，而不用于判定用户账号安全。

**第六轮尚无完全验收项。** 两项均实现并追加过返修，但第二轮仍有开放发现。
按两轮审查上限，将残余 P2/P3 写入 Draft PR 并交接，不继续用重复审查制造通过结论：

- #16：四类修正通过，但编码斜杠路径与 mux 清理顺序仍不同，可能把 bearer/调用者写入
  SQLite；另有 token 参数的旧“仅回显”描述。原先五类普通回归通过不代表编码路径已安全。
- #17：普通路径配置与非法列表处理已修；YAML 别名/语义重复键仍可能在 map 解码时覆盖
  原始配置并继续测量。应先校验原始 `yaml.Node`，不能宣称封闭键校验已完整。

两项修正版与前五轮的临时组合通过 Go 全套、Node、十个相关包 race、构建和 Linux route
交叉编译；但总控针对上述残余分别补探针，均实际失败。**已有组合测试绿色，不等于验收通过。**
未推送组合产品分支，两个 Draft 仍无合并/部署授权。

## 第五轮重新评估与取舍

2026-10-24 核对的竞品公开说明：
[IPLark](https://iplark.com/check) 展示质量、代理、评分与标签；
[IPPure](https://ippure.com/en/about) 描述地理、风险、指纹与 VPN 泄漏的一站式工具；
[ip.cx DNS 检测](https://ip.cx/dnsleak) 描述一次性随机域名与权威侧递归解析器观测。
这是公开功能说明，不是准确率、性能或隐私承诺的独立实测，也未提交页面显示的访客地址。

ipd 的主要差距仍是可信实际采集与开箱可用性，而非仅少一个分数。
真实 Clash 通道、权威 DNS 观测需要后续实现与受控运行证据；本轮不以 mock 冒充这些能力。
优先选择本地可验证的安全读取、线路证据准确性及 agent HTTP 契约：
先守住批量输入安全边界，再防止无关报文误判线路，最后减少 agent 猜测参数/返回形状。

## 验收证据与发现后返修

必跑命令：

```sh
go test ./...
node --test web/judge.test.mjs
```

原始基线在 macOS 上有两项失败：`TestServeTLSHandshakeAndH2` 要求 Linux MSS，
`TestSnapshotUncappedMapLoad` 读取 `/proc/self/maps`。#2 单独修复这些平台假设；
其他改进没有夹带 #2 的提交。总控在不推送的临时 detached worktree 中叠加 #2，
再组合各改动运行上述命令；不能将这些 macOS 基线失败说成单项测试全绿。

已验收改进的两套命令通过，并按风险额外运行无缓存/`-race` 测试：
lookup、route/probe/app、MCP、nodes，以及 CLI。具体检查只证明被覆盖的确定性路径。
Linux CI 的通过与本地真实 raw-socket 测量不是一回事；没有执行真实服务器或账号探测。

最终候选组合包含表中全部验收 SHA（含各分支的前序提交），按下文完成 CLI 展示整合，
在 macOS arm64 上实际通过：

```sh
go test -count=1 ./...
node --test web/judge.test.mjs
go test -race -count=1 ./internal/cli ./internal/app ./internal/lookup \
  ./internal/mcp ./internal/nodes ./internal/probe ./internal/route ./internal/api
go build ./cmd/ipd
GOOS=linux GOARCH=amd64 go test -c ./internal/route -o /tmp/ipd-route-linux.test
```

另外实跑英文帮助、英文 JSON 本地报告、离线 SVG 导出：离线导出保持 `abstain` / 退出码 `10`，
并不因成功保存文件变成“网络正常”。以上组合仅用于本地验收，未推送或合并成产品分支。
第五轮加入 #13–#15 后重新运行完整无缓存命令与上述八个包的 race、构建和 Linux route
交叉编译，全部通过。#13/#14 各经两轮、#15 经一轮独立新上下文审查后验收；
没有执行真实 Linux raw socket、生产订阅站点或账号测试。

第六轮额外组合检查（不构成 Draft 验收）：

```sh
go test -count=1 ./...
node --test web/judge.test.mjs
go test -race -count=1 ./internal/api ./internal/app ./internal/cli \
  ./internal/config ./internal/leak ./internal/lookup ./internal/mcp \
  ./internal/nodes ./internal/probe ./internal/route
```

这些命令通过；另加的编码路径与 YAML 别名键补充探针失败，其缺口和修复建议已进入 PR 正文。

总控实际发现并退回修复的缺口：

- #3：仅同步组引用仍会留下直接指向旧节点名的规则；补规则与拨号引用，以及实际分配名称。
- #5：有 hops 不等于到达目标；补 provider 完成证据、`no reply` 占位、目标 port-unreachable 判据。
- #6：UTF-8 测试硬编码旧路由文案，导致单项通过但组合失败；改为直接测试受控 Report 与协议不变量。
- #8：独立并发审查发现 disabled 源影响新鲜度时钟，要求保留 enabled-only 选择边界。
- #9：XML 转义不等于隐私脱敏；分享卡片不得直接包含可能带凭据的 provider 错误。
  独立安全审查另实际复现导出失败后按路径清理会误删替换文件，要求安全发布/清理回归。
  修复后只操作原文件描述符、不按路径删除；可能保留空/部分文件，导出并非原子发布。
- #13：独立审查复现既有 `ipv4.NewPacketConn(*icmp.PacketConn)` panic，导致关联逻辑无法执行；
  改用连接自有 IPv4 accessor，并用无 socket 的同一生产 adapter 回归验证错误路径。
- #14：组合复测发现空 target 的旧行为假设及 nullable RTT/loss 不符；独立审查还复现
  无观测 lookup 的 `disagreements:null` 和 MCP JSON-RPC 400 媒体缺失；返修与反证均通过。

## 剩余问题，按用户影响排序

### P1

1. **Clash 真实批量测量仍未接通。** #3 修复导出，#10 修复误报，但默认路径仍不会启动
   mihomo、分配逐节点通道或实测出口/AI 解锁。需要独立 runner/checker 集成、取消与清理、
   凭据隔离测试；不能因安装了外部二进制就宣称功能可用。#17 的显式 HTTP/SOCKS5 出口查询
   仅是候选子集，尚未完全验收，不提供全协议、AI 解锁或质量分数。
2. **其余网络目标及写入安全边界仍需专项审查。** #15 仅闭合远程订阅读取的地址校验、
   重定向和 DNS 固定连接边界，不是全产品 SSRF 认证；其他探测入口、webhook/watch 权限及外连、
   完整订阅导出的秘密处理仍需审查。其静态 IANA 策略需维护，配置代理会明确拒绝而非绕过固定连接。
3. **生产规模数据证据不足。** 完整线上数据的体积、来源许可、更新失败可观测性与 last-good
   保留需验证；#1 的 400,001 行合成快照性能不是生产文件实测。小型住宅留出集也不是大规模精度证明。
4. **账号诊断的缺测仍需真正的采集实现。** 默认 DNS 观测及部分 egress/双栈输入不足；
   #7 会如实弃权，重跑命令不会凭空产生观测。#16 的 DNS 后端会话仍因隐私缺口未验收，
   也没有公网 NS 委派或浏览器路径证据；应增加可信采集而非降低 safe 门槛。

### P2

- **开放阻碍：节点实测的 YAML 键完整性。** #17 第二轮发现别名/语义重复键可在 map 解码时覆盖坏类型
   或原始列表，随后仍发包。总控补测同样复现未拒绝；建议先校验原始 `yaml.Node` 的键再转换。
   已写入 Draft PR，按两轮审查上限记录为开放风险；组合绿测不等于此问题已修。
- **开放阻碍：DNS bearer 路径隐私。** #16 第二轮仍复现编码斜杠与 dot 段组合绕过日志排除，
  SQLite 会保留 bearer 和调用者。需按 mux 的 escaped 分段顺序处理敏感前缀，连同 P3 参数说明修正。
1. **受控 Linux 路由运行验证。** #13 已用跨平台报文夹具处理 #5 遗留的探针关联缺口，
   并修复阻断 ICMP 路径的包装 panic；仍未实跑 raw socket/TTL/收发。ICMP 没有认证，
   最小引用只提供有限标识，不能防止已观察当前标识者伪造回复，不能当成真实网络认证。
2. **解锁正向规则覆盖与巡检。** 未识别模板保守弃权；继续扩充可复核录制夹具、改版 canary，
   明确页面可达与真实登录/播放/模型调用的区别。
3. **英文覆盖边界。** CLI 展示不等于 HTTP/MCP/Web 全面本地化；原始来源证据应保留原文。
4. **分享体验。** 本地 SVG 不是公开托管；分享保持显式选择。浏览器下载、布局/长文本视觉检查、
   进一步隐私预览和无障碍验证仍有空间。
5. **协议持续一致性。** #14 已补齐 HTTP 参数、请求体、错误、同步 job 和能力边界，并有本地 wire
   回归；仍不是完整 OpenAPI/MCP 认证，后续业务变动须同步 schema、媒体及 nullable 回归。

## 采用建议

### 组合时的展示层整合

#9 与 #11 都修改 CLI。即使 Git 自动应用补丁没有冲突，也须按 #11 的
`docs/cli-language.md` 执行展示层整合：延迟帮助调用 locale；英文总帮助增加 latency；
延迟命令的自有错误改用 `cliError`，嵌套帮助使用 `messageText`。保留 #9 最新版本的
只关闭原 fd、不按路径删除，以及空/部分文件警告；不能为翻译恢复旧清理逻辑。
总控的临时组合按此整合，并非直接把并列 PR 无条件拼接。汇总 PR 本身仅含本文，
没有发布组合实现或替任何单项 PR 完成合并。

#13 与 #5 的 raw trace 修改重叠：按 `docs/route-probe-correlation.md` 保留 #5 的
`platformTrace`/UDP 接收及错误处理，采用 #13 的 ICMP/TCP 段、adapter 和 portable parser。
#15 与 #10 的 `nodes.go` 重叠：仅移走旧 reader/imports、加入新安全 reader，保留 #10 的默认
测量弃权，不可整文件覆盖。第五轮总控组合已按这两条逐段整合，#14 使用返修后的契约版本。

第六轮只作候选组合：#16 的 Service recorder 字段、API/schema、aux 接线与前轮代码并存；
#17 的 nodes 分发/helper 与 #9 latency helper 并存，新增用法使用 #11 的 `cliError` 及英文词典，
测试适配三返回值 `parseGlobals`。保留既有安全 reader、默认弃权和 SVG 无路径删除策略。
以上整合不修复第六轮开放发现，也不是推荐采用这两个 Draft。

先审阅独立 PR，再在候选组合上运行完整两套测试与相关 race 检查；不要把本清单视为合并授权。
留意 #7 的 nullable 布尔字段、#5 更保守的线路等级、#6 显式拒绝参数、#10 默认弃权等兼容性变化。
完整注入实测后的节点 YAML 可能仍含订阅凭据，不能公开转发。
