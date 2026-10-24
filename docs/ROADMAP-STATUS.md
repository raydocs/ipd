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
| 1 | P1 | [#5 去程/回程证据](https://github.com/raydocs/ipd/pull/5) | 主修复通过 `2eda873`，独立审查为 approve-with-fixes；既有 ICMP 关联 P2 未解决，见下文 |
| 2 | P1 | [#6 MCP 参数契约](https://github.com/raydocs/ipd/pull/6) | 通过 `6a24913`；13 组不支持的非默认参数明确拒绝，短摘要保持合法 UTF-8 |
| 2 | P1 | [#7 AI 诊断及修复顺序](https://github.com/raydocs/ipd/pull/7) | 通过 `a4cfde6`；未知不报 safe，按稳定优先级给检查建议，不把账号封禁归因于 IP |
| 2 | P1 | [#8 数据替换与新鲜度](https://github.com/raydocs/ipd/pull/8) | 通过 `c9fcb30`；并发/mmap 生命周期审查通过，disabled 源时钟修复已复测 |
| 3 | P2 | [#9 本地延迟 SVG 卡片](https://github.com/raydocs/ipd/pull/9) | 通过 `67e87d4`；原始错误不进入 SVG，文件清理竞态已修，第二轮独立安全审查 approve |
| 3 | P1 | [#10 节点测量未知态](https://github.com/raydocs/ipd/pull/10) | 通过 `9035290`；未配置实测能力时 abstain，不伪造整批 unreachable 或导出订阅凭据 |
| 4 | P2 | [#11 英文 CLI 展示](https://github.com/raydocs/ipd/pull/11) | 通过 `c5e4e25`；默认中文兼容，英文选项不翻译机器字段或原始证据 |

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
  ./internal/mcp ./internal/nodes ./internal/probe ./internal/route
go build ./cmd/ipd
```

另外实跑英文帮助、英文 JSON 本地报告、离线 SVG 导出：离线导出保持 `abstain` / 退出码 `10`，
并不因成功保存文件变成“网络正常”。以上组合仅用于本地验收，未推送或合并成产品分支。

总控实际发现并退回修复的缺口：

- #3：仅同步组引用仍会留下直接指向旧节点名的规则；补规则与拨号引用，以及实际分配名称。
- #5：有 hops 不等于到达目标；补 provider 完成证据、`no reply` 占位、目标 port-unreachable 判据。
- #6：UTF-8 测试硬编码旧路由文案，导致单项通过但组合失败；改为直接测试受控 Report 与协议不变量。
- #8：独立并发审查发现 disabled 源影响新鲜度时钟，要求保留 enabled-only 选择边界。
- #9：XML 转义不等于隐私脱敏；分享卡片不得直接包含可能带凭据的 provider 错误。
  独立安全审查另实际复现导出失败后按路径清理会误删替换文件，要求安全发布/清理回归。
  修复后只操作原文件描述符、不按路径删除；可能保留空/部分文件，导出并非原子发布。

## 剩余问题，按用户影响排序

### P1

1. **Clash 真实批量测量仍未接通。** #3 修复导出，#10 修复误报，但默认路径仍不会启动
   mihomo、分配逐节点通道或实测出口/AI 解锁。需要独立 runner/checker 集成、取消与清理、
   凭据隔离测试；不能因安装了外部二进制就宣称功能可用。
2. **网络目标及远程订阅安全边界需专项审查。** 域名解析、重定向、私网/metadata 防护，
   webhook/watch 的权限与外连边界，以及订阅导出的秘密处理，都不能由通用错误脱敏替代。
3. **生产规模数据证据不足。** 完整线上数据的体积、来源许可、更新失败可观测性与 last-good
   保留需验证；#1 的 400,001 行合成快照性能不是生产文件实测。小型住宅留出集也不是大规模精度证明。
4. **账号诊断的缺测仍需真正的采集实现。** 默认 DNS 观测及部分 egress/双栈输入不足；
   #7 会如实弃权，重跑命令不会凭空产生观测。应增加可信采集而非降低 safe 门槛。

### P2

1. **Linux ICMP 探针关联。** #5 第二轮独立审查发现既有 `trace_linux.go` 路径未完整关联
   探针 ID/序号或引用报文，无关 EchoReply 可能被误判为完成。已写入 PR 描述，未解决，
   不能当成真实网络认证；后续需要报文级回归与受控 Linux 验证。
2. **解锁正向规则覆盖与巡检。** 未识别模板保守弃权；继续扩充可复核录制夹具、改版 canary，
   明确页面可达与真实登录/播放/模型调用的区别。
3. **英文覆盖边界。** CLI 展示不等于 HTTP/MCP/Web 全面本地化；原始来源证据应保留原文。
4. **分享体验。** 本地 SVG 不是公开托管；分享保持显式选择。浏览器下载、布局/长文本视觉检查、
   进一步隐私预览和无障碍验证仍有空间。
5. **协议文档完整度。** OpenAPI 参数、请求体、错误、异步/同步语义与能力边界应继续对照实现补齐，
   不应仅靠结构性 lint 视为完整。

## 采用建议

### 组合时的展示层整合

#9 与 #11 都修改 CLI。即使 Git 自动应用补丁没有冲突，也须按 #11 的
`docs/cli-language.md` 执行展示层整合：延迟帮助调用 locale；英文总帮助增加 latency；
延迟命令的自有错误改用 `cliError`，嵌套帮助使用 `messageText`。保留 #9 最新版本的
只关闭原 fd、不按路径删除，以及空/部分文件警告；不能为翻译恢复旧清理逻辑。
总控的临时组合按此整合，并非直接把并列 PR 无条件拼接。汇总 PR 本身仅含本文，
没有发布组合实现或替任何单项 PR 完成合并。

先审阅独立 PR，再在候选组合上运行完整两套测试与相关 race 检查；不要把本清单视为合并授权。
留意 #7 的 nullable 布尔字段、#5 更保守的线路等级、#6 显式拒绝参数、#10 默认弃权等兼容性变化。
完整注入实测后的节点 YAML 可能仍含订阅凭据，不能公开转发。
