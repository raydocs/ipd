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
   [Draft #23](https://github.com/raydocs/ipd/pull/23) `ebd6b24` 已提交，组合 Go/Node/nodes race 通过，但首轮独立审查 block：端点归属验证、全局信任/路径策略保真两项 P1，以及清理失败报告 P2 正在返修，未验收。当前仅原生格式的 runner；跨格式配置转换明确 unsupported，自动协议转换及出口、纯净度和解锁接线仍待后续改进。
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
