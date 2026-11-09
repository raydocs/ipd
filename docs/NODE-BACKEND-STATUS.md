# 双核心节点检测：本地验收矩阵（2026-11-08）

以下是候选代码及本地fixture结果，**不是线上/真实核心协议认证**。
main仍3a08322；四层均Draft、GitHub当前报告可干净合并，未执行合并。

| 层 | 精确head | 已有本地结论 |
|---|---|---|
| #23 外部双runner | 8331260 | 共同接口、独立外部进程、格式选择/强制选择、backend标识、权限/配置隔离/归属/退出/清理 |
| #25 出口观测 | 676aabf | 显式opt-in、每节点固定HTTPS出口、IPv6/身份/公网性、无DIRECT/env回退 |
| #27 live handle | f698099 | run绑定Check/CheckAll/Done、后台检测、整批单向撤销、慢清理不延迟撤销 |
| #26 解锁接线 | b81228e | 同节点请求、拨号/读后/采纳门控、活跃连接取消、gzip/编码/预算、未知与错误不作positive |

## 实际支持范围

- Clash YAML默认为mihomo：当前白名单为ss、vless、vmess、trojan、hysteria2。
- sing-box原生JSON默认为sing-box：shadowsocks、vless、vmess、trojan、hysteria2、tuic、anytls。
- 可以强制选择后端，但格式不兼容时明确unsupported，不会偷偷换核心或忽略配置。
- ShadowTLS层叠、WireGuard endpoints及两格式间转换仍unsupported；**Clash YAML中mihomo不支持协议自动转换到sing-box尚未完成**。
- 出口与显式解锁已有fixture，逐节点纯净度尚未接通。没有把unsupported/无测量写成节点已死。
- 结果保留backend身份；用户自行提供核心可执行文件，本仓库不链接GPL核心、不下载、不启动真实机场配置。

## 本次复验

总控最终候选组合的nodes整包race：PASS，46.478s；
日志 /tmp/ipd-pr32-fix-20261108/batch-runner-race.log。
核心出口/解锁/lifetime回归随组合app套件运行；此前分支及独立审查见#23/#25/#26/#27对应记录。
2026-11-08单次GitHub读取：四层均Draft、MERGEABLE；#23所列CI成功，不把CI当review或race稳定性证明。
本地fixture为测试子进程，不是实际mihomo/sing-box，不证明其版本配置兼容或加密协议握手可用。
Linux此前仅交叉编译，未有本轮Linux运行证据；历史350ms就绪抖动记录保留，不靠改超时掩盖。

## 剩余工作（不替用户做上线/合并决策）

1. 精确的逐节点格式/协议转换与双核心混合批次路由；保真不了的字段必须继续拒绝，不能静默降级。
2. 在本地自建服务验证真实核心版本、协议握手、TLS/UDP，仍禁止真实机场/用户配置。
3. 逐节点纯净度独立证据接线，缺key/源未知保持弃权；不能把出口IP或解锁当纯净度。
4. Linux原生归属/撤销/清理运行覆盖和资源/规模测量。
5. 用户决定是否合并与上线；本轮不执行部署、SSH、main推送或仓库设置修改。

因此本项“收尾”是明确已有安全链路和缺口，不将尚未实现的全协议转换或真实核心验证标成完成。
