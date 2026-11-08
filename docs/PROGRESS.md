# ipd 总控进度

更新：2026-11-06。阶段：#28 本地验收完成，下一阶段 /cc。精确耗时未记录。
main 3a08322；汇总 Draft #21；本工作分支 docs/roadmap-main-status-r8。#12 已关闭不再更新。
本阶段文件：#28 web/app.js、judge.js、judge.test.mjs；汇总 ROADMAP-STATUS、PROGRESS。
#28 head157bdcb：原三项P2经独立R2确认闭环；新增一致性P2由总控限定修正、实际反证和矩阵验证。
组合 main+#13/#15/#20/#22/#23/#25/#26/#27/#28：Node/Go全套/九包race通过。
CI本阶段未查询；委派审查不是GitHub正式批准。真实浏览器/线上/真实core未验证。
开放：#17/#19冲突待处理；全部候选未合并。#28保持Draft，#13/#15/#20 Ready。
下一步：独立 /cc 只读脚本PR、独立审查及组合测试；之后场景/litmus、多源等既定清单。
约束：最新main base；不merge/mainpush/force/SSH部署/域名/设置/注册/真实IP秘密。

阶段更新：#29 只读 /cc 已验收，head89d1e59；两轮独立 review 闭合 P2，总控补强 P3 测试。
分支与候选组合 Go/Node/API-config-web race 通过，最终断言窄 race 通过；真实线上未验证。
改动在独立 #29，无 #28 混入。下一批：场景评分与 litmus，之后可选多源等既定优先级。

阶段更新：#30 五场景证据模型验收，head6a1f3e0，独立R2 approve；分支/组合Go-Node-race通过。
缺测/矛盾弃权，非封号概率或业务成功保证。下一独立增量：litmus挑战证据，真实CFBotScore不可得。

2026-11-07 阶段交接：#31 head55ba82b，四项P2与R2完整反例已通过，分支Go/Node/race通过。
最终组合Go/Node复测通过，nodes race再现sing-box三项就绪超时，日志见ROADMAP最新段。
#31仍Draft未验收；停止重复测试，无多源新PR。下一步定位既有#23/#27生命周期就绪阻碍，
不能靠改超时/删测试通过；修后组合与独立验证，再按顺序启动多源。耗时未精确记录，CI未查询。

2026-11-08：#31 head55ba82b验收，保持Draft。main及#23/#25/#26/#27逐分支nodes race全通过，
组合nodes树等于#27且组合race通过；历史超时未复现、唯一根因未证实，保留负载敏感限制。
证据/tmp/ipd-runner-diagnostic-20261108/；真实公网未验证、CFBotScore未知。下一步独立多源比较PR。
