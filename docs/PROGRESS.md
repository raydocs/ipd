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

2026-11-08 多源阶段：Draft #32 head93a6288，最新main仍3a08322。两轮独立审查；原五项修复，
R2备用Transport连接清理及mapped-zone由总控限定修复。旧码实际留下6条连接，新码全部关闭；
TLS fixture隔离子进程，不污染全套信任根。分支全Go、全部Node、providers/app/api/lookup race通过。
本阶段代码：providers比较契约、app compare、lookup原子来源观察、API/schema、web比较与测试。
完成范围仅IPQS/AbuseIPDB在线适配和IPinfo Lite快照；另外三在线适配及GeoLite独立MMDB观察pending。
真实provider/key/公网未验证；CI本阶段未查询，保持Draft不合并。最终候选组合复测进行中。
下一步：记录组合结果后验收限定增量，再补未完成provider adapter，之后既定UI等批次；不重复runner大PR。
精确耗时未记录。无用户决策阻塞。

2026-11-08 #32限定增量验收：head93a6288。最终组合main+#13/#15/#20/#22及已验收节点链、
#28/#29/#30/#31/#32，全Go、Node11/11、providers/app/api/lookup race通过。
该结论取代上段“组合进行中”；保持Draft。下一单元优先补pending provider adapter，无真实key/公网验证。

2026-11-08 下一独立Draft #33：ipapi.is比较适配，head91156cf，base main3a08322，依赖#32。
限定新增providers适配/测试及专属文档；不改默认探测或legacy Risk。旧父版本实际失败，
分支全Go/Node/provider race通过；独立R1 approve，51项反例由总控再跑race通过。
最终候选组合Go/Node/四包race正在执行，尚未验收。真实API/key/浏览器/线上未验证。
下一步取得组合结论后验收，再补proxycheck、Scamalytics及GeoLite独立观察缺口，之后UI等清单。
