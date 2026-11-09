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

2026-11-08 丹佛18:10：用户要求20:00前逐项状态。#33组合仍在跑，禁止提前验收。
本批顺序调整：多源最多再补proxycheck；Scamalytics/GeoLite完整适配移到后续，不挡UI/历史/中国权重/评测/runner收尾。
当前清单：UI未开始；历史/邻居未开始；中国Globalping健康权重未开始；住宅评测框架未开始；
runner23/25/26/27代码及本地fixture已验收，真实core/Linux runtime/协议转换仍未验证。
将并行启动互不重叠的历史、健康权重、住宅评测三个独立Draft；总控负责UI及组合/独立审查验收。
20:00是状态汇总期限，不等同全部功能/真实服务验证完成期限。每项必须区分partial、review、local、online。

#33最终验收：91156cf，完整候选组合Go/Node11项及providers/app/api/lookup race全部通过，
独立R1 approve；保持Draft。日志ipapiis-combo-{go,node,race}.log。真实API/线上未验证。
健康权重子任务获准仅service.go Sample→gfw.Obs新增字段透传；历史方法区域与其不重叠。

丹佛18:18批次：#34住宅评测16341f4、#35健康证据排序d9646e4、#36历史/匿名邻居dbd0cda、
#37证据UI ec1137a已开独立Draft，全部base main3a08322。前三作者局部/full/race通过但尚未独立验收；
#37本地浏览器桌面/390px、Node及窄Go通过，full/race另记。#37依赖#28/#32/#33，独立diff起570e9d4。
最终候选组合新增四项，history OpenAPI一行上下文冲突已精确保留其他候选并手动替换对应history操作。
全套/九包race正在跑；不提前验收。下一步独立审查三项后审UI，修复发现再更新精确head。

丹佛18:28：首轮四项组合fullGo/Node16/九包race通过，额外nodes整包race46.478s通过。
#35独立approve+总控隔离probe/gfw race通过，限定锚点历史/排序可验收；无生产锚点采集，非投票权重上线。
#34 R1 Unicode键折叠P2已补ASCII键检查，bec6454；旧码反证5例FAIL、真实CLI被拒绝，分支fullGo/Node/race通过。
#37 R1默认/me事实与空输入旧报告两项P2修至8952fbf；原独立反例旧6/8新8/8，Node回归通过，full/race复测中。
视觉子审受image-read hook阻挡未看截图，仅静态建议；已修空壳/ghost tab/unknown/触点等，不标像素审查通过。
#36独立审查待回。修正批次组合及#34/#37第二轮聚焦审查接下来执行；不提前整体验收。
