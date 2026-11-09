# 证据工作台 UI（独立候选）

Base main3a08322；依赖已验收未合并 #28/#32/#33。依赖合并点570e9d4，自己的改动仅web及本说明。

## 行为

- 响应式查询工作台、住宅/原生/国家/ASN报告卡、可横向滚动的数据源比较及按需原始JSON。
- 默认原有查询不增加请求；位置与归属仅显式点击，调用同源lookup。并列比较仍需显式live选择，offline覆盖它。
- 地图是本地等距坐标示意，不加载底图/SDK/字体/第三方资源。坐标必须有限、在范围内且有来源数组；
  既有(0,0)未知哨兵不画点。不是设备位置或精确定位，不补推断坐标；无地理证据就显示未知。
- 分享默认关闭。显式勾选才允许本机Blob SVG下载，不上传、不发布链接、不更改后端ShareEnabled。
  SVG只含受控结论标签和来源条数，完全隐藏IP，不含位置、ASN、原始错误、summary或账号数据。
  原始JSON仍可能含IP和未脱敏信息，界面明确提示；不承诺截图或手动复制原始数据已经脱敏。
- 每次请求清空分享授权/地图；失败不保留旧分享内容。迟到请求不能覆盖较新的报告。
- 保留AI本地采集/导入和WebRTC边界。键盘焦点、输入label、skip link、状态区和reduced-motion样式齐备。

## 本地证据与限制

新增迟到响应回归在570e9d4的旧app.js上实际FAIL：STALE覆盖LATEST；新代码通过。
日志 /tmp/ipd-pr32-fix-20261108/ui-old-behavior.log，其他Go/Node/race另报。
真实本地Chromium/T3 Preview：1280×800、390×844均无页面水平溢出；默认无第三方资源；
合成lookup fixture显示未知卡/地图点，分享默认disabled、勾选后开启，SVG不含合成IP/秘密；
localStorage/sessionStorage均0。测试服务仅loopback且offline，测试后关闭。
截图仅本地证据（不提交）：browser-screenshot-127-0-0-1-mw8kjh36-15eddb35.png、
browser-screenshot-127-0-0-1-mw8kjyjr-c3b94c2c.png，位于T3 browser-artifacts。
未做真实线上、其他浏览器、屏幕阅读器或完整WCAG认证；独立代码/视觉审查与最终组合待完成。
地图不是完整地理底图，真实公开分享服务仍默认关闭；不把这个UI增量称为所有产品缺口已完成。
