# 隐私威胁模型

ipd 的隐私承诺要能被检查，而不是只写在首页上。这篇说明谁能看到什么、二进制里有什么、以及怎么核对。

## 要保护的是什么

访客来查一个地址，或者在自己的出口上跑 CLI。需要保住的是：

- 浏览器里的 WebRTC 候选地址（真实网卡地址经常出现在这里）
- 能把一次查询和一个人长期对上的原始 IP 日志
- 页面上偷偷加载的第三方脚本、像素和字体

不在这个模型里的：用户故意填进查询框的公网地址。那个地址就是查询对象。

## 信任边界

| 组件 | 看到什么 | 不看到什么 |
|---|---|---|
| 浏览器页面 | 本机时区、WebRTC 候选 | 候选不会交给服务器 |
| `POST /v1/leak/webrtc` | `leak` 和 `candidate_count` | 候选字符串、网卡地址 |
| HTTP 访问日志 | 客户端 IP、路径，最多保留 7 天 | 查询内容以外的浏览器指纹 |
| CLI / MCP stdio | 在本机算，地址可以不离开机器 | `--offline` 时不访问在线情报源 |
| 数据更新 | 下载公开前缀表 | 不上传查询过的地址 |

页面脚本只有同源的 `/static/judge.js` 和 `/static/app.js`。WebRTC 判断在浏览器里做完，上传的正文只有两个字段。

## 我们明确不做的事

- 不把 WebRTC 候选写进日志、数据库或分享链接
- 不卖排名，不卖广告位，评分权重在 `models/purity.yaml`
- 页面不引用外部脚本、外部样式、外部图片或统计域名
- 发布的二进制附 SHA256，并用 GitHub Actions 的 OIDC 做 cosign keyless 签名

## 怎么核对

1. CI 作业跑 `go test ./web -run TestBundlePrivacy`。嵌入的页面、脚本、样式、图标里只要出现外部 `http(s)` URL 或第三方 `<script src>`，作业就会失败。XML 命名空间 `http://www.w3.org/2000/svg` 除外，浏览器不会去请求它。
2. 原始 IP 日志的保留时间是 `privacy.Retention`（7 天），由 `TestLogRetention` 覆盖。
3. 发布流程见 `.github/workflows/release.yml`。它写出 `SHA256SUMS`，并用 `cosign sign-blob --yes` 在没有长期密钥的情况下签名。验证：

```sh
cosign verify-blob ipd-linux-amd64 \
  --signature ipd-linux-amd64.sig \
  --certificate ipd-linux-amd64.pem \
  --certificate-identity-regexp '^https://github.com/.+/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c SHA256SUMS
```

身份正则里的仓库路径以实际发布仓库为准。签名证书来自 GitHub OIDC，不在仓库里放私钥。
