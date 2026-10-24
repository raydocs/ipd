# 部署手册

这次构建**没有登录任何服务器，没有改任何线上配置，也没有把进程绑到公网地址或真实域名**。下面的文件是给你之后批准上线时用的。域名只是配置项 `IPD_DOMAIN`，默认 `localhost`。

## 还没做、需要你点头的事

1. 在核心机上创建用户 `ipd`，安装二进制到 `/usr/local/bin/ipd`，数据目录 `/var/lib/ipd`。
2. 安装 `deploy/systemd/ipd.slice` 和 `ipd.service`。slice 只限制 ipd：`AllowedCPUs=8-11`、`CPUQuota=400%`、内存上限 4G。**没有改 GitHub Actions runner 的 CPU**（计划里的 D3，需要你同意才动 runner）。
3. 确认 80/443、53、3478 没被占用后再改监听地址。默认单元仍然听 `127.0.0.1`。
4. 备用机上 80/443 已被占用。`deploy/Caddyfile.snippet` 是一段注释掉的反代，指向 `127.0.0.1:8443`。改 Caddy 需要你同意（D4）。
5. 探针用 `deploy/install-agent.sh` 或 `deploy/ansible/install-agent.yml`，在你自己的机器上跑。小内存节点的单元限制是 `MemoryMax=64M`、`CPUQuota=50%`。
6. 故障切换（DNS TTL 60 秒、从 litestream 副本拉起 SQLite、RTO ≤ 5 分钟）和「ipd 打满时 CI 回归 ≤ 5%」都要在真实机器上演练，这里没有跑。
7. 公开域名、证书、`dns.<域名>` 的 NS 委派、STUN 公网端口、MCP Registry，都属于计划里的 M10。

## 本地先看服务

```sh
go build -o bin/ipd ./cmd/ipd
IPD_HTTP_ADDR=127.0.0.1:8787 IPD_OFFLINE=true ./bin/ipd serve
```

`IPD_OFFLINE=true` 时只用本地快照，不访问在线源和 DNSBL。`IPD_DATA_UPDATE` 在未离线时默认开启，`serve` 会按天刷新免密钥数据集。`IPD_PEAK` 和 `IPD_CANARY` 默认关闭。回程 traceroute 在没有 `CAP_NET_RAW` 时会退到 UDP 错误队列，再退到系统里的 `tracepath`/`traceroute`。TLS 端口会完成握手以读取 H2 指纹；抓 SYN 需要 `CAP_NET_RAW`，否则只用 `TCP_INFO` 的 MSS。

Docker 只把端口发布在回环上：

```sh
docker compose -f deploy/docker/compose.yaml up --build
```

## 监听地址

全部来自环境变量，见 `ipd` 的 `internal/config`：`IPD_HTTP_ADDR`、`IPD_DNS_ADDR`、`IPD_STUN_ADDR`、`IPD_TLS_ADDR`、`IPD_DOMAIN`、`IPD_DATA_DIR`。分享默认关（`IPD_SHARE_ENABLED`），标签提交默认关（`IPD_LABELS_ENABLED`）。
