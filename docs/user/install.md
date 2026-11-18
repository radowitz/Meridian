# 安装网关

前提：一台 Debian 13 主机（amd64 或 arm64），局域网口已配好地址，能以 root 登录。安装脚本不改家里路由器、不停已有的其他代理网关、不启动 DHCP/radvd。

第一次安装建议照 [快速上手](quickstart.md) 走一遍；本页是安装脚本的完整说明。安装之后的升级和回滚见 [upgrade-rollback.md](upgrade-rollback.md)，数据面和脚本内部细节见[参考手册](../install-debian13.md)。

## 一条命令

```sh
git clone https://github.com/<owner>/meridian.git && cd meridian
sudo bash deploy/debian/install.sh --lan-addr 192.0.2.1 --version v1.4.0
```

脚本依次：写入开机 sysctl（转发保持关闭）、写 `/etc/docker/daemon.json`（不让 Docker 改 iptables/转发）、安装 Docker 与依赖、取得面板镜像、安装宿主代理 `meridian-host` 与 unit、加载管理防火墙、写 `deploy/.env`（0600）、启动面板并做健康检查，最后打印下一步：

```sh
sudo docker compose -f deploy/docker-compose.yml exec meridian meridian setup-code
```

初始化码只显示在终端里，1 小时有效；浏览器打开 `http://<局域网地址>:8787` 创建管理员。

## 参数

| 参数 | 环境变量 | 说明 |
|---|---|---|
| `--lan-addr A` | `MERIDIAN_LAN_ADDR` | 面板监听的局域网 IPv4。不给时：沿用 `deploy/.env` → 沿用现有面板容器的地址（含已存拓扑的 `panel_bind`）→ 在终端确认探测到的候选 → 只监听 `127.0.0.1:8787` |
| `--lan-if IF` | `MERIDIAN_LAN_IF` | 局域网接口，默认是持有该地址的接口 |
| `--version V` | `MERIDIAN_VERSION` | 拉取 `ghcr.io/<owner>/meridian:V`。仓库可用 `MERIDIAN_IMAGE_OWNER` 或 `MERIDIAN_IMAGE_REPO` 改 |
| `--image REF` | `MERIDIAN_IMAGE` | 拉取指定镜像（可带 `@sha256:` 摘要） |
| `--image-tar F` | `MERIDIAN_IMAGE_TAR` | 载入 `docker save` 导出的镜像包，不联网拉取 |
| `--build` | | 在本机从源码构建 `meridian:local`（没有指定镜像且 `.env` 里也没有时的默认） |
| `--allow CIDR` | `MERIDIAN_MGMT_ALLOW`（逗号分隔） | 额外允许访问面板端口的来源，如远程接入地址池；可重复 |
| `--no-firewall` | | 不装管理防火墙（自行负责面板端口访问控制） |
| `--no-start` | | 只准备主机，不启动面板 |
| `--print-config` | | 打印解析后的设置并退出，不需要 root |

镜像来源四选一；同时给出多个会报错退出（退出码 2）。

**镜像是否已发布以镜像仓库为准。** 仓库只包含构建工作流的定义（`.github/workflows/release-images.yml`，手动触发、默认只构建）。拉取失败时脚本会说明可能原因，并给出本地构建（`--build`）和镜像包（`--image-tar`）两条路径。

网关自己的流量常常到不了 Docker Hub / ghcr.io，此时在能联网的机器上构建并导出：

```sh
docker buildx build --platform linux/arm64 -f deploy/Dockerfile -t meridian:local --load .
docker save meridian:local | gzip > meridian.tar.gz
# 拷到网关后
sudo bash deploy/debian/install.sh --lan-addr 192.0.2.1 --image-tar meridian.tar.gz
```

## 重复运行

可以放心重跑：面板口令、管理员、拓扑、凭据卷、`meridian-host` 的令牌和 DoT 证书都不会重新生成；`deploy/.env` 只替换 `MERIDIAN_BIND`、`MERIDIAN_IMAGE` 两行，其余行原样保留。不带镜像参数重跑时沿用 `.env` 里已有的镜像。已有数据面时脚本进入“升级模式”：只替换宿主二进制和 unit，失败自动恢复，不打开原本关闭的转发。

## 管理防火墙

规则写在 `/etc/meridian-host/mgmt-firewall.nft`（0600，面板容器不可写），由 `meridian-mgmt-firewall.service` 在 Docker 之前加载，只占用自己的表 `inet meridian_mgmt`：

8787/tcp 只接受以下连接，其余一律丢弃（IPv4 和 IPv6 同一张 inet 表）：

- 回环接口 `lo`；
- 局域网网卡（`--lan-if`，或 `--lan-addr` 所在的网卡）上、**同时**来源属于这块网卡自己的局域网网段的连接：它直连的 IPv4/IPv6 网段（内核路由，含 ULA 与全局前缀）和 `fe80::/10`。两个条件缺一不可：例如单网卡旁路网关上，被主路由器从公网转发进来的连接虽然到达局域网网卡，来源不是局域网网段，会被丢弃。没有确认局域网地址时没有这条规则（只剩回环、`mra` 和 `--allow`）；
- 远程接入接口 `mra` 上的连接，**不再按来源过滤**。`mra` 是面板的 WireGuard 远程接入接口，每个设备对端的 AllowedIPs 只有它在设备池里的地址，所以实际能到达的只有已登记的远程接入设备；
- `--allow` 列出的来源，**任意接口**。

经 DNAT 转发到 8787 的连接（Docker 发布端口的方式，以及将来 Docker 重新启用 iptables 时它自己的端口规则）按完全相同的四条判断。

`nft -c` 检查不通过时安装中止：规则不会加载，面板容器不会启动（已有的面板容器会被停止；升级模式下恢复到之前的版本）。修好原因后重跑；确实不要这层防火墙时用 `--no-firewall`，面板端口的访问控制由你自己负责。

- 基链策略是 accept，只匹配面板端口：SSH 和其他表的规则不受影响。

查看：`sudo nft list table inet meridian_mgmt`。撤销：`sudo systemctl disable --now meridian-mgmt-firewall`。
