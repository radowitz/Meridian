#!/bin/bash
# Prepare a fresh Debian host to run Meridian beside ROS and mihomo.
# It does not change RouterOS, does not stop mihomo, and does not start DHCP or radvd.
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "请用 root 运行：sudo bash deploy/debian/install.sh" >&2
  exit 1
fi

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  if [[ "${VERSION_ID:-}" != "13" ]]; then
    echo "当前是 ${PRETTY_NAME:-未知系统}。Meridian 按 Debian 13 编写，其他版本请先核对内核 WireGuard 和 nftables。" >&2
  fi
fi

if ip -4 addr show | grep -q "inet 192.168.100.88/"; then
  echo "已看到 192.168.100.88。"
else
  echo "还没有 192.168.100.88。请先把局域网口设成这个地址，网关 192.168.100.1，不要占用 ROS 的地址。" >&2
fi

install -d /etc/sysctl.d /etc/nftables.d /etc/wireguard /etc/smartdns /etc/meridian/tls /etc/meridian/dns \
  /etc/iproute2/rt_tables.d /var/lib/meridian /usr/local/sbin

cat > /etc/sysctl.d/99-meridian.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv6.conf.all.send_redirects=0
net.ipv6.conf.default.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
EOF

# SLAAC client on the LAN NIC. forwarding=1 ignores accept_ra unless it is 2.
# Prefer the interface that already has 192.168.100.88; Debian 13 rarely names it eth0.
lan_if="${MERIDIAN_LAN_IF:-}"
if [[ -z "${lan_if}" ]]; then
  lan_if="$(ip -o -4 addr show 2>/dev/null | awk '/inet 192.168.100.88\//{print $2; exit}')"
fi
lan_if="${lan_if:-eth0}"
echo "局域网接口：${lan_if}。面板拓扑里的 lan_interface 要和它一致。"
if [[ -d "/proc/sys/net/ipv6/conf/${lan_if}" ]]; then
  cat >> /etc/sysctl.d/99-meridian.conf <<EOF
net.ipv4.conf.${lan_if}.rp_filter=2
net.ipv4.conf.${lan_if}.send_redirects=0
net.ipv6.conf.${lan_if}.accept_ra=2
net.ipv6.conf.${lan_if}.forwarding=1
net.ipv6.conf.${lan_if}.send_redirects=0
net.ipv6.conf.${lan_if}.accept_redirects=0
EOF
fi
# "all=0" does not clear a per-interface send_redirects that is still 1.
for d in /proc/sys/net/ipv4/conf/*; do
  i="$(basename "$d")"
  sysctl -w "net.ipv4.conf.${i}.rp_filter=2" >/dev/null || true
  sysctl -w "net.ipv4.conf.${i}.send_redirects=0" >/dev/null || true
  sysctl -w "net.ipv4.conf.${i}.accept_redirects=0" >/dev/null || true
done
for d in /proc/sys/net/ipv6/conf/*; do
  i="$(basename "$d")"
  sysctl -w "net.ipv6.conf.${i}.send_redirects=0" >/dev/null || true
  sysctl -w "net.ipv6.conf.${i}.accept_redirects=0" >/dev/null || true
done
sysctl --system >/dev/null || true

if systemctl list-unit-files | grep -q '^systemd-resolved.service'; then
  mkdir -p /etc/systemd/resolved.conf.d
  cat > /etc/systemd/resolved.conf.d/meridian.conf <<'EOF'
[Resolve]
DNSStubListener=no
EOF
  systemctl restart systemd-resolved || true
  echo "已关闭 systemd-resolved 的 53 端口占用。"
fi

if systemctl list-unit-files | grep -q '^radvd.service'; then
  systemctl disable --now radvd || true
  echo "已停用 radvd。主局域网的 RA 仍由 ROS 发送。"
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
compose_pkg="docker-compose"
if apt-cache show docker-compose-v2 >/dev/null 2>&1; then
  # Debian 13 ships the v2 plugin here. The Python v1 package does not
  # provide `docker compose`, which is what the Compose file needs.
  compose_pkg="docker-compose-v2"
fi
apt-get install -y docker.io "${compose_pkg}" wireguard-tools nftables iproute2 curl ca-certificates openssl
# SmartDNS refuses to start if bind-tls points at a missing certificate.
# The name will not match what clients dial; strict DoT fails closed and
# falls back to the hijacked port 53. Generated only when absent.
if [[ ! -s /etc/meridian/dns/cert.pem ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /etc/meridian/dns/key.pem \
    -out /etc/meridian/dns/cert.pem \
    -days 3650 -subj "/CN=meridian.lan"
  chmod 600 /etc/meridian/dns/key.pem /etc/meridian/dns/cert.pem
fi
# Host networking does not need Docker's FORWARD rules. Leaving them on
# sets FORWARD to DROP and black-holes the LAN gateway.
if [[ ! -f /etc/docker/daemon.json ]]; then
  install -d /etc/docker
  cat > /etc/docker/daemon.json <<'EOF'
{
  "iptables": false,
  "ip6tables": false
}
EOF
else
  echo "已有 /etc/docker/daemon.json。若其中 iptables 不是 false，Docker 可能把转发策略改成 DROP，网关会丢包。" >&2
fi
systemctl enable docker
systemctl restart docker

here="$(cd "$(dirname "$0")" && pwd)"
install -m 644 "${here}/meridian.service" /etc/systemd/system/meridian.service
systemctl daemon-reload
systemctl enable meridian.service

echo
echo "主机准备完成。下一步："
if docker compose version >/dev/null 2>&1; then
  echo "  sudo docker compose -f deploy/docker-compose.yml up -d --build"
elif command -v docker-compose >/dev/null 2>&1; then
  echo "  sudo docker-compose -f deploy/docker-compose.yml up -d --build"
fi
echo "  面板口令：sudo cat /var/lib/meridian/panel.token"
echo "  浏览器打开 http://192.168.100.88:8787"
echo "不要把真实端点或私钥提交进仓库。"
