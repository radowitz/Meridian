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

install -d /etc/sysctl.d /etc/nftables.d /etc/wireguard /etc/smartdns /etc/meridian/tls /var/lib/meridian

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
net.ipv6.conf.all.accept_redirects=0
EOF

# SLAAC client on the LAN NIC. forwarding=1 ignores accept_ra unless it is 2.
lan_if="${MERIDIAN_LAN_IF:-eth0}"
if [[ -d "/proc/sys/net/ipv6/conf/${lan_if}" ]]; then
  cat >> /etc/sysctl.d/99-meridian.conf <<EOF
net.ipv4.conf.${lan_if}.rp_filter=2
net.ipv4.conf.${lan_if}.send_redirects=0
net.ipv6.conf.${lan_if}.accept_ra=2
net.ipv6.conf.${lan_if}.forwarding=1
EOF
fi
sysctl --system >/dev/null

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
apt-get install -y docker.io docker-compose wireguard-tools nftables iproute2 curl ca-certificates
systemctl enable --now docker

echo
echo "主机准备完成。下一步："
echo "  sudo docker compose -f deploy/docker-compose.yml up -d --build"
echo "  浏览器打开 http://192.168.100.88:8787"
echo "不要把真实端点或私钥提交进仓库。"
