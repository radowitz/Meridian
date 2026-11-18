#!/bin/bash
# Prepare a fresh Debian host to run Meridian beside ROS and mihomo, or
# upgrade an existing install in place.
# It does not change RouterOS, does not stop mihomo, and does not start DHCP or radvd.
#
# Two modes, chosen from the host's state (never from a flag):
#
#   prepare  No Meridian data plane is installed on this host yet
#            (/usr/local/sbin/meridian-up.sh is not an executable file or
#            /etc/systemd/system/meridian.service is missing). The script
#            writes the boot-time sysctls, applies them, and leaves IPv4 and
#            IPv6 forwarding OFF: they are only turned on by meridian-up.sh
#            after the panel's first install has loaded the firewall and guard.
#
#   upgrade  The panel has installed a data plane here (both files exist).
#            The script never writes a forwarding sysctl to the kernel and
#            never runs "sysctl --system". It replaces the meridian binary and
#            the three unit files, restarts meridian-host, and then:
#              - data plane active before and forwarding on (v4 and v6):
#                "meridian host-restore" checks it through meridian-host
#                (meridian.service active, both nft tables, forwarding on) and
#                re-activates it through the same agent action the panel uses
#                if the check fails;
#              - data plane active but forwarding not fully on: health check
#                only, nothing is (re)started;
#              - data plane not active before: left as it was (forwarding is
#                not turned on); the summary says how to start it.
#            If meridian-host or the restore fails, the previous binary and
#            unit files are put back, meridian-host is restarted on them, and
#            forwarding that was off before is switched off again. The script
#            then exits 1.
#
# In both modes a forwarding key that was 0 before the script ran is 0 when it
# ends (Docker's own start cannot leave it on).
#
# Usage (every option also has an environment variable; re-running with the
# same input changes nothing — credentials, topology, the agent token and the
# DoT certificate are never regenerated):
#
#   sudo bash deploy/debian/install.sh [options]
#     --lan-addr A        gateway LAN IPv4 the panel listens on   MERIDIAN_LAN_ADDR
#     --lan-if IF         LAN interface (default: the one with A) MERIDIAN_LAN_IF
#     --version V         pull <repo>:V (repo: MERIDIAN_IMAGE_REPO, default
#                         ghcr.io/${MERIDIAN_IMAGE_OWNER:-radowitz}/meridian) MERIDIAN_VERSION
#     --image REF         pull this exact image                   MERIDIAN_IMAGE
#     --image-tar FILE    load a "docker save" archive instead    MERIDIAN_IMAGE_TAR
#     --build             build meridian:local from this checkout (default
#                         when no image is given and deploy/.env names none)
#     --allow CIDR        extra source allowed to reach the panel port
#                         (repeatable; e.g. the remote-access pool)  MERIDIAN_MGMT_ALLOW (comma list)
#     --no-firewall       do not install the management firewall
#     --no-start          prepare only; do not start the panel container
#     --print-config      print the resolved settings and exit (no root needed)
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=deploy/debian/lib.sh
. "${here}/lib.sh"

opt_lan_addr="${MERIDIAN_LAN_ADDR:-}"
opt_lan_if="${MERIDIAN_LAN_IF:-}"
opt_version="${MERIDIAN_VERSION:-}"
opt_image="${MERIDIAN_IMAGE:-}"
opt_tar="${MERIDIAN_IMAGE_TAR:-}"
opt_build=0
opt_firewall=1
opt_start=1
opt_print=0
opt_allow=()
if [[ -n "${MERIDIAN_MGMT_ALLOW:-}" ]]; then
  IFS=, read -r -a opt_allow <<<"${MERIDIAN_MGMT_ALLOW}"
fi
need_val() { [[ $# -ge 2 && -n "$2" ]] || usage_die "$1 需要一个值（--help 查看用法）"; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --lan-addr) need_val "$@"; opt_lan_addr="$2"; shift 2 ;;
    --lan-if) need_val "$@"; opt_lan_if="$2"; shift 2 ;;
    --version) need_val "$@"; opt_version="$2"; shift 2 ;;
    --image) need_val "$@"; opt_image="$2"; shift 2 ;;
    --image-tar) need_val "$@"; opt_tar="$2"; shift 2 ;;
    --build) opt_build=1; shift ;;
    --allow) need_val "$@"; opt_allow+=("$2"); shift 2 ;;
    --no-firewall) opt_firewall=0; shift ;;
    --no-start) opt_start=0; shift ;;
    --print-config) opt_print=1; shift ;;
    -h|--help) sed -n '/^# Usage/,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *) usage_die "未知参数：$1（--help 查看用法）" ;;
  esac
done
if [[ -n "${opt_lan_addr}" ]] && ! valid_ipv4 "${opt_lan_addr}"; then
  usage_die "--lan-addr 必须是 IPv4 地址：${opt_lan_addr}"
fi
if [[ -n "${opt_lan_if}" ]] && ! valid_ifname "${opt_lan_if}"; then
  usage_die "--lan-if 不是合法的接口名：${opt_lan_if}"
fi
if [[ -n "${opt_version}" ]] && ! valid_version "${opt_version}"; then
  usage_die "--version 应形如 v1.2.3：${opt_version}"
fi
if [[ -n "${opt_image}" ]] && ! valid_image_ref "${opt_image}"; then
  usage_die "--image 不是合法的镜像名：${opt_image}"
fi
for c in "${opt_allow[@]+"${opt_allow[@]}"}"; do
  valid_cidr "${c}" || usage_die "--allow 需要 CIDR（如 10.8.0.0/24）：${c}"
done
n_src=0
[[ -n "${opt_tar}" ]] && n_src=$((n_src + 1))
[[ -n "${opt_image}" ]] && n_src=$((n_src + 1))
[[ -n "${opt_version}" ]] && n_src=$((n_src + 1))
[[ "${opt_build}" == 1 ]] && n_src=$((n_src + 1))
(( n_src <= 1 )) || usage_die "--image-tar、--image、--version、--build 只能选一个。"

repo="$(cd "${here}/../.." && pwd)"
envfile="${MERIDIAN_ENV_FILE:-${repo}/deploy/.env}"

# Image source, in order: archive, explicit image, version, local build,
# what deploy/.env already names (a re-run keeps the installed image), and
# finally the local build.
if [[ -n "${opt_tar}" ]]; then
  image_src=tar; image_ref=""
elif [[ -n "${opt_image}" ]]; then
  image_src=pull; image_ref="${opt_image}"
elif [[ -n "${opt_version}" ]]; then
  image_src=pull; image_ref="$(default_image_repo):${opt_version}"
elif [[ "${opt_build}" == 1 ]]; then
  image_src=build; image_ref="meridian:local"
elif [[ -n "$(env_get MERIDIAN_IMAGE "${envfile}")" ]]; then
  image_src=keep; image_ref="$(env_get MERIDIAN_IMAGE "${envfile}")"
else
  image_src=build; image_ref="meridian:local"
fi

if [[ "${opt_print}" == 1 ]]; then
  echo "lan_addr=${opt_lan_addr}"
  echo "lan_if=${opt_lan_if}"
  echo "image_source=${image_src}"
  echo "image=${image_ref}${opt_tar:+(from ${opt_tar})}"
  echo "firewall=${opt_firewall}"
  echo "allow=$(IFS=,; echo "${opt_allow[*]+"${opt_allow[*]}"}")"
  echo "start=${opt_start}"
  echo "env_file=${envfile}"
  exit 0
fi

require_root deploy/debian/install.sh
# One install, upgrade or rollback at a time (same lock as upgrade.sh and
# rollback.sh); without flock(1) the script stops here.
acquire_lock

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  if [[ "${VERSION_ID:-}" != "13" ]]; then
    echo "当前是 ${PRETTY_NAME:-未知系统}。Meridian 按 Debian 13 编写，其他版本请先核对内核 WireGuard 和 nftables。" >&2
  fi
fi

units=(meridian.service meridian-guard.service meridian-host.service)

# --- mode and the state to preserve ------------------------------------------
mode=prepare
if [[ -x /usr/local/sbin/meridian-up.sh && -f /etc/systemd/system/meridian.service ]]; then
  mode=upgrade
fi
fwd_read() { sysctl -n "$1" 2>/dev/null || echo 0; }
pre_fwd4="$(fwd_read net.ipv4.ip_forward)"
pre_fwd6="$(fwd_read net.ipv6.conf.all.forwarding)"
pre_active=0
if systemctl is-active --quiet meridian.service 2>/dev/null; then
  pre_active=1
fi
if [[ "${mode}" == upgrade ]]; then
  echo "检测到已有安装（meridian-up.sh 与 meridian.service 都在）：升级模式。数据面升级前 $([[ ${pre_active} == 1 ]] && echo 正在运行 || echo 未运行)，转发 IPv4=${pre_fwd4} IPv6=${pre_fwd6}；本脚本不会关闭它，也不会在原本关闭时打开。"
else
  echo "首次准备：本机还没有 Meridian 数据面。转发保持关闭，直到面板第一次「安装到本机」。"
fi

# off_unless_was_on: a forwarding key that was 0 when the script started is 0
# again. Used after anything (Docker) may have switched it on.
off_unless_was_on() {
  if [[ "${mode}" == prepare || "${pre_fwd4}" != 1 ]]; then
    sysctl -qw net.ipv4.ip_forward=0
  fi
  if [[ "${mode}" == prepare || "${pre_fwd6}" != 1 ]]; then
    sysctl -qw net.ipv6.conf.all.forwarding=0
  fi
}

# --- panel LAN address --------------------------------------------------------
# Never a built-in address. MERIDIAN_LAN_ADDR (the gateway's LAN IPv4) is
# confirmed by the operator; an existing deploy/.env keeps its MERIDIAN_BIND.
# Without either, the address the default route leaves from is offered as a
# candidate and must be confirmed on a terminal; otherwise the panel listens
# on 127.0.0.1:8787 only (reach it with ssh -L 8787:127.0.0.1:8787).
lan_addr="${opt_lan_addr}"
if [[ -z "${lan_addr}" && -f "${envfile}" ]] && grep -q '^MERIDIAN_BIND=' "${envfile}"; then
  lan_addr="$(sed -n 's/^MERIDIAN_BIND=\(.*\):[0-9]*$/\1/p' "${envfile}" | head -n1)"
fi
# An existing panel container keeps the address it listens on: its
# MERIDIAN_BIND, else the stored topology's panel_bind (asked from the panel
# binary itself, "meridian panel-bind"). Loopback is not written.
if [[ -z "${lan_addr}" ]] && command -v "${DOCKER}" >/dev/null 2>&1 && "${DOCKER}" info >/dev/null 2>&1; then
  if "${DOCKER}" compose version >/dev/null 2>&1; then
    compose_init "${repo}/deploy/docker-compose.yml"
    old_cid="$(panel_container || true)"
    if [[ -n "${old_cid}" ]]; then
      old_bind="$(container_env "${old_cid}" MERIDIAN_BIND)"
      [[ -n "${old_bind}" ]] || old_bind="$(panel_bind_of "${old_cid}" || true)"
      cand_addr="${old_bind%:*}"
      if [[ -n "${cand_addr}" && "${cand_addr}" != 127.* ]] && valid_ipv4 "${cand_addr}"; then
        lan_addr="${cand_addr}"
        echo "沿用现有面板的监听地址 ${old_bind}。"
      fi
    fi
  fi
fi
if [[ -z "${lan_addr}" ]]; then
  cand="$(ip -4 route get 192.0.2.1 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="src"){print $(i+1); exit}}')"
  if [[ -n "${cand}" && -t 0 ]]; then
    read -r -p "面板监听局域网地址 ${cand}:8787？[y/N] " ans || ans=""
    [[ "${ans}" == y || "${ans}" == Y ]] && lan_addr="${cand}"
  fi
fi
if [[ -n "${lan_addr}" ]]; then
  if ! ip -4 addr show | grep -q "inet ${lan_addr}/"; then
    echo "还没有 ${lan_addr}。请先把局域网口设成这个地址；面板会等它出现（MERIDIAN_BIND_WAIT）。" >&2
  fi
  env_set MERIDIAN_BIND "${lan_addr}:8787" "${envfile}"
  panel_url="http://${lan_addr}:8787"
else
  echo "没有确认的局域网地址：面板只监听 127.0.0.1:8787（升级时沿用已存拓扑的 panel_bind）。设置 MERIDIAN_LAN_ADDR=<局域网地址> 重新运行可改为监听局域网。"
  panel_url="http://127.0.0.1:8787（经 ssh -L 8787:127.0.0.1:8787 访问）"
fi

install -d /etc/sysctl.d /etc/nftables.d /etc/smartdns /etc/meridian/tls /etc/meridian/dns \
  /etc/iproute2/rt_tables.d /var/lib/meridian /usr/local/sbin
# WireGuard configs hold private keys: the directory is root-only, also when
# it already existed with the distribution's default mode.
install -d -m 0700 /etc/wireguard
chmod 0700 /etc/wireguard
# SmartDNS domain sets are shared host directories between the controller and
# the resolver container (see deploy/docker-compose.yml).
install -d /var/lib/meridian/geosite /var/lib/meridian/keywords
# Host-only list state (saved China lists, the chnroute copy meridian-up.sh
# re-adds on reload, status.json). Written by meridian-host's list action;
# not mounted into any container.
install -d -m 0755 /var/lib/meridian/lists
# The DNS query journal's audit directory (settings dns_log, off by default):
# the one directory mounted read-write into the resolver container. It must
# exist before that container is created, or Docker creates it 0755. Root
# only; empty while the journal is off.
install -d -m 0700 /var/lib/meridian-dnslog /var/lib/meridian-dnslog/raw
chmod 0700 /var/lib/meridian-dnslog /var/lib/meridian-dnslog/raw

# SLAAC client on the LAN NIC. forwarding=1 ignores accept_ra unless it is 2.
# Prefer the interface that has the confirmed LAN address; Debian 13 rarely names it eth0.
lan_if="${opt_lan_if}"
if [[ -z "${lan_if}" && -n "${lan_addr}" ]]; then
  lan_if="$(ip -o -4 addr show 2>/dev/null | awk -v a="${lan_addr}" 'index($4, a"/")==1{print $2; exit}')"
fi
lan_if="${lan_if:-eth0}"
echo "局域网接口：${lan_if}。面板拓扑的 settings.lan_interface 要和它一致（网关节点自己的 lan_interface 留空或填同一个名字，不同会被校验拒绝）。"

write_boot_sysctl() {
  # Forwarding stays OFF at boot: systemd-sysctl applies this file before the
  # nft guard exists. meridian-up.sh turns it on from
  # /etc/meridian/forwarding.conf only after the guard and ruleset are loaded.
  cat > /etc/sysctl.d/99-meridian.conf <<'EOF'
net.ipv4.ip_forward=0
net.ipv6.conf.all.forwarding=0
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
EOF
  if [[ -d "/proc/sys/net/ipv6/conf/${lan_if}" ]]; then
    cat >> /etc/sysctl.d/99-meridian.conf <<EOF
net.ipv4.conf.${lan_if}.rp_filter=2
net.ipv4.conf.${lan_if}.send_redirects=0
net.ipv6.conf.${lan_if}.accept_ra=2
net.ipv6.conf.${lan_if}.accept_redirects=0
EOF
  fi
}

if [[ "${mode}" == prepare ]]; then
  write_boot_sysctl
  # "all=0" does not clear a per-interface send_redirects that is still 1.
  for d in /proc/sys/net/ipv4/conf/*; do
    i="$(basename "$d")"
    sysctl -w "net.ipv4.conf.${i}.rp_filter=2" >/dev/null || true
    sysctl -w "net.ipv4.conf.${i}.send_redirects=0" >/dev/null || true
    sysctl -w "net.ipv4.conf.${i}.accept_redirects=0" >/dev/null || true
  done
  for d in /proc/sys/net/ipv6/conf/*; do
    i="$(basename "$d")"
    sysctl -w "net.ipv6.conf.${i}.accept_redirects=0" >/dev/null || true
  done
  sysctl --system >/dev/null || true
  off_unless_was_on
else
  # The panel's installs own 99-meridian.conf now. Only the boot-time
  # forwarding lines are corrected in the file (an older version may have
  # written =1); nothing is applied to the running kernel.
  if [[ ! -f /etc/sysctl.d/99-meridian.conf ]]; then
    write_boot_sysctl
  elif grep -qE '^[[:space:]]*net\.(ipv4\.ip_forward|ipv6\.conf\.all\.forwarding)[[:space:]]*=[[:space:]]*1' /etc/sysctl.d/99-meridian.conf; then
    sed -i -E 's/^[[:space:]]*(net\.(ipv4\.ip_forward|ipv6\.conf\.all\.forwarding))[[:space:]]*=[[:space:]]*1[[:space:]]*$/\1=0/' /etc/sysctl.d/99-meridian.conf
    echo "已把 /etc/sysctl.d/99-meridian.conf 里开机即打开转发的行改成 0（只改文件，运行中的转发不变）。"
  fi
fi

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

# Docker's settings must be in place BEFORE the package is installed: apt
# starts dockerd right away, and with default settings it switches IPv4
# forwarding on and sets the iptables FORWARD policy to DROP, which
# black-holes the gateway until the next reboot. Host networking does not
# need Docker's FORWARD rules. "ip-forward": false keeps dockerd from turning
# forwarding on at boot before Meridian's guard.
daemon_written=0
if [[ ! -f /etc/docker/daemon.json ]]; then
  install -d /etc/docker
  cat > /etc/docker/daemon.json <<'EOF'
{
  "iptables": false,
  "ip6tables": false,
  "ip-forward": false
}
EOF
  daemon_written=1
else
  echo "已有 /etc/docker/daemon.json，未改动。若其中 iptables 不是 false，Docker 可能把转发策略改成 DROP，网关会丢包；若没有 \"ip-forward\": false，dockerd 会在开机时先打开转发（meridian-guard.service 仍会先挡住局域网转发）。" >&2
fi
docker_was_active=0
if systemctl is-active --quiet docker 2>/dev/null; then
  docker_was_active=1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
compose_pkg="docker-compose"
if apt-cache show docker-compose-v2 >/dev/null 2>&1; then
  # Debian 13 ships the v2 plugin here. The Python v1 package does not
  # provide `docker compose`, which is what the Compose file needs.
  compose_pkg="docker-compose-v2"
fi
apt-get install -y docker.io "${compose_pkg}" wireguard-tools nftables iproute2 conntrack curl ca-certificates openssl
# SmartDNS refuses to start if bind-cert-file / bind-cert-key-file point at a
# missing certificate. The name will not match what clients dial; strict DoT
# fails closed and falls back to the hijacked port 53. Generated only when absent.
if [[ ! -s /etc/meridian/dns/cert.pem ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /etc/meridian/dns/key.pem \
    -out /etc/meridian/dns/cert.pem \
    -days 3650 -subj "/CN=meridian.lan"
  chmod 600 /etc/meridian/dns/key.pem /etc/meridian/dns/cert.pem
fi
systemctl enable docker
# A first-time host restarts Docker so the settings above are certainly in
# effect. On an upgrade Docker (and with it the panel and SmartDNS
# containers) is only restarted when its settings were just written or it
# was not running.
if [[ "${mode}" == prepare || "${daemon_written}" == 1 || "${docker_was_active}" == 0 ]]; then
  systemctl restart docker
fi
# Docker may have switched forwarding on while starting with older settings.
off_unless_was_on

# A FORWARD policy of DROP left in the iptables filter tables by an earlier
# dockerd start drops every packet Meridian forwards. Nothing in Meridian
# clears it on purpose (it may belong to someone else); a reboot does, as
# dockerd no longer creates it with "iptables": false.
need_reboot=0
check_forward_policy() {
  local tool="$1" rules
  command -v "${tool}" >/dev/null 2>&1 || return 0
  rules="$("${tool}" -S FORWARD 2>/dev/null || true)"
  if [[ "${rules}" == *"-P FORWARD DROP"* ]]; then
    need_reboot=1
    echo "!!! ${tool}：filter 表的 FORWARD 策略是 DROP（通常是 Docker 先前以默认设置启动时留下的）。它会丢掉 Meridian 转发的全部流量。" >&2
    echo "!!! 重启本机即可清除（daemon.json 已设 iptables/ip6tables=false，Docker 不会再建它）；确认没有别的程序依赖它时，也可手动执行 ${tool} -P FORWARD ACCEPT。" >&2
  fi
}
check_forward_policy iptables
check_forward_policy ip6tables

if docker compose version >/dev/null 2>&1; then
  compose=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  compose=(docker-compose)
else
  echo "没有找到 docker compose。" >&2
  exit 1
fi

# meridian-host: the only way the panel starts, checks and removes host
# runtime (fixed actions, validated names, root-only socket + token). Its
# binary is the same meridian build, copied out of the panel image to
# /usr/local/bin, which the panel container cannot write.
#
# The gateway's own traffic leaves through ROS on the domestic line, so it
# often cannot reach Docker Hub or proxy.golang.org and a local build times
# out. The image therefore comes from (see the options at the top):
#   tar    a "docker save" archive built elsewhere (docs/user/install.md);
#   pull   a prebuilt image (<repo>:<version> or --image); a failed pull
#          says what to do instead and never claims the image is published;
#   keep   the image deploy/.env already names (a re-run);
#   build  docker compose build from this checkout (tagged meridian:local).
case "${image_src}" in
  tar)
    image_ref="$(load_image_tar "${opt_tar}")"
    ;;
  pull)
    pull_image "${image_ref}"
    ;;
  keep)
    if ! "${DOCKER}" image inspect "${image_ref}" >/dev/null 2>&1; then
      if [[ "${image_ref}" == meridian:local ]]; then
        MERIDIAN_IMAGE="${image_ref}" "${compose[@]}" -f "${repo}/deploy/docker-compose.yml" build meridian
      else
        pull_image "${image_ref}"
      fi
    fi
    ;;
  build)
    MERIDIAN_IMAGE=meridian:local "${compose[@]}" -f "${repo}/deploy/docker-compose.yml" build meridian
    ;;
esac
check_image_arch "${image_ref}"
env_set MERIDIAN_IMAGE "${image_ref}" "${envfile}"
echo "面板镜像：${image_ref}（已写入 ${envfile}）"

# Keep what is being replaced, so a failed upgrade can go back to it.
bak=/var/lib/meridian-host/upgrade-backup
install -d -m 0700 /var/lib/meridian-host
rm -rf "${bak}"
install -d -m 0700 "${bak}"
if [[ -f /usr/local/bin/meridian ]]; then
  cp -p /usr/local/bin/meridian "${bak}/meridian"
fi
for u in "${units[@]}"; do
  if [[ -f "/etc/systemd/system/${u}" ]]; then
    cp -p "/etc/systemd/system/${u}" "${bak}/${u}"
  fi
done

# rollback_upgrade: previous binary and unit files back, meridian-host on
# them, no forwarding that was off before. Exits 1.
in_rollback=0
rollback_upgrade() {
  if [[ "${in_rollback}" == 1 ]]; then
    return 0
  fi
  in_rollback=1
  trap - ERR
  set +e
  echo "升级失败：$1" >&2
  echo "恢复升级前的 meridian 二进制和 unit 文件……" >&2
  if [[ -f "${bak}/meridian" ]]; then
    install -m 0755 -o root -g root "${bak}/meridian" /usr/local/bin/meridian
  fi
  for u in "${units[@]}"; do
    if [[ -f "${bak}/${u}" ]]; then
      install -m 644 "${bak}/${u}" "/etc/systemd/system/${u}"
    fi
  done
  systemctl daemon-reload || true
  systemctl restart meridian-host.service || echo "旧版 meridian-host 也没有启动：journalctl -u meridian-host" >&2
  if [[ "${pre_active}" == 1 ]] && ! systemctl is-active --quiet meridian.service; then
    # The data plane was running before; bring it back on the previous
    # units (meridian.service runs the same meridian-up.sh as at boot).
    systemctl reset-failed meridian.service >/dev/null 2>&1 || true
    systemctl restart meridian.service || echo "meridian.service 仍未恢复：journalctl -u meridian.service（局域网兜底表保持 fail-closed）" >&2
  fi
  off_unless_was_on
  echo "数据面：$(systemctl is-active meridian.service 2>/dev/null || true)；转发 IPv4=$(fwd_read net.ipv4.ip_forward) IPv6=$(fwd_read net.ipv6.conf.all.forwarding)（升级前 ${pre_fwd4}/${pre_fwd6}）。" >&2
  exit 1
}

if [[ "${mode}" == upgrade ]]; then
  # Any failing command from here on puts the previous version back.
  trap 'rollback_upgrade "命令失败（install.sh 第 ${LINENO} 行）"' ERR
fi

cid="$(docker create "${image_ref}")"
trap 'docker rm -f "${cid}" >/dev/null 2>&1 || true' EXIT
docker cp "${cid}:/usr/local/bin/meridian" /usr/local/bin/.meridian.new
install -m 0755 -o root -g root /usr/local/bin/.meridian.new /usr/local/bin/meridian
rm -f /usr/local/bin/.meridian.new
install -d -m 0700 /etc/meridian-host /run/meridian-host
if [[ ! -s /etc/meridian-host/agent.token ]]; then
  (umask 077 && openssl rand -hex 32 > /etc/meridian-host/agent.token)
fi
chmod 600 /etc/meridian-host/agent.token

for u in "${units[@]}"; do
  install -m 644 "${here}/${u}" "/etc/systemd/system/${u}"
done
systemctl daemon-reload
# meridian.service is started by the first install from the panel (through
# meridian-host), not here: before that there is no meridian-up.sh. On an
# upgrade a running meridian.service is not restarted by daemon-reload.
systemctl enable meridian.service meridian-guard.service
systemctl enable meridian-host.service
systemctl restart meridian-host.service
if ! systemctl is-active --quiet meridian-host.service; then
  if [[ "${mode}" == upgrade ]]; then
    rollback_upgrade "新版 meridian-host 没有启动（journalctl -u meridian-host）"
  fi
  echo "meridian-host 没有启动，面板将无法安装到本机：journalctl -u meridian-host" >&2
  exit 1
fi

# --- management firewall ------------------------------------------------------
# Panel port 8787/tcp only from lo, the LAN interface with a LAN source
# address (both must match), the remote-access interface and --allow sources,
# IPv4 and IPv6, including connections Docker would DNAT to it. Its own
# table (inet meridian_mgmt), loaded at boot before Docker; SSH and other
# tables are never touched. The rules file is root-only and outside every
# directory the panel container can write.
if [[ "${opt_firewall}" == 1 ]]; then
  fw_if=""
  [[ -n "${lan_addr}" ]] && fw_if="${lan_if}"
  install -d -m 0700 /etc/meridian-host
  fw_src="$(lan_sources "${fw_if}")"
  if [[ -n "${fw_if}" && "${fw_src}" != *.* ]]; then
    echo "${fw_if} 上还没有 IPv4 网段：管理防火墙暂时只放行它的 IPv6 局域网来源。设好局域网地址后重新运行本脚本（或用 --allow 加来源）。" >&2
  fi
  if ! mgmt_firewall_install 8787 "${fw_if}" "${fw_src}" "${opt_allow[@]+"${opt_allow[@]}"}"; then
    # Never let the panel listen without the source filter it was promised:
    # stop here, before the panel container is (re)started. A fresh host
    # has no panel running yet; an upgrade puts the previous version back
    # (its management firewall, if any, stays loaded as it was).
    if [[ "${mode}" == upgrade ]]; then
      rollback_upgrade "管理防火墙规则没有通过 nft -c 检查"
    fi
    # A panel container left from an earlier run is stopped too.
    "${compose[@]}" -f "${repo}/deploy/docker-compose.yml" stop meridian >/dev/null 2>&1 || true
    die "管理防火墙规则没有通过 nft -c 检查（输出见上），安装中止，面板没有启动（已有的面板容器已停止）。修好原因后重新运行本脚本；确实不需要时可加 --no-firewall（面板端口的访问控制由你自己负责）。"
  fi
  echo "管理防火墙：8787/tcp 只接受 lo${fw_if:+、${fw_if} 上来自 ${fw_src} 的连接}、远程接入接口 mra${opt_allow[*]+、${opt_allow[*]}}（IPv4+IPv6，含 Docker 端口转发；局域网网卡上的其他来源，例如主路由器转发进来的公网连接，一律丢弃）。"
else
  echo "按 --no-firewall 跳过管理防火墙。面板端口的访问控制需要你自己负责。" >&2
fi

restore_note=""
if [[ "${mode}" == upgrade ]]; then
  # Give the agent a moment to create its socket.
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    [[ -S /run/meridian-host/agent.sock ]] && break
    sleep 1
  done
  if [[ "${pre_active}" == 1 && "${pre_fwd4}" == 1 && "${pre_fwd6}" == 1 ]]; then
    if ! /usr/local/bin/meridian host-restore; then
      rollback_upgrade "升级后数据面检查/重新激活失败（输出见上）"
    fi
    for key in net.ipv4.ip_forward net.ipv6.conf.all.forwarding; do
      if [[ "$(fwd_read "${key}")" != 1 ]]; then
        rollback_upgrade "${key} 升级前是 1，现在不是"
      fi
    done
    restore_note="数据面已经 meridian-host 检查（必要时重新激活），双栈转发保持打开。"
  elif [[ "${pre_active}" == 1 ]]; then
    if ! /usr/local/bin/meridian host-restore --health-only; then
      rollback_upgrade "升级后数据面健康检查失败（输出见上）"
    fi
    restore_note="数据面健康；升级前转发不是双栈全开（IPv4=${pre_fwd4} IPv6=${pre_fwd6}），未做改动。"
  else
    restore_note="数据面升级前没有运行，保持原状（转发未打开）。在面板「安装到本机」，或修好原因后 sudo systemctl restart meridian.service。"
  fi
  off_unless_was_on
  trap - ERR
fi
rm -rf "${bak}"

echo
if [[ "${mode}" == upgrade ]]; then
  echo "宿主部分升级完成（meridian-host 已运行）。${restore_note}"
else
  echo "主机准备完成（meridian-host 已运行）。"
fi
if [[ "${opt_start}" == 1 ]]; then
  # (Re)create the panel container on the chosen image; the data plane is
  # not touched. Same image and settings: compose leaves it running as is.
  "${compose[@]}" -f "${repo}/deploy/docker-compose.yml" up -d --no-build meridian
  compose_init "${repo}/deploy/docker-compose.yml"
  new_cid="$(panel_container)"
  if [[ -z "${new_cid}" ]] || ! health_wait "${new_cid}" "${MERIDIAN_HEALTH_TIMEOUT:-90}"; then
    echo "面板容器没有通过健康检查：sudo ${compose[*]} -f deploy/docker-compose.yml logs meridian" >&2
    exit 1
  fi
  # The DNS split resolver (compose profile "dns"): created on a fresh
  # install, started now when its config exists; a stopped one is started
  # when its config exists; a running one is kept; a host smartdns.service
  # takes precedence (lib.sh smartdns_ensure).
  smartdns_ensure || exit 1
else
  echo "按 --no-start 未启动面板。启动：sudo ${compose[*]} -f deploy/docker-compose.yml up -d --no-build"
fi
if [[ "${mode}" == prepare ]]; then
  echo "下一步："
  echo "  1. 生成一次性初始化码（只显示在你的终端里，1 小时有效）："
  echo "       sudo ${compose[*]} -f deploy/docker-compose.yml exec meridian meridian setup-code"
  echo "  2. 浏览器打开 ${panel_url}，用初始化码创建管理员。"
  echo "  3. 面板里「安装到本机」经 meridian-host 完成 daemon-reload、启动 meridian.service 与相关服务（含 SmartDNS 容器 meridian-smartdns）并做健康检查，任一步失败即停止并补偿。"
fi
echo "以后升级/回滚：sudo bash deploy/debian/upgrade.sh <版本>；sudo bash deploy/debian/rollback.sh（见 docs/user/upgrade-rollback.md）。"
# Servers, SSH credentials and Cloudflare accounts live in the panel's own
# named volume meridian-secrets (deploy/docker-compose.yml), created by
# Docker on "up"; nothing on the host is written for them and the data
# plane is not touched. An upgraded panel moves the old Mesh credential
# file and the topology's SSH targets into it on its first start.
echo "服务器、SSH 凭据和 Cloudflare 账户保存在面板的命名卷 meridian-secrets 里（目录 0700、文件 0600，不进快照）。"
if [[ "${mode}" == upgrade ]]; then
  echo "  面板重建后第一次启动会把旧的 Mesh 凭据和拓扑里的 SSH 地址迁移进去（可重复执行，不影响数据面）。"
fi
echo "  （Compose 给卷名加项目前缀，可用 docker volume ls 查看；备份它时按私钥对待。）"
echo "不要把真实端点或私钥提交进仓库。"
if [[ "${need_reboot}" == 1 ]]; then
  echo >&2
  echo "!!! 注意：FORWARD 策略仍是 DROP（见上）。在它清除之前，网关不会转发任何 IPv4 流量。请先重启本机再在面板里安装。" >&2
fi
