package compile

import (
	"fmt"
	"strings"

	"github.com/radowitz/meridian/internal/artifacts"
)

// Alpine exits (model.OSAlpine) run under OpenRC. Their two services are the
// systemd units' counterparts under the same names without ".service":
// /etc/init.d/meridian-node runs meridian-up.sh at boot and
// /etc/init.d/meridian-smartdns supervises the exit resolver. Manifests,
// footprints and the provision/withdraw scripts keep naming them by the
// systemd unit name; ServiceShim maps those calls onto OpenRC on the host.

// OpenRCPath is the bundle path of the OpenRC script for a unit name
// ("meridian-node.service" → "etc/init.d/meridian-node").
func OpenRCPath(unit string) string {
	return "etc/init.d/" + strings.TrimSuffix(unit, ".service")
}

func renderNodeOpenRC() string {
	return `#!/sbin/openrc-run
# Meridian node data plane at boot (meridian-up.sh), OpenRC.
description="Meridian node data plane restore (meridian-up.sh)"

depend() {
	need localmount
	after net networking firewall nftables
}

start() {
	ebegin "Restoring the Meridian data plane"
	/usr/local/sbin/meridian-up.sh >/var/log/meridian-node.log 2>&1
	eend $? "meridian-up.sh failed (see /var/log/meridian-node.log)"
}

stop() {
	return 0
}
`
}

func renderSmartDNSOpenRC() string {
	return fmt.Sprintf(`#!/sbin/openrc-run
# Meridian exit resolver (panel-delivered SmartDNS %s), OpenRC.
description="Meridian exit resolver (SmartDNS bound to tunnel addresses only)"
supervisor=supervise-daemon
command=%s
command_args="-f -x -p - -c /etc/smartdns/smartdns.conf"
respawn_delay=5
respawn_max=0
output_log=/dev/null
error_log=/var/log/meridian-smartdns.log

depend() {
	after meridian-node
}

start_pre() {
	# Keep the error log small on hosts with little disk.
	if [ -f /var/log/meridian-smartdns.log ] && [ "$(wc -c < /var/log/meridian-smartdns.log)" -gt 1048576 ]; then
		tail -c 131072 /var/log/meridian-smartdns.log > /var/log/meridian-smartdns.log.new && mv -f /var/log/meridian-smartdns.log.new /var/log/meridian-smartdns.log
	fi
	return 0
}
`, artifacts.Version(artifacts.SmartDNS), artifacts.HostPath(artifacts.SmartDNS))
}

// smartDNSRestartOpenRC is meridian-up.sh's resolver restart on an Alpine
// exit: the resolver binds tunnel addresses that exist only now.
const smartDNSRestartOpenRC = `if [ -f /etc/smartdns/smartdns.conf ] && command -v rc-service >/dev/null 2>&1; then
  if [ -x /etc/init.d/meridian-smartdns ]; then
    # Into the default runlevel only when it is in none (a runlevel the
    # operator chose stays as it is).
    m_l=""
    for m_r in /etc/runlevels/*/meridian-smartdns; do [ -L "$m_r" ] && [ -e "$m_r" ] && m_l=1; done
    [ -n "$m_l" ] || rc-update add meridian-smartdns default >/dev/null 2>&1 || true
    rc-service meridian-smartdns restart >/dev/null 2>&1 || echo "meridian-smartdns restart failed; exit resolver is down" >&2
  else
    echo "meridian-smartdns is not installed; exit resolver is down" >&2
  fi
fi
`

// ServiceShim is shell (bash) for the provision and withdraw scripts. On an
// Alpine host (/etc/alpine-release) without systemd but with OpenRC it defines a
// systemctl function that maps the scripts' calls onto OpenRC services named
// like the unit without ".service" (enable/disable [--now], start, stop,
// restart, try-restart, is-active, is-enabled, status, cat; daemon-reload
// and show are no-ops). A unit with no OpenRC script is inactive and not
// enabled. Paths are under $M_ROOT (empty on a host; tests point it at a
// sandbox). On systemd hosts it defines nothing but m_has_init, so their
// scripts run exactly as before. m_has_init: the host has an init system
// the scripts can drive.
const ServiceShim = `M_OPENRC=0
M_NOINIT=0
if [ -f "${M_ROOT:-}/etc/alpine-release" ] && ! { [ -d "${M_ROOT:-}/run/systemd/system" ] && command -v systemctl >/dev/null 2>&1; } && ! { command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1; }; then
  # Alpine without OpenRC's tools: services can be neither driven nor
  # checked. The scripts refuse before changing anything.
  M_NOINIT=1
fi
if [ -f "${M_ROOT:-}/etc/alpine-release" ] && ! { [ -d "${M_ROOT:-}/run/systemd/system" ] && command -v systemctl >/dev/null 2>&1; } && command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1; then
  M_OPENRC=1
  m_rc_name() { case "$1" in *.service) printf '%s' "${1%.service}" ;; *) return 1 ;; esac; }
  m_rc_up() { rc-service "$1" status >/dev/null 2>&1; }
  # Runlevel membership is a symbolic link (a plain file there is not
  # Meridian's and is never touched). Meridian adds its services to the
  # default runlevel only when no runlevel starts them; a link in another
  # runlevel is the operator's and is left alone. A link counts as starting
  # the service only when it resolves (OpenRC skips a dead one at boot).
  m_rc_live() { local t; [ -L "$1" ] || return 1; [ -e "$1" ] && return 0; t=$(readlink -- "$1"); case "$t" in /*) [ -e "${M_ROOT:-}$t" ] ;; *) return 1 ;; esac; }
  m_rc_default() { [ -L "${M_ROOT:-}/etc/runlevels/default/$1" ]; }
  m_rc_any() { local l; for l in "${M_ROOT:-}"/etc/runlevels/*/"$1"; do m_rc_live "$l" && return 0; done; return 1; }
  m_rc_link() { local l; for l in "${M_ROOT:-}"/etc/runlevels/*/"$1"; do [ -L "$l" ] && return 0; done; return 1; }
  systemctl() {
    local quiet=0 now=0 op="" u r rc=0 has
    local -a units=()
    while [ $# -gt 0 ]; do
      case "$1" in
        -q|--quiet) quiet=1 ;;
        --now) now=1 ;;
        -p) shift ;;
        -*) ;;
        *) if [ -z "$op" ]; then op=$1; else units+=("$1"); fi ;;
      esac
      shift
    done
    case "$op" in daemon-reload|reset-failed) return 0 ;; esac
    for u in "${units[@]}"; do
      if ! r=$(m_rc_name "$u"); then
        case "$op" in
          is-active) [ "$quiet" = 1 ] || echo inactive; rc=3 ;;
          is-enabled) [ "$quiet" = 1 ] || echo not-found; rc=1 ;;
          disable|stop|try-restart|show) ;;
          *) echo "systemctl (OpenRC): no service for $u" >&2; rc=5 ;;
        esac
        continue
      fi
      has=0; [ -x "${M_ROOT:-}/etc/init.d/$r" ] && has=1
      case "$op" in
        enable)
          if [ "$has" = 0 ]; then echo "systemctl (OpenRC): no service for $u" >&2; rc=5; continue; fi
          if ! m_rc_any "$r"; then
            # A dead default link (left by a removed script) is replaced.
            if m_rc_default "$r"; then rc-update del "$r" default >/dev/null 2>&1 || rm -f -- "${M_ROOT:-}/etc/runlevels/default/$r"; fi
            rc-update add "$r" default >/dev/null 2>&1 || true
            m_rc_any "$r" || rc=1
          fi
          if [ "$now" = 1 ] && ! m_rc_up "$r"; then rc-service "$r" start >/dev/null 2>&1 || rc=1; fi ;;
        disable)
          # Also a dead link (its script already gone) is taken out.
          if m_rc_default "$r"; then
            rc-update del "$r" default >/dev/null 2>&1 || rm -f -- "${M_ROOT:-}/etc/runlevels/default/$r"
            if m_rc_default "$r"; then rc=1; fi
          fi
          if [ "$now" = 1 ] && [ "$has" = 1 ] && m_rc_up "$r"; then rc-service "$r" stop >/dev/null 2>&1 || rc=1; fi ;;
        is-enabled) if m_rc_any "$r"; then [ "$quiet" = 1 ] || echo enabled; else [ "$quiet" = 1 ] || echo disabled; rc=1; fi ;;
        is-active) if [ "$has" = 1 ] && m_rc_up "$r"; then [ "$quiet" = 1 ] || echo active; else [ "$quiet" = 1 ] || echo inactive; rc=3; fi ;;
        stop|try-restart|show) if [ "$has" = 1 ] && m_rc_up "$r"; then case "$op" in stop) rc-service "$r" stop >/dev/null 2>&1 || rc=1 ;; try-restart) rc-service "$r" restart >/dev/null 2>&1 || rc=1 ;; esac; fi ;;
        *)
          if [ "$has" = 0 ]; then echo "systemctl (OpenRC): no service for $u" >&2; rc=5; continue; fi
          case "$op" in
            start) m_rc_up "$r" || rc-service "$r" start >/dev/null 2>&1 || rc=1 ;;
            restart) rc-service "$r" restart >/dev/null 2>&1 || rc=1 ;;
            status) rc-service "$r" status || rc=3 ;;
            cat) cat "${M_ROOT:-}/etc/init.d/$r" ;;
            *) echo "systemctl (OpenRC): $op is not supported" >&2; rc=1 ;;
          esac ;;
      esac
    done
    return "$rc"
  }
fi
m_has_init() { { [ -d "${M_ROOT:-}/run/systemd/system" ] && command -v systemctl >/dev/null 2>&1; } || [ "$M_OPENRC" = 1 ]; }
# m_unit_linked UNIT: an OpenRC service of UNIT still has a link in some
# runlevel (its script must stay so the link can be removed). Never on
# systemd hosts.
m_unit_linked() { [ "$M_OPENRC" = 1 ] && m_rc_link "${1%.service}"; }
# m_init_refuse prints why the host's services cannot be driven ("" when
# they can): an Alpine host without rc-service / rc-update.
m_init_refuse() { [ "$M_NOINIT" = 1 ] && echo 'this Alpine host has no rc-service / rc-update (OpenRC): its services can be neither changed nor checked'; return 0; }
# m_openrc_nft_flush: an enabled or running OpenRC nftables service. Its
# ruleset (with whatever it includes) and its stop action are not checked
# one by one: Alpine's flushes the whole ruleset, Meridian's tables with it.
m_openrc_nft_flush() {
  [ "$M_OPENRC" = 1 ] && [ -x "${M_ROOT:-}/etc/init.d/nftables" ] || return 1
  # Anything under that name in a runlevel (OpenRC lists the names, a
  # plain file too), or running.
  local l
  for l in "${M_ROOT:-}"/etc/runlevels/*/nftables; do { [ -e "$l" ] || [ -L "$l" ]; } && return 0; done
  m_rc_up nftables
}
`
