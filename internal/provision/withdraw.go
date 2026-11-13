package provision

import (
	"fmt"
	"strings"

	"github.com/radowitz/meridian/internal/preflight"
)

// Remote node withdraw ("撤回"). One fixed, reviewed script; only the
// validated values of WithdrawOptions are placed into it (as single-quoted
// shell assignments at the top). It reads what to remove from the host
// itself, never from the request:
//
//   - mode "manifest": the ownership manifest a successful provision left
//     at /var/lib/meridian/node/manifest. The manifest must name this node,
//     this panel deployment and this server; every entry is re-validated
//     in the script (interface, unit, nft table, route table and path
//     patterns) and an entry it does not recognise refuses the whole run.
//     Units are disabled and stopped, the Mesh sidecar compose project (if
//     the manifest has its file) is brought down, interfaces deleted, the
//     rules pointing at the manifest's route tables deleted and the tables
//     flushed, the main-table blackhole routes the manifest records deleted,
//     the nft tables deleted, and every listed file removed only when its
//     SHA-256 still matches the manifest (a file changed since the install
//     is kept and reported). SmartDNS is stopped and disabled only when the
//     manifest records that Meridian installed the package. Packages, the
//     runtime sysctl values and everything not in the manifest (Docker,
//     other WireGuard interfaces, WARP, other nft tables, other files) are
//     kept. The manifest is deleted only when nothing is left; the journal
//     then says "withdrawn" and a second run answers "already withdrawn".
//     A run that leaves something is "withdraw_incomplete" and can be
//     repeated (roll-forward: what is gone is skipped).
//   - mode "journal": recovery of an interrupted provision run (journal
//     "running" or "incomplete"). The run's work directory holds what it did
//     (actions, backups, pre-* state, params); the script runs the same
//     compensation as a failed provision (compensateLib). A run that never
//     got past opening its journal changed nothing and is just closed.
//   - mode "legacy": a host provisioned by a version without manifests.
//     Only well-known Meridian paths and names are considered: WireGuard
//     configs /etc/wireguard/mNN[w].conf, meridian-*/wstunnel-meridian*/
//     wstunnel-client-* unit files, /usr/local/sbin/meridian-*,
//     /etc/nftables.d/meridian*.nft, /etc/sysctl.d/99-meridian.conf,
//     /etc/iproute2/rt_tables.d/meridian.conf, /etc/smartdns/smartdns.conf
//     (each only with "meridian" in its first 12 lines) and the files of
//     /etc/meridian; interfaces only of such configs, nft tables only as
//     declared in such an nft file, route tables only as listed in such an
//     rt_tables file. Blackhole routes of the old version are not known and
//     are reported, not guessed.
//
// Every mode has two actions. "plan" is read-only: it prints what would be
// removed (MERIDIAN_PLAN …) and a digest of the state it was computed from
// (MERIDIAN_PLAN_DIGEST). "run" recomputes that digest and refuses
// (plan_changed) unless it equals the one the operator confirmed.
//
// Output markers: MERIDIAN_REFUSED <code>, MERIDIAN_OWNER, MERIDIAN_PLAN,
// MERIDIAN_PLAN_DIGEST, MERIDIAN_REMOVED, MERIDIAN_KEPT, MERIDIAN_LEFTOVER,
// MERIDIAN_WITHDRAW_OK / _PARTIAL / _ALREADY, MERIDIAN_COMPENSATED /
// MERIDIAN_COMPENSATION_INCOMPLETE / MERIDIAN_RESTORED_PREVIOUS.

// Withdraw modes and actions.
const (
	WithdrawManifest = "manifest"
	WithdrawJournal  = "journal"
	WithdrawLegacy   = "legacy"

	WithdrawPlan = "plan"
	WithdrawRun  = "run"
)

// WithdrawOptions is everything that varies between withdraw scripts.
type WithdrawOptions struct {
	NodeID     string
	Deployment string
	ServerID   string
	Run        string
	Mode       string
	Action     string
	// Digest is the plan digest the operator confirmed (run only).
	Digest string
}

// CheckWithdrawOptions validates every value placed into the script.
func CheckWithdrawOptions(o WithdrawOptions) error {
	for name, v := range map[string]string{"node": o.NodeID, "deployment": o.Deployment, "server": o.ServerID, "run": o.Run} {
		if !optRe.MatchString(v) {
			return fmt.Errorf("withdraw %s %q 不合法", name, v)
		}
	}
	switch o.Mode {
	case WithdrawManifest, WithdrawJournal, WithdrawLegacy:
	default:
		return fmt.Errorf("withdraw mode %q 不合法", o.Mode)
	}
	switch o.Action {
	case WithdrawPlan:
		if o.Digest != "" {
			return fmt.Errorf("withdraw plan 不带摘要")
		}
	case WithdrawRun:
		if !isHex64(o.Digest) {
			return fmt.Errorf("withdraw run 需要计划摘要")
		}
	default:
		return fmt.Errorf("withdraw action %q 不合法", o.Action)
	}
	return nil
}

func isHex64(s string) bool {
	return len(s) == 64 && strings.Trim(s, "0123456789abcdef") == ""
}

// WithdrawScript renders the fixed withdraw script. Invalid options give a
// script that refuses before doing anything.
func WithdrawScript(o WithdrawOptions) string {
	var sb strings.Builder
	sb.WriteString("#!/bin/bash\n# Meridian withdraw (fixed script; only the assignments below vary)\n")
	if err := CheckWithdrawOptions(o); err != nil {
		sb.WriteString("echo 'MERIDIAN_REFUSED bad_options'\necho 'meridian: withdraw script without valid options; refusing to run' >&2\nexit 3\n")
		return sb.String()
	}
	digest := o.Digest
	if digest == "" {
		digest = "-"
	}
	fmt.Fprintf(&sb, "M_NODE=%s\nM_DEPLOYMENT=%s\nM_SERVER=%s\nM_RUN=%s\nM_MODE=%s\nM_ACTION=%s\nM_DIGEST=%s\n",
		shellQuote(o.NodeID), shellQuote(o.Deployment), shellQuote(o.ServerID), shellQuote(o.Run), shellQuote(o.Mode), shellQuote(o.Action), shellQuote(digest))
	// The shared compensation helpers (journal mode) are only defined
	// here, never run on their own.
	sb.WriteString(compensateLib)
	sb.WriteString(withdrawBody)
	return sb.String()
}

// withdrawBody is the fixed part. M_ROOT is "" on a host (tests point it at
// a sandbox); it is never an option.
const withdrawBody = `set -o pipefail
umask 077
export LC_ALL=C
M_ROOT=''
M_STATE=$M_ROOT/var/lib/meridian/node
M_MANIFEST=$M_STATE/manifest
M_JOURNAL=$M_STATE/journal
M_LEFT=0
W_LEFTSET=' '
w_refuse() { echo "MERIDIAN_REFUSED $1"; echo "meridian: $2; nothing was changed" >&2; exit 3; }
[ "$(id -u)" = 0 ] || w_refuse not_root 'withdraw needs root'
w_sum() { sha256sum | cut -c1-64; }
w_jget() { sed -n "s/^$1 //p" "$M_JOURNAL" 2>/dev/null | head -n 1; }
w_mget() { sed -n "s/^$1 //p" "$M_MANIFEST" 2>/dev/null | head -n 1; }
# Patterns live in variables: the portable way to use [[ =~ ]].
W_RE_IFACE='^(m[0-9]{2,3}w?|mmesh|mmesh-c)$'
W_RE_UNIT='^(meridian-[a-z0-9][a-z0-9-]{0,40}|wstunnel-meridian|wstunnel-client-[a-z0-9][a-z0-9-]{0,40})[.](service|timer)$'
W_RE_NFT='^meridian(_[a-z0-9_]{1,30})?$'
W_RE_TABLE='^[0-9]{3}$'
W_RE_PRIO='^[0-9]{1,5}$'
W_RE_DST='^[0-9a-fA-F.:]{2,45}/[0-9]{1,3}$'
W_RE_PKG='^[a-z0-9][a-z0-9.+-]{0,40}$'
W_RE_HASH='^[0-9a-f]{64}$'
W_RE_PATH='^/(etc/wireguard|etc/nftables[.]d|etc/sysctl[.]d|etc/smartdns|etc/meridian|etc/systemd/system|etc/iproute2/rt_tables[.]d|usr/local/sbin)/[A-Za-z0-9._@+-][A-Za-z0-9._/@+-]{0,190}$'
W_RE_RUN='^[A-Za-z0-9._-]{1,64}$'
w_iface() { [[ $1 =~ $W_RE_IFACE ]]; }
w_unit() { [[ $1 =~ $W_RE_UNIT ]]; }
w_nft() { [[ $1 =~ $W_RE_NFT ]]; }
w_table() { [[ $1 =~ $W_RE_TABLE ]] && [ "$1" -ge 100 ] && [ "$1" -le 252 ]; }
w_prio() { [[ $1 =~ $W_RE_PRIO ]]; }
w_dst() { [[ $1 =~ $W_RE_DST ]]; }
w_pkg() { [[ $1 =~ $W_RE_PKG ]]; }
w_hash() { [[ $1 =~ $W_RE_HASH ]]; }
w_path() { [[ $1 =~ $W_RE_PATH ]] && [[ $1 != *..* ]] && [[ $1 != */ ]]; }
w_marked() { [ -f "$1" ] && [ ! -L "$1" ] && head -n 12 -- "$1" 2>/dev/null | grep -qi meridian; }
w_runid() { [[ $1 =~ $W_RE_RUN ]]; }
w_removed() { echo "MERIDIAN_REMOVED $*"; }
w_kept() { echo "MERIDIAN_KEPT $*"; }
w_left() {
  local k="$1:${2%% *}"
  case "$W_LEFTSET" in *" $k "*) return ;; esac
  W_LEFTSET="$W_LEFTSET$k "
  echo "MERIDIAN_LEFTOVER $*"
  printf 'leftover %s\n' "$*" >> "$M_JOURNAL"
  M_LEFT=1
}
w_unit_live() { systemctl is-active --quiet "$1" 2>/dev/null || systemctl is-enabled --quiet "$1" 2>/dev/null; }
w_has_link() { ip link show "$1" >/dev/null 2>&1; }
w_has_nft() { command -v nft >/dev/null 2>&1 && nft list table inet "$1" >/dev/null 2>&1; }
w_fam() { case "$1" in *:*) echo 6 ;; *) echo 4 ;; esac; }

# ---------------------------------------------------------------- inputs ---

# w_load_manifest reads and validates every manifest entry. An entry this
# script does not recognise refuses the whole withdraw.
W_FILES=(); W_HASHES=(); W_ORPHANS=(); W_IFACES=(); W_UNITS=(); W_NFTS=(); W_TABLES=(); W_DSTS=(); W_PKGS=()
w_load_manifest() {
  local kind a b rest bad=""
  while read -r kind a b rest; do
    case "$kind" in
      ''|meridian-node-manifest|node|deployment|server|bundle|installed) ;;
      file) if w_path "$a" && w_hash "$b"; then W_FILES+=("$a"); W_HASHES+=("$b"); else bad="$bad file"; fi ;;
      orphan) if w_path "$a"; then W_ORPHANS+=("$a"); else bad="$bad orphan"; fi ;;
      iface) if w_iface "$a"; then W_IFACES+=("$a"); else bad="$bad iface:$a"; fi ;;
      unit) if w_unit "$a"; then W_UNITS+=("$a"); else bad="$bad unit:$a"; fi ;;
      nft) if [ "$a" = inet ] && w_nft "$b"; then W_NFTS+=("$b"); else bad="$bad nft:$a/$b"; fi ;;
      table) if w_table "$a"; then W_TABLES+=("$a"); else bad="$bad table:$a"; fi ;;
      prio) w_prio "$a" || bad="$bad prio:$a" ;;
      route) if w_dst "$a"; then W_DSTS+=("$a"); else bad="$bad route:$a"; fi ;;
      pkg) if w_pkg "$a"; then W_PKGS+=("$a"); else bad="$bad pkg:$a"; fi ;;
      *) bad="$bad $kind" ;;
    esac
  done < "$M_MANIFEST"
  if [ -n "$bad" ]; then
    w_refuse bad_manifest_entry "the manifest has entries this withdraw does not accept ($(printf '%s' "$bad" | tr -cd 'A-Za-z0-9_:./ -' | head -c 200)); check $M_MANIFEST by hand"
  fi
}

w_has_pkg() { local p; for p in "${W_PKGS[@]}"; do [ "$p" = "$1" ] && return 0; done; return 1; }
w_has_file() { local p; for p in "${W_FILES[@]}"; do [ "$p" = "$1" ] && return 0; done; return 1; }

# w_legacy_scan prints the sorted list of what a legacy cleanup may remove.
w_legacy_scan() {
  local f n t
  {
    for f in "$M_ROOT"/etc/wireguard/*.conf; do
      n=${f##*/}; n=${n%.conf}
      if w_iface "$n" && w_marked "$f"; then echo "file /etc/wireguard/$n.conf"; echo "iface $n"; fi
    done
    for f in "$M_ROOT"/etc/systemd/system/*.service "$M_ROOT"/etc/systemd/system/*.timer; do
      n=${f##*/}
      if w_unit "$n" && w_marked "$f"; then echo "file /etc/systemd/system/$n"; echo "unit $n"; fi
    done
    for f in "$M_ROOT"/usr/local/sbin/meridian-*; do
      n=${f##*/}
      if w_path "/usr/local/sbin/$n" && w_marked "$f"; then echo "file /usr/local/sbin/$n"; fi
    done
    for f in "$M_ROOT"/etc/nftables.d/meridian*.nft; do
      n=${f##*/}
      if w_path "/etc/nftables.d/$n" && w_marked "$f"; then
        echo "file /etc/nftables.d/$n"
        grep -oE '^table inet [a-z0-9_]+ [{]' "$f" 2>/dev/null | awk '{print $3}' | while read -r t; do
          if w_nft "$t"; then echo "nft $t"; fi
        done
      fi
    done
    f=$M_ROOT/etc/iproute2/rt_tables.d/meridian.conf
    if w_marked "$f"; then
      echo "file /etc/iproute2/rt_tables.d/meridian.conf"
      grep -oE '^[0-9]+' "$f" 2>/dev/null | while read -r t; do
        if w_table "$t"; then echo "table $t"; fi
      done
    fi
    for n in /etc/sysctl.d/99-meridian.conf /etc/smartdns/smartdns.conf; do
      if w_marked "$M_ROOT$n"; then echo "file $n"; fi
    done
    for f in "$M_ROOT"/etc/meridian/*; do
      n=${f##*/}
      if [ -f "$f" ] && [ ! -L "$f" ] && w_path "/etc/meridian/$n"; then echo "file /etc/meridian/$n"; fi
    done
  } | sort -u
}

w_legacy_load() {
  local kind a
  while read -r kind a; do
    case "$kind" in
      file)
        W_FILES+=("$a")
        # Files of /etc/meridian are Meridian's by location; elsewhere the
        # marker is re-checked right before removal.
        case "$a" in /etc/meridian/*) W_HASHES+=("legacy-dir") ;; *) W_HASHES+=("legacy") ;; esac ;;
      iface) W_IFACES+=("$a") ;;
      unit) W_UNITS+=("$a") ;;
      nft) W_NFTS+=("$a") ;;
      table) W_TABLES+=("$a") ;;
    esac
  done < <(w_legacy_scan)
}

# w_plan_items prints the plan of the loaded set with each item's state.
w_plan_items() {
  local i p f st
  for p in "${W_UNITS[@]}"; do
    st=absent; if w_unit_live "$p" || [ -e "$M_ROOT/etc/systemd/system/$p" ]; then st=present; fi
    echo "MERIDIAN_PLAN unit $p $st"
  done
  for p in "${W_IFACES[@]}"; do st=absent; w_has_link "$p" && st=present; echo "MERIDIAN_PLAN iface $p $st"; done
  for p in "${W_TABLES[@]}"; do echo "MERIDIAN_PLAN table $p flush"; done
  for p in "${W_DSTS[@]}"; do echo "MERIDIAN_PLAN route $p blackhole"; done
  for p in "${W_NFTS[@]}"; do st=absent; w_has_nft "$p" && st=present; echo "MERIDIAN_PLAN nft inet $p $st"; done
  for i in "${!W_FILES[@]}"; do
    p=${W_FILES[$i]}; f=$M_ROOT$p
    if [ ! -e "$f" ] && [ ! -L "$f" ]; then st=absent
    elif [ "${W_HASHES[$i]}" = legacy ] || [ "${W_HASHES[$i]}" = legacy-dir ]; then st=present
    elif [ -f "$f" ] && [ ! -L "$f" ] && [ "$(sha256sum -- "$f" | cut -c1-64)" = "${W_HASHES[$i]}" ]; then st=present
    else st=changed; fi
    echo "MERIDIAN_PLAN file $p $st"
  done
  for p in "${W_ORPHANS[@]}"; do st=absent; [ -e "$M_ROOT$p" ] && st=present; echo "MERIDIAN_PLAN orphan $p $st"; done
  for p in "${W_PKGS[@]}"; do echo "MERIDIAN_PLAN keep package $p"; done
}

w_keep_notes() {
  local p
  for p in "${W_PKGS[@]}"; do w_kept package "$p (installed by Meridian, kept on purpose)"; done
  w_kept sysctl 'runtime forwarding / rp_filter values stay as they are until reboot or until you change them'
  if w_has_file /etc/smartdns/smartdns.conf && ! w_has_pkg smartdns; then
    w_kept service 'smartdns.service (package not installed by Meridian): its Meridian config was removed; it keeps running with the old config until restarted'
  fi
  if [ "$M_MODE" = legacy ]; then
    w_kept routes 'main-table blackhole routes of the old version are not recorded anywhere: check "ip route show type blackhole" by hand'
  fi
}

# ------------------------------------------------------------ the steps ---

w_remove_all() {
  local i p f u t fam n d reload=0
  for u in "${W_UNITS[@]}"; do
    if w_unit_live "$u"; then
      if systemctl disable --now "$u" >/dev/null 2>&1; then w_removed unit "$u"; else w_left unit "$u (disable --now failed)"; fi
    fi
  done
  if w_has_pkg smartdns && w_has_file /etc/smartdns/smartdns.conf; then
    if systemctl disable --now smartdns.service >/dev/null 2>&1; then w_removed service "smartdns.service stopped and disabled (package kept)"; else w_left service "smartdns.service (disable --now failed)"; fi
  fi
  if w_has_file /etc/meridian/mesh-sidecar.compose.yml && [ -f "$M_ROOT/etc/meridian/mesh-sidecar.compose.yml" ] && command -v docker >/dev/null 2>&1; then
    if docker compose -f "$M_ROOT/etc/meridian/mesh-sidecar.compose.yml" down >/dev/null 2>&1; then w_removed container 'mesh sidecar (docker compose down)'; else w_left container 'mesh sidecar (docker compose down failed)'; fi
  fi
  for p in "${W_IFACES[@]}"; do
    if w_has_link "$p"; then
      if ip link del "$p" >/dev/null 2>&1; then w_removed iface "$p"; else w_left iface "$p"; fi
    fi
  done
  for t in "${W_TABLES[@]}"; do
    for fam in 4 6; do
      n=0
      while [ "$n" -lt 64 ] && ip -"$fam" rule del lookup "$t" >/dev/null 2>&1; do n=$((n + 1)); done
      ip -"$fam" route flush table "$t" >/dev/null 2>&1 || true
    done
    w_removed table "$t (rules deleted, table flushed)"
  done
  for d in "${W_DSTS[@]}"; do
    fam=$(w_fam "$d")
    n=0
    while [ "$n" -lt 8 ] && ip -"$fam" route del blackhole "$d" >/dev/null 2>&1; do n=$((n + 1)); done
    if [ "$n" -gt 0 ]; then w_removed route "blackhole $d"; fi
  done
  for t in "${W_NFTS[@]}"; do
    if w_has_nft "$t"; then
      if nft delete table inet "$t" >/dev/null 2>&1; then w_removed nft "inet $t"; else w_left nft "inet $t"; fi
    fi
  done
  for i in "${!W_FILES[@]}"; do
    p=${W_FILES[$i]}; f=$M_ROOT$p
    [ -e "$f" ] || [ -L "$f" ] || continue
    if [ "${W_HASHES[$i]}" = legacy ]; then
      if ! w_marked "$f"; then w_left file "$p (no longer carries the Meridian marker: kept)"; continue; fi
    elif [ "${W_HASHES[$i]}" = legacy-dir ]; then
      if [ ! -f "$f" ] || [ -L "$f" ]; then w_left file "$p (not a regular file: kept)"; continue; fi
    elif [ ! -f "$f" ] || [ -L "$f" ] || [ "$(sha256sum -- "$f" | cut -c1-64)" != "${W_HASHES[$i]}" ]; then
      w_left file "$p (changed since the install: kept, check it by hand)"
      continue
    fi
    if rm -f -- "$f"; then
      w_removed file "$p"
      case "$p" in /etc/systemd/system/*) reload=1 ;; esac
    else
      w_left file "$p"
    fi
  done
  for p in "${W_ORPHANS[@]}"; do
    f=$M_ROOT$p
    if [ -f "$f" ] && [ ! -L "$f" ]; then
      if rm -f -- "$f"; then w_removed file "$p"; else w_left file "$p"; fi
    fi
  done
  if [ "$reload" = 1 ]; then systemctl daemon-reload >/dev/null 2>&1 || true; fi
  rmdir -- "$M_ROOT/etc/meridian" 2>/dev/null || true
  # Verify: nothing named above may still be there.
  for u in "${W_UNITS[@]}"; do
    if systemctl is-active --quiet "$u" 2>/dev/null; then w_left unit "$u (still active)"; fi
  done
  for p in "${W_IFACES[@]}"; do if w_has_link "$p"; then w_left iface "$p"; fi; done
  for t in "${W_NFTS[@]}"; do if w_has_nft "$t"; then w_left nft "inet $t"; fi; done
}

w_journal_open() {
  install -d -m 700 "$M_STATE"
  printf 'meridian-node-journal 1\nstate withdrawing\nkind withdraw\nmode %s\nnode %s\ndeployment %s\nrun %s\nstarted %s\n' \
    "$M_MODE" "$M_NODE" "$M_DEPLOYMENT" "$M_RUN" "$(date +%s)" > "$M_JOURNAL.next"
  mv -f "$M_JOURNAL.next" "$M_JOURNAL"
}

w_journal_close() {
  if [ "$M_LEFT" = 0 ]; then
    rm -f -- "$M_MANIFEST"
    sed -i 's/^state withdrawing$/state withdrawn/' "$M_JOURNAL"
    printf 'withdrawn %s\n' "$(date +%s)" >> "$M_JOURNAL"
    echo MERIDIAN_WITHDRAW_OK
    exit 0
  fi
  sed -i 's/^state withdrawing$/state withdraw_incomplete/' "$M_JOURNAL"
  echo MERIDIAN_WITHDRAW_PARTIAL
  exit 4
}

w_digest_gate() {
  echo "MERIDIAN_PLAN_DIGEST $1"
  if [ "$M_ACTION" = plan ]; then
    echo MERIDIAN_PLAN_OK
    exit 0
  fi
  [ "$1" = "$M_DIGEST" ] || w_refuse plan_changed 'the host changed since the plan was reviewed; plan again'
}

# ------------------------------------------------------------- the modes ---

w_journal_ours() { [ "$(w_jget node)" = "$M_NODE" ] && [ "$(w_jget deployment)" = "$M_DEPLOYMENT" ]; }

w_mode_manifest() {
  local st
  st=$(w_jget state)
  if [ ! -e "$M_MANIFEST" ]; then
    if [ "$st" = withdrawn ] && w_journal_ours; then
      echo MERIDIAN_WITHDRAW_ALREADY
      exit 0
    fi
    case "$st" in running|incomplete) w_refuse journal_incomplete "a provision run did not finish (see $M_JOURNAL): recover it first (journal mode)" ;; esac
    if [ -n "$(w_legacy_scan)" ]; then
      w_refuse legacy_install 'Meridian files without a manifest (an older version): use the legacy cleanup with explicit confirmation'
    fi
    w_refuse manifest_missing "no Meridian manifest on this host ($M_MANIFEST)"
  fi
  [ -f "$M_MANIFEST" ] && [ ! -L "$M_MANIFEST" ] || w_refuse manifest_unreadable "$M_MANIFEST is not a regular file"
  local node dep srv
  node=$(w_mget node); dep=$(w_mget deployment); srv=$(w_mget server)
  echo "MERIDIAN_OWNER $(printf '%s %s %s' "${node:--}" "${dep:--}" "${srv:--}" | tr -cd 'A-Za-z0-9._ -' | head -c 200)"
  [ -n "$node" ] || w_refuse manifest_unreadable 'the manifest names no node'
  if [ "$node" != "$M_NODE" ] || [ "$dep" != "$M_DEPLOYMENT" ]; then
    w_refuse manifest_other 'the manifest on this host belongs to another node or another panel deployment'
  fi
  [ "$srv" = "$M_SERVER" ] || w_refuse manifest_other_server 'the manifest on this host was written for another server of this panel'
  case "$st" in
    running|incomplete) w_refuse journal_incomplete "a provision run did not finish (see $M_JOURNAL): recover it first (journal mode)" ;;
    withdrawing|withdraw_incomplete) w_journal_ours || w_refuse journal_other 'an unfinished withdraw on this host belongs to another node or deployment' ;;
  esac
  w_load_manifest
  w_plan_items
  w_digest_gate "$(w_sum < "$M_MANIFEST")"
  trap '' HUP PIPE
  w_journal_open
  w_remove_all
  w_keep_notes
  w_journal_close
}

w_mode_legacy() {
  [ ! -e "$M_MANIFEST" ] || w_refuse manifest_present 'this host has a Meridian manifest: withdraw by manifest, not as legacy'
  local st scan
  st=$(w_jget state)
  case "$st" in
    running|incomplete) w_refuse journal_incomplete "a provision run did not finish (see $M_JOURNAL): recover it first (journal mode)" ;;
    withdrawn) if w_journal_ours && [ -z "$(w_legacy_scan)" ]; then echo MERIDIAN_WITHDRAW_ALREADY; exit 0; fi ;;
  esac
  scan=$(w_legacy_scan)
  [ -n "$scan" ] || w_refuse legacy_none 'no Meridian-marked files at the well-known paths: nothing to clean up'
  w_legacy_load
  w_plan_items
  w_digest_gate "$(printf '%s\n' "$scan" | w_sum)"
  trap '' HUP PIPE
  w_journal_open
  w_remove_all
  w_keep_notes
  w_journal_close
}

w_mode_journal() {
  local st run work kind a b
  [ -f "$M_JOURNAL" ] || w_refuse journal_missing "no provision journal on this host ($M_JOURNAL)"
  st=$(w_jget state)
  case "$st" in
    running|incomplete) ;;
    *) w_refuse journal_clean "the provision journal is not unfinished (state ${st:-unknown}); nothing to recover" ;;
  esac
  w_journal_ours || w_refuse journal_other 'the unfinished run on this host belongs to another node or panel deployment'
  run=$(w_jget run)
  w_runid "$run" || w_refuse journal_unrecoverable 'the journal names no valid run'
  work=$M_STATE/run-$run
  [ -d "$work" ] || w_refuse journal_unrecoverable "the run's work directory $work is gone: it cannot be compensated from the panel; check $M_JOURNAL by hand"
  if [ ! -f "$work/params" ]; then
    # The run never finished opening its journal: m_begin writes params
    # last, before any change. Nothing of it reached the host.
    [ ! -s "$work/actions" ] || w_refuse journal_unrecoverable "the run's work directory has actions but no params; check $work by hand"
    echo "MERIDIAN_PLAN journal $run nothing-changed"
    w_digest_gate "$(cat "$M_JOURNAL" | w_sum)"
    trap '' HUP PIPE
    sed -i -e 's/^state running$/state compensated/' -e 's/^state incomplete$/state compensated/' "$M_JOURNAL"
    printf 'recovered %s nothing-changed\n' "$M_RUN" >> "$M_JOURNAL"
    rm -rf -- "$work"
    echo MERIDIAN_COMPENSATED
    exit 1
  fi
  for f in actions pre-links pre-nft pre-rule4 pre-rule6 pre-route4 pre-route6 pre-sysctl pre-units; do
    [ -f "$work/$f" ] || w_refuse journal_unrecoverable "the run's work directory lacks $f; check $work by hand"
  done
  M_IFACES=""; M_UNITS=""; M_NFT=""; M_TABLES=""; M_PRIOS=""; M_DSTS=""; M_EXPECT=""
  local v bad=""
  while read -r kind rest; do
    for v in $rest; do
      case "$kind" in
        ifaces) w_iface "$v" || bad="$bad iface:$v" ;;
        units) w_unit "$v" || bad="$bad unit:$v" ;;
        nft) w_nft "$v" || bad="$bad nft:$v" ;;
        tables) w_table "$v" || bad="$bad table:$v" ;;
        prios) w_prio "$v" || bad="$bad prio:$v" ;;
        dsts) w_dst "$v" || bad="$bad route:$v" ;;
        expect) [ "$v" = none ] || [ "$v" = same ] || bad="$bad expect:$v" ;;
        *) bad="$bad $kind" ;;
      esac
    done
    case "$kind" in
      ifaces) M_IFACES=$rest ;; units) M_UNITS=$rest ;; nft) M_NFT=$rest ;; tables) M_TABLES=$rest ;;
      prios) M_PRIOS=$rest ;; dsts) M_DSTS=$rest ;; expect) M_EXPECT=$rest ;;
    esac
  done < "$work/params"
  [ -z "$bad" ] || w_refuse journal_unrecoverable "the run's params are not acceptable ($(printf '%s' "$bad" | tr -cd 'A-Za-z0-9_:./ -' | head -c 200))"
  [ -n "$M_EXPECT" ] || w_refuse journal_unrecoverable 'the run params name no expectation'
  while read -r kind a b; do
    case "$kind" in
      file-new) echo "MERIDIAN_PLAN remove file $a" ;;
      file-replaced) echo "MERIDIAN_PLAN restore file $a" ;;
      dir-new) echo "MERIDIAN_PLAN remove dir $a" ;;
      pkg) echo "MERIDIAN_PLAN keep package $a" ;;
    esac
  done < "$work/actions"
  for v in $M_IFACES; do echo "MERIDIAN_PLAN check iface $v"; done
  for v in $M_UNITS; do echo "MERIDIAN_PLAN check unit $v"; done
  for v in $M_NFT; do echo "MERIDIAN_PLAN check nft inet $v"; done
  if [ "$M_EXPECT" = same ]; then echo "MERIDIAN_PLAN restart previous meridian-up.sh"; fi
  w_digest_gate "$(cat "$M_JOURNAL" "$work/params" "$work/actions" | w_sum)"
  # The earlier attempt's leftovers are re-evaluated by this compensation.
  grep -v '^leftover ' "$M_JOURNAL" | grep -v 'kept on purpose' | sed 's/^state incomplete$/state running/' > "$M_JOURNAL.next"
  printf 'recovery %s\n' "$M_RUN" >> "$M_JOURNAL.next"
  mv -f "$M_JOURNAL.next" "$M_JOURNAL"
  M_WORK=$work
  M_DONE=0
  false
  m_compensate
}

case "$M_MODE" in
  manifest) w_mode_manifest ;;
  legacy) w_mode_legacy ;;
  journal) w_mode_journal ;;
  *) w_refuse bad_mode 'unknown mode' ;;
esac
`

// WithdrawOutcome is what a withdraw script reported (markers only).
type WithdrawOutcome struct {
	OK, Partial, Already    bool
	Compensated, Incomplete bool
	Restored, PlanOK        bool
	Refused                 string
	Owner                   string
	Digest                  string
	Plan                    []string
	Removed, Kept           []string
	Leftovers               []string
}

// ParseWithdrawOutput reads the markers. Text is cleaned and capped.
func ParseWithdrawOutput(out string) WithdrawOutcome {
	var o WithdrawOutcome
	add := func(list *[]string, v string) {
		if len(*list) < 256 {
			*list = append(*list, preflight.Clean(v))
		}
	}
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		key, rest, _ := strings.Cut(l, " ")
		switch key {
		case "MERIDIAN_WITHDRAW_OK":
			o.OK = true
		case "MERIDIAN_WITHDRAW_PARTIAL":
			o.Partial = true
		case "MERIDIAN_WITHDRAW_ALREADY":
			o.Already = true
		case "MERIDIAN_COMPENSATED":
			o.Compensated = true
		case "MERIDIAN_COMPENSATION_INCOMPLETE":
			o.Incomplete = true
		case "MERIDIAN_RESTORED_PREVIOUS":
			o.Restored = true
		case "MERIDIAN_PLAN_OK":
			o.PlanOK = true
		case "MERIDIAN_REFUSED":
			o.Refused = preflight.Clean(rest)
		case "MERIDIAN_OWNER":
			o.Owner = preflight.Clean(rest)
		case "MERIDIAN_PLAN_DIGEST":
			if isHex64(strings.TrimSpace(rest)) {
				o.Digest = strings.TrimSpace(rest)
			}
		case "MERIDIAN_PLAN":
			add(&o.Plan, rest)
		case "MERIDIAN_REMOVED":
			add(&o.Removed, rest)
		case "MERIDIAN_KEPT":
			add(&o.Kept, rest)
		case "MERIDIAN_LEFTOVER":
			add(&o.Leftovers, rest)
		}
	}
	return o
}
