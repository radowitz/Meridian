package compile

import (
	"fmt"
	"strings"

	"github.com/radowitz/meridian/internal/dnsjournal"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/validate"
)

// The gateway's DNS query journal (settings.dns_log; internal/dnsjournal,
// docs/architecture.md「网关解析日志」). Off: nothing here is rendered and
// every file is byte-identical to a topology without the setting.
//
// On, exactly three things change in the gateway's files:
//
//   - smartdns.conf gets the four audit directives (writeDNSAudit): the
//     resolver appends one line per answered query to a regular file in
//     dnsjournal.RawDir, the one directory mounted read-write into its
//     container (SmartDNSWritableDirs; deploy/docker-compose.yml);
//   - DNSJournalUnit is added: "meridian dns-journal", the reader that
//     prepares that directory and file before the resolver is restarted,
//     follows the file and keeps the bounded journal;
//   - meridian-verify.sh gets the checks of dnsLogVerifyBlock.
//
// Whether the resolver may be given an audit log at all is not decided
// here: the capability gate (dnsjournal.Evaluate) is checked when the
// switch is set, by the install pre-check and by the host agent right
// before it restarts the resolver.
const DNSJournalUnit = dnsjournal.Unit

// SmartDNSWritableDirs are the host directories the gateway resolver's
// container mounts read-write at the same path: only the audit directory.
// Every other mount of that container is read-only (SmartDNSSharedDirs).
var SmartDNSWritableDirs = []string{dnsjournal.RawDir}

// writeDNSAudit adds the audit directives. The size suffix "k" and these
// four directives are the ones observed with the gateway's resolver binary;
// nothing else about the audit log is configured.
func writeDNSAudit(sb *strings.Builder) {
	sb.WriteString("# Query log (settings dns_log): one audit line per answered query, read on this host by\n")
	fmt.Fprintf(sb, "# %s. The file is a regular file in a root-only directory that exists\n", DNSJournalUnit)
	sb.WriteString("# before this resolver starts, and only ever a regular file: a FIFO or another special file\n")
	sb.WriteString("# has no use there and the resolver's behaviour with one is not relied on. Names blocked by\n")
	sb.WriteString("# an \"address /name/#\" rule are not written by the resolver.\n")
	sb.WriteString("audit-enable yes\n")
	fmt.Fprintf(sb, "audit-file %s\n", dnsjournal.AuditFile)
	fmt.Fprintf(sb, "audit-size %dk\n", dnsjournal.AuditSizeKB)
	fmt.Fprintf(sb, "audit-num %d\n", dnsjournal.AuditNum)
}

// SmartDNSAuditOn reports whether a gateway SmartDNS config enables the
// audit log this compiler renders.
func SmartDNSAuditOn(conf string) bool { return dnsjournal.ReadAuditConfig(conf).Managed() }

// DNSJournalUnitSpec is what the reader's unit is rendered from.
type DNSJournalUnitSpec struct {
	Unit, Binary         string
	StateDir, RuntimeDir string
	RawDir, JournalDir   string
	NeighIf              string
}

// StatusSocket is the reader's status socket.
func (s DNSJournalUnitSpec) StatusSocket() string { return "/run/" + s.RuntimeDir + "/status.sock" }

func gatewayDNSJournalSpec(t model.Topology) DNSJournalUnitSpec {
	return DNSJournalUnitSpec{Unit: DNSJournalUnit, Binary: "/usr/local/bin/meridian", StateDir: dnsjournal.StateDirName, RuntimeDir: dnsjournal.RuntimeDirName,
		RawDir: dnsjournal.RawDir, JournalDir: dnsjournal.JournalDir, NeighIf: gatewayLAN(t)}
}

// RenderDNSJournalUnit runs the reader as root without any capability: the
// audit file is written by the resolver container's root, which is this
// host's uid 0, so the owner bits are enough and no CAP_DAC_OVERRIDE is
// needed. It cannot reach the network (only Unix and netlink sockets: the
// status socket and the neighbour table), writes only its StateDirectory
// and runs at low CPU and idle I/O priority, so it cannot compete with the
// resolver. ExecStartPre prepares the audit sink before the unit counts as
// started: the host agent restarts the resolver only after this unit was
// (re)started and the sink checked.
func RenderDNSJournalUnit(s DNSJournalUnitSpec) string {
	dirs := fmt.Sprintf("--raw-dir %s --journal-dir %s", s.RawDir, s.JournalDir)
	args := dirs + " --status-socket " + s.StatusSocket()
	if s.NeighIf != "" {
		args += " --neigh-if " + s.NeighIf
	}
	return fmt.Sprintf(`# Meridian gateway DNS query journal (settings.dns_log): reads the audit file
# the gateway's SmartDNS writes into %[4]s and keeps a bounded record
# in %[5]s; see docs/architecture.md「网关解析日志」.
# Stopped or crashed: nothing is recorded; the resolver is not affected (it
# only appends to its own file, which its own rotation bounds).
[Unit]
Description=Meridian gateway DNS query journal
After=local-fs.target

[Service]
Type=simple
# An older host binary has no dns-journal subcommand and would start the panel.
ExecStartPre=/bin/grep -q %[2]s %[3]s
# The audit sink first: a 0700 directory and a regular 0600 file, never a
# special file. The resolver is restarted only after this has run. (The
# resolver sets the file to 0640 when it opens it; this service sets it back
# every second. The 0700 directory is what keeps other users out.)
ExecStartPre=%[3]s dns-journal --prepare %[6]s
ExecStart=%[3]s dns-journal %[7]s
User=root
CapabilityBoundingSet=
AmbientCapabilities=
NoNewPrivileges=yes
# %[8]s is root-only (0700): the audit file and its rotated copies
# in raw/ (the one directory mounted read-write into the resolver container)
# and the journal in journal/. Together at most 32 MiB, 24 h, 50000 records.
StateDirectory=%[9]s
StateDirectoryMode=0700
# Status socket: 0666 in a 0755 directory, answering uid 0 only (SO_PEERCRED);
# the host agent is root without CAP_DAC_OVERRIDE.
RuntimeDirectory=%[10]s
RuntimeDirectoryMode=0755
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK
IPAddressDeny=any
UMask=0077
Nice=10
CPUWeight=20
IOSchedulingClass=idle
MemoryMax=96M
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
`, s.Unit, dnsjournal.ReadyMarker, s.Binary, s.RawDir, s.JournalDir, dirs, args, "/var/lib/"+s.StateDir, s.StateDir, s.RuntimeDir)
}

// dnsLogVerifyBlock: the query journal on the gateway (only with
// settings.dns_log on; the script is unchanged without it).
var dnsLogVerifyBlock = fmt.Sprintf(`# --- DNS query journal (settings.dns_log) --------------------------------------
if ! command -v systemctl >/dev/null 2>&1; then
  unknown dns_log_reader "systemctl not found; %[1]s was not checked"
elif run dns-log-reader systemctl is-active %[1]s; then
  pass dns_log_reader "%[1]s is active (evidence dns-log-reader.txt)"
else
  fail dns_log_reader "%[1]s is not active: queries are not recorded; resolution is not affected (journalctl -u %[1]s)"
fi
# The audit sink: the resolver opens this file when it starts. It is only
# ever a regular file in a root-only directory: a FIFO, socket, device or link
# has no use there, and the resolver's behaviour with one is not relied on.
dnslog_raw="$root"%[2]s
dnslog_file="$dnslog_raw"/%[3]s
if [ -L "$dnslog_raw" ] || [ ! -d "$dnslog_raw" ]; then
  fail dns_log_sink "audit directory $dnslog_raw is missing or not a real directory"
elif [ "$(stat -c '%%a %%u' "$dnslog_raw" 2>/dev/null)" != "700 0" ]; then
  fail dns_log_sink "audit directory $dnslog_raw is $(stat -c '%%a %%u' "$dnslog_raw" 2>/dev/null), not 0700 owned by root: other local users might read the queries"
elif [ -L "$dnslog_file" ] || [ ! -f "$dnslog_file" ]; then
  fail dns_log_sink "audit file $dnslog_file is missing or not a regular file: only a regular file belongs there (the reader replaces anything else when it starts)"
elif [ -n "$(find "$dnslog_raw" -mindepth 1 \( ! -type f -o ! -user 0 -o -perm /027 \) -print 2>/dev/null | head -n 1)" ]; then
  fail dns_log_sink "an entry in $dnslog_raw is not a regular root-owned file closed to other users: $(find "$dnslog_raw" -mindepth 1 \( ! -type f -o ! -user 0 -o -perm /027 \) -print 2>/dev/null | head -n 1)"
else
  pass dns_log_sink "audit sink $dnslog_raw: directory 0700 root, $dnslog_file a regular file, nothing readable by other users (the resolver sets its file to 0640 when it opens it; the reader sets it back to 0600 on its next pass, at most a second)"
fi
dnslog_journal="$root"%[4]s
if [ ! -d "$dnslog_journal" ]; then
  fail dns_log_journal_dir "journal directory $dnslog_journal is missing (the reader creates it at start)"
elif [ "$(stat -c '%%a %%u' "$dnslog_journal" 2>/dev/null)" != "700 0" ] || [ "$(stat -c '%%a %%u' "$root"%[5]s 2>/dev/null)" != "700 0" ]; then
  fail dns_log_journal_dir "journal directory $dnslog_journal or its parent is not 0700 owned by root"
elif [ -n "$(find "$dnslog_journal" -mindepth 1 \( ! -type f -o ! -user 0 -o -perm /077 \) -print 2>/dev/null | head -n 1)" ]; then
  fail dns_log_journal_dir "an entry in $dnslog_journal is not a 0600 root-owned regular file: $(find "$dnslog_journal" -mindepth 1 \( ! -type f -o ! -user 0 -o -perm /077 \) -print 2>/dev/null | head -n 1)"
else
  pass dns_log_journal_dir "journal $dnslog_journal: directory 0700, files 0600, owned by root (the panel reads it through the reader's status socket)"
fi
dnslog_total=$(du -sk "$root"%[5]s 2>/dev/null | cut -f1)
case $dnslog_total in ''|*[!0-9]*) unknown dns_log_budget "the size of $root%[5]s could not be read" ;;
  *) if [ "$dnslog_total" -le %[6]d ]; then
       pass dns_log_budget "$root%[5]s holds ${dnslog_total} KiB (budget %[6]d KiB for the audit file, its rotated copies and the journal)"
     else
       fail dns_log_budget "$root%[5]s holds ${dnslog_total} KiB, over the %[6]d KiB budget"
     fi ;;
esac
dnslog_sock=%[7]s
if [ -S "$dnslog_sock" ] && [ "$(stat -c '%%a %%u' "$dnslog_sock" 2>/dev/null)" = "666 0" ]; then
  pass dns_log_status_socket "status socket $dnslog_sock: 0666 owned by root; the reader answers uid 0 only (SO_PEERCRED)"
else
  fail dns_log_status_socket "status socket $dnslog_sock missing or with other owner/mode ($(stat -c '%%a %%u' "$dnslog_sock" 2>/dev/null)): the panel cannot read the query journal"
fi
if grep -q '^audit-enable yes$' "$root/etc/smartdns/smartdns.conf" 2>/dev/null && grep -q '^audit-file %[2]s/%[3]s$' "$root/etc/smartdns/smartdns.conf" 2>/dev/null; then
  pass dns_log_config "the installed resolver config enables the audit log into %[2]s/%[3]s"
else
  fail dns_log_config "the installed resolver config does not enable the audit log into %[2]s/%[3]s"
fi
pending dns_log_real_binary "the audit behaviour of the resolver image in use (format, rotation, full and frozen filesystem, a sink that cannot be opened): sudo bash deploy/verify-smartdns.sh --audit-check (throw-away containers without a network)"
`, DNSJournalUnit, dnsjournal.RawDir, dnsjournal.AuditBase, dnsjournal.JournalDir, dnsjournal.StateDir, dnsjournal.DefaultMaxBytes>>10, dnsjournal.StatusSocket)

// DNSLogGroup says what one SmartDNS upstream group of the gateway config
// is in the panel's terms: the "group" an audit line names.
type DNSLogGroup struct {
	// Group is the name as the resolver logs it.
	Group string `json:"group"`
	// Kind: domestic | default | unlisted | exit | region_group.
	Kind string `json:"kind"`
	// ID is the exit or region group id ("" for the others).
	ID    string `json:"id,omitempty"`
	Label string `json:"label"`
}

// DNSLogGroups maps the group names of the gateway's SmartDNS config (as
// renderGatewayDNS writes them) back to the panel's objects, from the same
// plans. A name that is not in the list (a record written under an older
// topology) is unknown to the panel and shown as logged.
func DNSLogGroups(t model.Topology) ([]DNSLogGroup, error) {
	res := validate.Run(t)
	if res.HasErrors() {
		return nil, &ValidationError{Result: res}
	}
	tunnels, err := buildTunnels(t)
	if err != nil {
		return nil, err
	}
	exits := planExits(t, tunnels)
	groups := planGroups(t, exits)
	out := []DNSLogGroup{{Group: "domestic", Kind: "domestic", Label: "国内解析器（国内名单和直连规则的名字）"}}
	_, split := renderDNSSplitUnit(t, exits, groups)
	def := DNSLogGroup{Group: "default", Kind: "default", Label: "默认去向的解析器（没有名单、没有规则命中的名字）"}
	if defT, ok := defaultExit(t, groups); ok {
		switch {
		case split:
			def.Kind, def.Label = "unlisted", "未列名单检查（meridian-dns-split：国内回答全是国内地址时采用，否则用默认去向的回答）"
		case defT.Group != nil:
			def.ID, def.Label = defT.Group.Group.ID, "默认地区组 "+defT.Group.Group.ID+" 的解析器（没有名单、没有规则命中的名字）"
		default:
			def.ID, def.Label = defT.Exit.Node.ID, "默认出口 "+defT.Exit.Node.ID+" 的解析器（没有名单、没有规则命中的名字）"
		}
	}
	out = append(out, def)
	if split {
		out = append(out, DNSLogGroup{Group: "unlisted_split", Kind: "unlisted", Label: "未列名单检查（meridian-dns-split）"})
	}
	for _, e := range exits {
		if e.DNSULA == "" {
			continue
		}
		out = append(out, DNSLogGroup{Group: e.Group, Kind: "exit", ID: e.Node.ID, Label: "出口 " + e.Node.ID + " 的解析器"})
	}
	for _, g := range groups {
		if !g.Dynamic {
			continue
		}
		out = append(out, DNSLogGroup{Group: g.DNSGroup, Kind: "region_group", ID: g.Group.ID, Label: "地区组 " + g.Group.ID + " 的解析器（由枢纽当前使用的成员应答）"})
	}
	return out, nil
}
