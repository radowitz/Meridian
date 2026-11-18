package dnsjournal

// The capability gate: is this gateway's resolver known not to be slowed or
// stopped by its own audit log?
//
// What it rests on. Whether a full, slow or broken audit sink can delay
// name resolution is a property of the SmartDNS binary, and the gateway's
// resolver is a container whose image tag is "latest": its version is not
// the version of the binaries the panel delivers to remote nodes
// (internal/artifacts) and may differ from one gateway to the next. So the
// gate never infers anything from a tag or from the pinned node artifact.
// It asks the running container for its version (the host agent's fixed
// "docker exec meridian-smartdns /usr/sbin/smartdns -v") and accepts only:
//
//   - a version in VerifiedVersions: the audit behaviour of that version
//     was observed on the date given (deploy/verify-smartdns.sh
//     --audit-check passed every check, the frozen filesystem included, on
//     a real gateway with its resolver's image; docs/architecture.md
//     「网关解析日志」lists exactly what was and was not observed); or
//   - a version recorded on this host by deploy/verify-smartdns.sh
//     --audit-check --record, which runs the same checks in throw-away
//     containers without a network and writes one line
//     "<version> <image id> <date>" to LocalVerifiedFile. A record counts
//     only for the image the running container was created from: a pulled
//     image has another id and is unverified again.
//
// It also requires what the collection needs: the resolver is the Compose
// container (a host smartdns.service was not verified and is refused) and
// the container has RawDir mounted read-write at the same path. Anything
// else leaves the feature unavailable with the reason; nothing ever falls
// back to reading the resolver's ordinary log.

import (
	"bufio"
	"regexp"
	"strings"
)

// VerifiedVersions are the SmartDNS versions whose audit behaviour was
// observed, with the date of the observation.
var VerifiedVersions = map[string]string{
	"1.2026.11.09-1240": "2026-11-15",
}

// LocalVerifiedFile is where deploy/verify-smartdns.sh --audit-check
// --record notes a version it verified on this host (root-only directory of
// the host agent).
const LocalVerifiedFile = "/etc/meridian-host/smartdns-audit-verified"

// ResolverBinary is the resolver's binary inside its container (the Compose
// service's command).
const ResolverBinary = "/usr/sbin/smartdns"

var (
	versionRe  = regexp.MustCompile(`^[0-9][0-9A-Za-z.+_-]{2,40}$`)
	imageIDRe  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	dateRe     = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	versionOut = regexp.MustCompile(`(?m)^smartdns\s+([0-9][0-9A-Za-z.+_-]{2,40})(\s.*)?$`)
)

// ParseVersion reads the version from the output of "smartdns -v" ("" when
// it is not there): the word after "smartdns" (observed: "smartdns
// 1.2026.11.09-1240" from the gateway's image, "smartdns 1.2026.08.05-0921
// (Release48.4)" from the node artifact).
func ParseVersion(out string) string {
	if m := versionOut.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

// LocalRecord is one line of LocalVerifiedFile.
type LocalRecord struct {
	Version string `json:"version"`
	ImageID string `json:"image_id"`
	Date    string `json:"date"`
}

// ParseLocalVerified reads LocalVerifiedFile's content: lines of
// "<version> <image id> <date>"; comments and lines that are not exactly
// that are ignored. At most 32 records.
func ParseLocalVerified(body string) []LocalRecord {
	var out []LocalRecord
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() && len(out) < 32 {
		f := strings.Fields(sc.Text())
		if len(f) != 3 || !versionRe.MatchString(f[0]) || !imageIDRe.MatchString(f[1]) || !dateRe.MatchString(f[2]) {
			continue
		}
		out = append(out, LocalRecord{Version: f[0], ImageID: f[1], Date: f[2]})
	}
	return out
}

// Facts is what the host agent read about the gateway's resolver.
type Facts struct {
	// Provider: "container" (the Compose service), "unit" (a host
	// smartdns.service) or "" (neither).
	Provider string `json:"provider"`
	// Running: the container is running.
	Running bool `json:"running"`
	// Version is the running binary's own report ("" unreadable).
	Version string `json:"version,omitempty"`
	// ImageID is the image the container was created from.
	ImageID string `json:"image_id,omitempty"`
	// MountFound / MountRW: RawDir is mounted into the container at the same
	// path, and writable.
	MountFound bool `json:"mount_found"`
	MountRW    bool `json:"mount_rw"`
	// Local are the host's own verification records.
	Local []LocalRecord `json:"local_verified,omitempty"`
}

// Codes of an unavailable capability.
const (
	CodeNoResolver      = "no_resolver"
	CodeHostUnit        = "host_unit"
	CodeNotRunning      = "resolver_not_running"
	CodeVersionUnknown  = "version_unreadable"
	CodeVersionUnproven = "version_unverified"
	CodeNoMount         = "no_mount"
	CodeMountReadOnly   = "mount_read_only"
)

// Capability is the gate's verdict.
type Capability struct {
	Available bool   `json:"available"`
	Code      string `json:"code,omitempty"`
	Reason    string `json:"reason,omitempty"`
	// Action says what the operator can do about it.
	Action  string `json:"action,omitempty"`
	Version string `json:"version,omitempty"`
	// VerifiedBy: "builtin" (VerifiedVersions) or "host_record"
	// (LocalVerifiedFile); VerifiedOn the date of that verification.
	VerifiedBy string `json:"verified_by,omitempty"`
	VerifiedOn string `json:"verified_on,omitempty"`
}

const recreateHint = "在网关上用这一版的 deploy/docker-compose.yml 重建解析器容器：docker compose -f deploy/docker-compose.yml --profile dns up -d（会重启解析器一次）"

// Evaluate judges f.
func Evaluate(f Facts) Capability {
	c := Capability{Version: f.Version}
	no := func(code, reason, action string) Capability {
		c.Code, c.Reason, c.Action = code, reason, action
		return c
	}
	switch {
	case f.Provider == "unit":
		return no(CodeHostUnit, "网关的解析器是宿主上的 smartdns.service，不是 Compose 的 meridian-smartdns 容器：这种方式下审计日志的行为没有核对过，解析日志保持不可用",
			"改用 deploy/docker-compose.yml 的 smartdns 服务，或保持关闭")
	case f.Provider != "container":
		return no(CodeNoResolver, "网关上没有 meridian-smartdns 容器：读不到解析器的版本，解析日志保持不可用", "先启动解析器（docker compose --profile dns up -d）")
	case !f.Running:
		return no(CodeNotRunning, "meridian-smartdns 容器没有在运行：读不到解析器的版本，解析日志保持不可用", "先启动解析器（docker compose --profile dns up -d）")
	case f.Version == "":
		return no(CodeVersionUnknown, "读不到 meridian-smartdns 容器里 SmartDNS 的版本（"+ResolverBinary+" -v 没有给出版本号）：无法确认它的审计日志不会拖住解析，解析日志保持不可用", "")
	}
	if on, ok := VerifiedVersions[f.Version]; ok {
		c.VerifiedBy, c.VerifiedOn = "builtin", on
	} else {
		for _, r := range f.Local {
			if r.Version == f.Version && f.ImageID != "" && r.ImageID == f.ImageID {
				c.VerifiedBy, c.VerifiedOn = "host_record", r.Date
			}
		}
	}
	if c.VerifiedBy == "" {
		return no(CodeVersionUnproven, "meridian-smartdns 容器里的 SmartDNS 是 "+f.Version+"：这个版本的审计日志在写失败、磁盘写满和写入卡住时会不会拖住解析，没有核对过（镜像标签是 latest，各网关的版本可能不同），解析日志保持不可用",
			"在网关上以 root 运行 sudo bash deploy/verify-smartdns.sh --audit-check --record：它用没有网络的临时容器对正在使用的镜像做同样的核对，全部通过后在本机记下这个版本")
	}
	switch {
	case !f.MountFound:
		return no(CodeNoMount, "meridian-smartdns 容器没有挂载 "+RawDir+"（容器是用旧的 Compose 文件创建的）：解析器没有可写的地方放审计日志，解析日志保持不可用", recreateHint)
	case !f.MountRW:
		return no(CodeMountReadOnly, "meridian-smartdns 容器里 "+RawDir+" 是只读挂载：解析器写不了审计日志，解析日志保持不可用", recreateHint)
	}
	c.Available = true
	return c
}

// AuditConfig is what a gateway SmartDNS config says about the audit log.
type AuditConfig struct {
	// Enabled: an "audit-enable yes" line.
	Enabled bool
	// File is the "audit-file" value ("" none).
	File string
}

// ReadAuditConfig reads the audit directives of a SmartDNS config
// (directives start their line; comments do not count).
func ReadAuditConfig(conf string) AuditConfig {
	var a AuditConfig
	for _, l := range strings.Split(conf, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "audit-enable":
			a.Enabled = f[1] == "yes"
		case "audit-file":
			a.File = f[1]
		}
	}
	return a
}

// Managed reports whether a is exactly the audit this package reads:
// enabled, into AuditFile.
func (a AuditConfig) Managed() bool { return a.Enabled && a.File == AuditFile }
