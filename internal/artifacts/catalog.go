// Package artifacts is the panel's catalog of the binaries it delivers to
// hosts itself (wstunnel and SmartDNS), pinned per architecture by SHA-256.
//
// The pins live in one file, artifacts.lock, embedded here and read by
// deploy/fetch-artifacts.sh when the image is built. The image build
// downloads each upstream release once, refuses a digest mismatch and puts
// the executables into a read-only directory of the image (DefaultDir).
// At startup the panel loads that directory (or an operator-supplied one,
// for air-gapped builds) and verifies every file against the embedded pins
// (Load); it verifies again every time it reads a file to send it (Read).
// Target hosts never download anything: the bytes travel over the pinned
// SSH channel (remote nodes) or the gateway install's bind mount, and the
// host checks the digest once more before anything is activated.
//
// Hosts get the binaries at Meridian-owned paths (HostPath:
// /usr/local/sbin/meridian-<name>), never at /usr/local/bin/wstunnel or
// the distribution's smartdns path, so a binary another service installed
// is neither overwritten nor removed.
//
// The package has no dependency on other Meridian packages.
package artifacts

import (
	_ "embed"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

//go:embed artifacts.lock
var lockFile string

// Names of the delivered binaries.
const (
	Wstunnel = "wstunnel"
	SmartDNS = "smartdns"
	// Gost is the transparent TCP redirector of external SOCKS exits on
	// their carrier (go-gost/gost v3, MIT).
	Gost = "gost"
)

// Architectures, as uname -m prints them on the target host.
const (
	ArchAMD64 = "x86_64"
	ArchARM64 = "aarch64"
)

// MaxSize bounds a delivered binary (the host-side receive command and the
// preflight's hash of an installed copy use the same bound).
const MaxSize = 64 << 20

// HostDir is where hosts keep the delivered binaries.
const HostDir = "/usr/local/sbin"

// HostPath is the Meridian-owned path of a delivered binary on a host.
func HostPath(name string) string { return HostDir + "/meridian-" + name }

// Pin is one pinned binary for one architecture.
type Pin struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
	// SHA256 and Size are those of the executable as installed.
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	// Source* describe the upstream download the image build verifies.
	SourceSHA256 string `json:"source_sha256"`
	SourceKind   string `json:"source_kind"` // tar.gz | raw
	Member       string `json:"member,omitempty"`
	URL          string `json:"url"`
}

// File is the pin's file name inside an artifact directory.
func (p Pin) File() string { return p.Name + "-" + p.Arch }

// HostPath is where the pin is installed on a host.
func (p Pin) HostPath() string { return HostPath(p.Name) }

var (
	nameRe    = regexp.MustCompile(`^(wstunnel|smartdns|gost)$`)
	archRe    = regexp.MustCompile(`^(x86_64|aarch64)$`)
	versionRe = regexp.MustCompile(`^[0-9][0-9A-Za-z.+-]{0,40}$`)
	hexRe     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	memberRe  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	urlRe     = regexp.MustCompile(`^https://github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/releases/download/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`)
)

// ValidName reports whether name is a delivered binary.
func ValidName(name string) bool { return nameRe.MatchString(name) }

// ValidArch reports whether arch is a supported architecture.
func ValidArch(arch string) bool { return archRe.MatchString(arch) }

// ValidSHA256 reports whether s is a lower-case hex SHA-256.
func ValidSHA256(s string) bool { return hexRe.MatchString(s) }

// ParseLock reads a lock file. Every line is validated; any problem is an
// error (the build and the panel refuse a lock they do not fully accept).
func ParseLock(text string) ([]Pin, error) {
	var out []Pin
	seen := map[string]bool{}
	versions := map[string]string{}
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 9 {
			return nil, fmt.Errorf("artifacts.lock 第 %d 行应有 9 列，实际 %d 列", i+1, len(f))
		}
		size, err := strconv.ParseInt(f[4], 10, 64)
		p := Pin{Name: f[0], Version: f[1], Arch: f[2], SHA256: f[3], Size: size, SourceSHA256: f[5], SourceKind: f[6], Member: f[7], URL: f[8]}
		switch {
		case !ValidName(p.Name):
			return nil, fmt.Errorf("artifacts.lock 第 %d 行：名字 %q 不支持", i+1, p.Name)
		case !versionRe.MatchString(p.Version):
			return nil, fmt.Errorf("artifacts.lock 第 %d 行：版本 %q 不合法", i+1, p.Version)
		case !ValidArch(p.Arch):
			return nil, fmt.Errorf("artifacts.lock 第 %d 行：架构 %q 不支持", i+1, p.Arch)
		case !ValidSHA256(p.SHA256) || !ValidSHA256(p.SourceSHA256):
			return nil, fmt.Errorf("artifacts.lock 第 %d 行：摘要不是 64 位小写十六进制", i+1)
		case err != nil || size <= 0 || size > MaxSize:
			return nil, fmt.Errorf("artifacts.lock 第 %d 行：大小 %q 不合法", i+1, f[4])
		case p.SourceKind != "tar.gz" && p.SourceKind != "raw":
			return nil, fmt.Errorf("artifacts.lock 第 %d 行：来源类型 %q 不支持", i+1, p.SourceKind)
		case p.SourceKind == "tar.gz" && !memberRe.MatchString(p.Member):
			return nil, fmt.Errorf("artifacts.lock 第 %d 行：压缩包成员名 %q 不合法", i+1, p.Member)
		case p.SourceKind == "raw" && (p.Member != "-" || p.SourceSHA256 != p.SHA256):
			return nil, fmt.Errorf("artifacts.lock 第 %d 行：raw 来源的成员必须是 - 且两个摘要相同", i+1)
		case !urlRe.MatchString(p.URL):
			return nil, fmt.Errorf("artifacts.lock 第 %d 行：下载地址必须是 GitHub release 资产", i+1)
		}
		if p.SourceKind == "raw" {
			p.Member = ""
		}
		k := p.Name + "/" + p.Arch
		if seen[k] {
			return nil, fmt.Errorf("artifacts.lock 第 %d 行：%s 重复", i+1, k)
		}
		seen[k] = true
		if v, ok := versions[p.Name]; ok && v != p.Version {
			return nil, fmt.Errorf("artifacts.lock 第 %d 行：%s 的各架构版本不一致（%s / %s）", i+1, p.Name, v, p.Version)
		}
		versions[p.Name] = p.Version
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("artifacts.lock 是空的")
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Arch < out[j].Arch
	})
	return out, nil
}

var pins []Pin

func init() {
	p, err := ParseLock(lockFile)
	if err != nil {
		// The lock is part of the source tree and covered by tests: a broken
		// one must not produce a panel that silently delivers nothing.
		panic(err)
	}
	pins = p
}

// Pins returns every pinned binary (a copy).
func Pins() []Pin { return append([]Pin(nil), pins...) }

// PinFor returns the pin of name for arch.
func PinFor(name, arch string) (Pin, bool) {
	for _, p := range pins {
		if p.Name == name && p.Arch == arch {
			return p, true
		}
	}
	return Pin{}, false
}

// Version is the pinned version of name ("" when unknown).
func Version(name string) string {
	for _, p := range pins {
		if p.Name == name {
			return p.Version
		}
	}
	return ""
}

// UnameArch maps a Go GOARCH to uname -m ("" when unsupported).
func UnameArch(goarch string) string {
	switch goarch {
	case "amd64":
		return ArchAMD64
	case "arm64":
		return ArchARM64
	}
	return ""
}

// StageDir is where the panel stages a binary on a remote host before the
// provision script verifies and installs it (sshexec.Connector.Stage).
const StageDir = "/var/lib/meridian/stage"

// StagePath is the staging path of name on a remote host.
func StagePath(name string) string { return StageDir + "/" + name }
