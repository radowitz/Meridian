package artifacts

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// DefaultDir is where the image keeps the verified binaries (read-only,
// written by deploy/fetch-artifacts.sh at build time).
const DefaultDir = "/usr/share/meridian/artifacts"

// ManifestFile is the manifest the build writes next to the binaries:
// one line "name version arch sha256 size file" per binary.
const ManifestFile = "manifest.txt"

// ErrUnavailable: the panel has no verified copy of a pinned binary.
var ErrUnavailable = errors.New("面板没有这个二进制的已校验副本")

// Status is what the panel knows about one pinned binary.
type Status struct {
	Pin
	// Available: the file exists and matched the pin when loaded.
	Available bool `json:"available"`
	// Error says why it is not available (missing, wrong size, digest
	// mismatch, manifest disagreement).
	Error string `json:"error,omitempty"`
}

// Bundle is a loaded artifact directory.
type Bundle struct {
	dir    string
	pins   []Pin
	mu     sync.Mutex
	status map[string]Status
}

func key(name, arch string) string { return name + "/" + arch }

// Load verifies every pinned binary in dir against the embedded pins:
// the file <name>-<arch> must exist, be a regular file of exactly the
// pinned size and have the pinned SHA-256. When dir holds a manifest.txt
// (the image build writes one), every entry must agree with the pins too;
// an entry that disagrees makes that binary unavailable. Load never fails:
// what is wrong is recorded per binary and refused when used.
func Load(dir string) *Bundle { return LoadPins(dir, pins) }

// LoadPins is Load against other pins (tests: fake binaries with their own
// digests; the panel always uses Load and the embedded pins).
func LoadPins(dir string, ps []Pin) *Bundle {
	b := &Bundle{dir: dir, pins: append([]Pin(nil), ps...), status: map[string]Status{}}
	manifest, merr := readManifest(dir)
	for _, p := range b.pins {
		st := Status{Pin: p}
		if err := verifyFile(filepath.Join(dir, p.File()), p); err != nil {
			st.Error = err.Error()
		} else if merr != nil {
			st.Error = merr.Error()
		} else if m, ok := manifest[key(p.Name, p.Arch)]; manifest != nil && !ok {
			st.Error = "manifest.txt 没有这一项"
		} else if ok && m != manifestLine(p) {
			st.Error = fmt.Sprintf("manifest.txt 与面板固定的版本不一致（%q）", m)
		} else {
			st.Available = true
		}
		b.status[key(p.Name, p.Arch)] = st
	}
	return b
}

// Dir is the loaded directory.
func (b *Bundle) Dir() string {
	if b == nil {
		return ""
	}
	return b.dir
}

// Status reports one binary. An unknown name or architecture is reported
// as unavailable with the reason.
func (b *Bundle) Status(name, arch string) Status {
	p, ok := b.pinFor(name, arch)
	if !ok {
		return Status{Pin: Pin{Name: name, Arch: arch}, Error: fmt.Sprintf("面板没有为架构 %s 固定 %s 的版本", orDash(arch), name)}
	}
	if b == nil {
		return Status{Pin: p, Error: "面板没有加载二进制目录"}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if st, ok := b.status[key(name, arch)]; ok {
		return st
	}
	return Status{Pin: p, Error: "面板没有加载这个二进制"}
}

func (b *Bundle) pinFor(name, arch string) (Pin, bool) {
	if b == nil {
		return PinFor(name, arch)
	}
	for _, p := range b.pins {
		if p.Name == name && p.Arch == arch {
			return p, true
		}
	}
	return Pin{}, false
}

// Statuses reports every pinned binary, sorted by name and architecture.
func (b *Bundle) Statuses() []Status {
	var out []Status
	ps := pins
	if b != nil {
		ps = b.pins
	}
	for _, p := range ps {
		out = append(out, b.Status(p.Name, p.Arch))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Arch < out[j].Arch
	})
	return out
}

// Read returns the bytes of name for arch after verifying them again
// against the pin (a file changed after Load is refused, and that binary
// is marked unavailable from then on).
func (b *Bundle) Read(name, arch string) ([]byte, Pin, error) {
	st := b.Status(name, arch)
	if !st.Available {
		return nil, st.Pin, fmt.Errorf("%w：%s（%s）：%s", ErrUnavailable, name, orDash(arch), st.Error)
	}
	data, err := readVerified(filepath.Join(b.dir, st.File()), st.Pin)
	if err != nil {
		b.mu.Lock()
		st.Available, st.Error = false, err.Error()
		b.status[key(name, arch)] = st
		b.mu.Unlock()
		return nil, st.Pin, fmt.Errorf("%w：%s（%s）：%s", ErrUnavailable, name, arch, err.Error())
	}
	return data, st.Pin, nil
}

func verifyFile(path string, p Pin) error {
	_, err := readVerified(path, p)
	return err
}

// readVerified reads at most p.Size+1 bytes and checks size and digest.
func readVerified(path string, p Pin) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("文件 %s 不存在", filepath.Base(path))
		}
		return nil, fmt.Errorf("读不到 %s：%v", filepath.Base(path), err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s 不是普通文件", filepath.Base(path))
	}
	if st.Size() != p.Size {
		return nil, fmt.Errorf("%s 大小 %d 字节，固定的是 %d 字节", filepath.Base(path), st.Size(), p.Size)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("读不到 %s：%v", filepath.Base(path), err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, p.Size+1))
	if err != nil {
		return nil, fmt.Errorf("读不到 %s：%v", filepath.Base(path), err)
	}
	if int64(len(data)) != p.Size {
		return nil, fmt.Errorf("%s 读到 %d 字节，固定的是 %d 字节", filepath.Base(path), len(data), p.Size)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != p.SHA256 {
		return nil, fmt.Errorf("%s 的 SHA-256 是 %s，固定的是 %s：拒绝使用", filepath.Base(path), got, p.SHA256)
	}
	return data, nil
}

// SHA256Of is the hex SHA-256 of data.
func SHA256Of(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func manifestLine(p Pin) string {
	return strings.Join([]string{p.Name, p.Version, p.Arch, p.SHA256, strconv.FormatInt(p.Size, 10), p.File()}, " ")
}

// ManifestText is the manifest.txt the build writes for pins (tests and
// tooling).
func ManifestText(ps []Pin) string {
	var b bytes.Buffer
	b.WriteString("# meridian-artifacts 1\n")
	for _, p := range ps {
		b.WriteString(manifestLine(p) + "\n")
	}
	return b.String()
}

// readManifest returns nil, nil when dir has no manifest.
func readManifest(dir string) (map[string]string, error) {
	raw, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("读不到 manifest.txt：%v", err)
	}
	if len(raw) > 64<<10 {
		return nil, errors.New("manifest.txt 过大")
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.Join(strings.Fields(line), " ")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 6 {
			return nil, fmt.Errorf("manifest.txt 有无法读懂的行 %q", line)
		}
		out[key(f[0], f[2])] = line
	}
	return out, nil
}

func orDash(s string) string {
	if s == "" {
		return "未知"
	}
	return s
}
