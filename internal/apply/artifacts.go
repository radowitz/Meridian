package apply

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/radowitz/meridian/internal/artifacts"
	"github.com/radowitz/meridian/internal/preflight"
)

// Panel-delivered binaries on the gateway (wstunnel for the WSS client).
// The gateway install writes them through the same bind mount as the other
// host files, at artifacts.HostPath (/usr/local/sbin/meridian-<name>), as
// part of the install transaction: the manifest records them (Artifacts),
// converge installs what the target manifest names and removes what only
// the source manifest names, a replaced copy is backed up in the hold
// directory so a compensation can put it back, and every copy is verified
// by SHA-256 before it is renamed into place.

// ArtifactSource hands out a verified binary (artifacts.Bundle).
type ArtifactSource interface {
	Read(name, arch string) ([]byte, artifacts.Pin, error)
}

// ManagedArtifact is one panel-delivered binary of a manifest.
type ManagedArtifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
	// Path is relative to the host root, like ManagedFile.Path.
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

func artifactRel(name string) string { return strings.TrimPrefix(artifacts.HostPath(name), "/") }

// planArtifacts resolves the binaries the gateway files run. Nil source:
// artifact handling is off (legacy callers and tests that do not install
// units needing one). Any binary that is not available refuses the
// install before anything is written.
func (a Applier) planArtifacts(local map[string]string) ([]ManagedArtifact, error) {
	if a.Artifacts == nil {
		return nil, nil
	}
	abs := map[string]string{}
	for rel, body := range local {
		abs["/"+strings.TrimPrefix(rel, "/")] = body
	}
	bins := preflight.FootprintOf(abs).Binaries
	if len(bins) == 0 {
		return nil, nil
	}
	if !artifacts.ValidArch(a.Arch) {
		return nil, fmt.Errorf("网关的 CPU 架构 %q 没有面板下发的二进制，拒绝安装；宿主上没有写入任何文件", a.Arch)
	}
	var out []ManagedArtifact
	for _, name := range bins {
		data, pin, err := a.Artifacts.Read(name, a.Arch)
		if err != nil {
			return nil, fmt.Errorf("网关要用的 %s 不可用，拒绝安装（宿主上没有写入任何文件）：%w", name, err)
		}
		if artifacts.SHA256Of(data) != pin.SHA256 {
			return nil, fmt.Errorf("%s 的内容与固定摘要不一致，拒绝安装", name)
		}
		out = append(out, ManagedArtifact{Name: name, Version: pin.Version, Arch: a.Arch, Path: artifactRel(name), SHA256: pin.SHA256, Size: pin.Size})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func (m Manifest) artifact(path string) (ManagedArtifact, bool) {
	for _, x := range m.Artifacts {
		if x.Path == path {
			return x, true
		}
	}
	return ManagedArtifact{}, false
}

func fileSHA256(p string) (string, bool) {
	f, err := os.Open(p)
	if err != nil {
		return "", false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > artifacts.MaxSize {
		return "", false
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, artifacts.MaxSize)); err != nil {
		return "", false
	}
	return hex.EncodeToString(h.Sum(nil)), true
}

func (a Applier) artifactBackupDir() string { return filepath.Join(a.holdDir(), "artifacts") }

// artifactBytes finds the bytes of x: the panel's verified copy when its
// pin is x, else a backup this transaction made of a replaced copy.
func (a Applier) artifactBytes(x ManagedArtifact) ([]byte, error) {
	if a.Artifacts != nil {
		if data, pin, err := a.Artifacts.Read(x.Name, x.Arch); err == nil && pin.SHA256 == x.SHA256 && artifacts.SHA256Of(data) == x.SHA256 {
			return data, nil
		}
	}
	if b, err := os.ReadFile(filepath.Join(a.artifactBackupDir(), x.SHA256)); err == nil && artifacts.SHA256Of(b) == x.SHA256 {
		return b, nil
	}
	return nil, fmt.Errorf("没有 %s %s（sha256 %s）的副本，不能把它放回宿主", x.Name, x.Version, x.SHA256)
}

// convergeArtifacts installs the binaries of to and removes those only
// from names. A copy already on the host with the right digest is left as
// it is; a Meridian copy with another digest is backed up first. A file at
// a path to names that neither manifest owns is never overwritten.
func (t *txn) convergeArtifacts(from, to Manifest) error {
	a := t.a
	if len(from.Artifacts) == 0 && len(to.Artifacts) == 0 {
		return nil
	}
	root := a.hostRoot()
	for _, x := range from.Artifacts {
		if _, keep := to.artifact(x.Path); keep {
			continue
		}
		if !allowed(x.Path) || !preflight.IsArtifactPath("/"+x.Path) {
			return fmt.Errorf("拒绝删除路径 %s", x.Path)
		}
		p := filepath.Join(root, filepath.FromSlash(x.Path))
		if sum, ok := fileSHA256(p); ok && sum != x.SHA256 {
			t.rep.Warnings = append(t.rep.Warnings, fmt.Sprintf("%s 在安装后被改过（摘要不再是 %s），保留没有删除", "/"+x.Path, x.SHA256[:12]))
			continue
		}
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	for _, x := range to.Artifacts {
		if !allowed(x.Path) || !preflight.IsArtifactPath("/"+x.Path) {
			return fmt.Errorf("拒绝写入路径 %s", x.Path)
		}
		p := filepath.Join(root, filepath.FromSlash(x.Path))
		cur, exists := fileSHA256(p)
		if exists && cur == x.SHA256 {
			continue
		}
		if st, err := os.Lstat(p); err == nil {
			if !st.Mode().IsRegular() || !exists {
				return fmt.Errorf("%s 不是普通文件，拒绝覆盖", "/"+x.Path)
			}
			prev, owned := from.artifact(x.Path)
			if !owned {
				return fmt.Errorf("%s 已存在且不属于 Meridian 的受管清单，拒绝覆盖", "/"+x.Path)
			}
			if cur != prev.SHA256 {
				t.rep.Warnings = append(t.rep.Warnings, fmt.Sprintf("%s 在安装后被改过，按固定版本替换", "/"+x.Path))
			}
			// Keep the replaced copy for a compensation.
			if old, err := os.ReadFile(p); err == nil && artifacts.SHA256Of(old) == cur {
				if err := writeDurable(filepath.Join(a.artifactBackupDir(), cur), old, 0o600); err != nil {
					return err
				}
			}
		}
		data, err := a.artifactBytes(x)
		if err != nil {
			return err
		}
		if err := writeHostFile(p, data, 0o755); err != nil {
			return err
		}
		if sum, ok := fileSHA256(p); !ok || sum != x.SHA256 {
			return errors.New("写入后的 " + "/" + x.Path + " 摘要不对，停止安装")
		}
	}
	return nil
}
