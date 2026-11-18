package apply

// The remote-access fast path inside the install transaction.
//
// With Applier.PeerSync set, an install whose only difference from what is
// installed is the content of etc/wireguard/mra.conf is activated by the
// host agent's peer sync (hostexec remote_access.go: wg-quick strip +
// wg syncconf, interface not restarted) instead of "activate". Everything
// else is the ordinary transaction: journal, snapshot rotation (version
// +1, rollback-able), installed copy and commit. A failed sync compensates
// through the same path: the previous mra.conf is written back and synced,
// so the running peer set follows it. Any other difference refuses the
// install before anything is written (ErrNotPeerOnly).

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/radowitz/meridian/internal/hostexec"
)

// ErrNotPeerOnly: the fast path was asked for a change that is not limited
// to the remote-access peers. Nothing was written.
var ErrNotPeerOnly = errors.New("改动不只是远程接入的 peer：需要完整安装")

// ErrNoPeerSync: the host boundary has no peer sync. Nothing was written.
var ErrNoPeerSync = errors.New("宿主执行通道不支持远程接入快速生效")

// PeerSyncer is the host boundary's peer sync (hostexec.Client).
type PeerSyncer interface {
	PeerSync(ctx context.Context, req hostexec.PeerSyncRequest) (hostexec.Result, error)
}

// PeerSyncFiles are the gateway files a remote-access device change may
// change: the remote-access config (which must change) and the local check
// script, which lists the device addresses it tests and is only run by an
// operator. Paths are relative to the host root.
var PeerSyncFiles = []string{hostexec.RemoteAccessConf, "usr/local/sbin/meridian-verify.sh"}

// PeerOnlyDiff reports whether a manifest difference is a remote-access
// peer change only: mra.conf changed, possibly the check script, nothing
// else (no file added or removed, no runtime resource).
func PeerOnlyDiff(d ManifestDiff) bool {
	if !contains(d.FilesChanged, hostexec.RemoteAccessConf) {
		return false
	}
	for _, f := range d.FilesChanged {
		if !contains(PeerSyncFiles, f) {
			return false
		}
	}
	d.FilesChanged = nil
	return d.Empty()
}

// PeerOnlyChange reports whether going from one installed manifest to the
// other is a remote-access peer change only (PeerOnlyDiff) with the same
// origin, resolver flag and binaries, and mra in both.
func PeerOnlyChange(from, to Manifest) bool {
	if from.Empty() || from.Origin != "" || to.Origin != "" || from.DNS != to.DNS {
		return false
	}
	if !reflect.DeepEqual(from.Artifacts, to.Artifacts) {
		return false
	}
	return PeerOnlyDiff(DiffManifests(from, to)) && contains(from.Interfaces, "mra") && contains(to.Interfaces, "mra")
}

// peerConverge writes the PeerSyncFiles of to (secrets injected; mra.conf
// 0600) and asks the agent to sync the running peers to mra.conf.
func (t *txn) peerConverge(to Manifest, toFiles map[string]string, tag string) error {
	files := map[string]string{}
	for _, p := range PeerSyncFiles {
		if body, ok := toFiles[p]; ok {
			files[p] = body
		}
	}
	if _, ok := files[hostexec.RemoteAccessConf]; !ok {
		return ErrNotPeerOnly
	}
	planned, err := t.a.prepareHost(files)
	if err != nil {
		return err
	}
	var digest string
	for _, f := range planned {
		if f.rel == hostexec.RemoteAccessConf {
			if f.mode != 0o600 {
				return fmt.Errorf("远程接入配置的权限必须是 0600")
			}
			digest = hostexec.FileDigest(f.body)
		}
		if err := writeHostFile(filepath.Join(t.a.hostRoot(), filepath.FromSlash(f.rel)), f.body, f.mode); err != nil {
			return err
		}
	}
	if t.rt == nil {
		return nil // files only (test host root without a runtime)
	}
	ps, ok := t.rt.(PeerSyncer)
	if !ok {
		return ErrNoPeerSync
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	res, err := ps.PeerSync(ctx, hostexec.PeerSyncRequest{Transaction: t.reqID(tag), Digest: digest})
	t.rep.Steps = append(t.rep.Steps, res.Steps...)
	t.rep.Warnings = append(t.rep.Warnings, res.Warnings...)
	if err != nil {
		return err
	}
	if !res.OK {
		return fmt.Errorf("远程接入快速生效失败：%s", res.Error)
	}
	return nil
}

// checkPeerOnly is the fast path's gate inside Apply, under the lock and
// before anything is written.
func (a Applier) checkPeerOnly(rt Runtime, from, to Manifest) error {
	if !PeerOnlyChange(from, to) {
		return ErrNotPeerOnly
	}
	if rt != nil {
		if _, ok := rt.(PeerSyncer); !ok {
			return ErrNoPeerSync
		}
	} else if filepath.Clean(a.hostRoot()) == "/" {
		return ErrNoHostExec
	}
	if _, err := os.Stat(a.installedDir()); err != nil {
		return ErrNotPeerOnly
	}
	return nil
}

// InstalledConfig returns the installed copy of one of this node's files
// (redacted: placeholders, never secrets). ok is false when there is none.
func (a Applier) InstalledConfig(rel string) (string, bool, error) {
	files, err := readNodeFiles(a.installedDir(), a.localID())
	if err != nil {
		return "", false, err
	}
	body, ok := files[rel]
	return body, ok, nil
}
