package apply

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/radowitz/meridian/internal/hostexec"
)

// Gateway withdraw ("撤回") through the host transaction.
//
// A withdraw converges the host from the installed manifest to a
// "withdrawn" manifest (Origin OriginWithdrawn) that owns only the LAN
// guard: the boot file etc/nftables.d/meridian-guard.nft and the table
// inet meridian_guard. Everything else the installed manifest lists (files,
// WireGuard interfaces, units, the inet meridian table, policy route tables
// and their rules) is removed through the agent's fixed withdraw action,
// which turns forwarding off first, stops meridian.service and verifies the
// guard is still loaded afterwards. Nothing outside the manifest is touched:
// meridian.service, meridian-guard.service and meridian-host.service
// (installed by deploy/debian/install.sh), Docker, the SmartDNS package or
// container, other nft tables, other WireGuard interfaces and the panel's
// data directory (snapshots stay, so a reinstall is possible) are kept.
//
// Guard decision: the LAN stays fail closed after a withdraw. The guard
// drops forwarded LAN traffic that Meridian did not classify; with the
// classification gone it drops all of it, so LAN clients that still use
// this host as their gateway lose connectivity instead of leaving via ROS
// unguarded. meridian-guard.service keeps loading it at boot. Removing the
// guard is a separate, explicit step (WithdrawGuard) that the panel only
// offers after a completed withdraw; it uses the agent's rollback action,
// which turns forwarding off before deleting the table.
//
// Both are ordinary host transactions: the journal is persisted, a failure
// is compensated back to the installed state (the withdraw is undone and
// the data plane re-activated), a failed compensation leaves the journal
// for Recover, and nothing is reported as done before the agent verified it.

var (
	// ErrNothingInstalled: no managed installation on the gateway.
	ErrNothingInstalled = errors.New("网关上没有受管的 Meridian 安装（没有安装清单），没有可撤回的内容")
	// ErrWithdrawLegacy: a pre-manifest data plane is on the host.
	ErrWithdrawLegacy = errors.New("网关上是旧版 Meridian（没有安装清单）：无法按清单撤回。先用「安装到网关」接管它（接管失败会说明原因），再撤回；宿主上没有改动")
	// ErrNoGuardFile: the installed manifest has no guard to keep.
	ErrNoGuardFile = errors.New("已安装清单里没有局域网兜底表（etc/nftables.d/meridian-guard.nft 与 inet meridian_guard）：撤回后局域网不能保持兜底拒绝，已拒绝；先安装当前版本再撤回")
	// ErrNotWithdrawn: the guard can only be released after a withdraw.
	ErrNotWithdrawn = errors.New("网关还没有撤回：先撤回，再单独移除兜底表")
	// ErrWithdrawnState: rollback is not offered on a withdrawn gateway.
	ErrWithdrawnState = errors.New("网关已撤回（只保留兜底表）：恢复请重新「安装到网关」（含安装前预检），不经回滚")
)

// WithdrawSet names what a withdraw removes or would remove.
type WithdrawSet struct {
	Files       []string `json:"files"`
	Interfaces  []string `json:"interfaces"`
	Units       []string `json:"units"`
	NFTTables   []string `json:"nft_tables"`
	RouteTables []int    `json:"route_tables"`
}

// WithdrawResult is the outcome of Withdraw / WithdrawGuard.
type WithdrawResult struct {
	// State: withdrawn (down to the guard), guard_released (nothing of
	// Meridian left in the manifest), already_withdrawn (re-run: the agent
	// re-checked forwarding off and the guard), not_installed.
	State   string      `json:"state"`
	Removed WithdrawSet `json:"removed"`
	// Kept is what stays on purpose.
	Kept []string    `json:"kept"`
	Host *HostReport `json:"host,omitempty"`
}

// GatewayKept lists what a gateway withdraw keeps on purpose.
func GatewayKept(guard bool) []string {
	out := []string{}
	if guard {
		out = append(out, "局域网兜底表 inet meridian_guard、它的开机文件 /etc/nftables.d/meridian-guard.nft 和 meridian-guard.service：局域网转发保持兜底拒绝（单独确认后才移除）")
	}
	return append(out,
		"转发保持关闭（撤回第一步就关掉，撤回不会打开它）",
		"meridian.service、meridian-guard.service、meridian-host.service（deploy/debian/install.sh 安装的宿主部分；meridian-up.sh 删除后 meridian.service 开机会被跳过）",
		"面板容器、数据目录和配置快照（之后可以重新安装）",
		"Docker、SmartDNS 软件包或容器（其配置文件 /etc/smartdns/smartdns.conf 若在清单里会被删除，正在运行的解析器保持旧配置直到重启）、其他 nft 表、不属于 Meridian 的 WireGuard 接口和软件包",
	)
}

// WithdrawPlan is what Withdraw would remove from the installed manifest.
func WithdrawPlan(m Manifest) WithdrawSet {
	ws := WithdrawSet{Files: []string{}, Interfaces: append([]string{}, m.Interfaces...), Units: append([]string{}, m.Units...),
		NFTTables: minus(m.NFTTables, []string{hostexec.GuardTable}), RouteTables: append([]int{}, m.RouteTables...)}
	for _, f := range m.Files {
		if f.Path != hostexec.GuardBootFile {
			ws.Files = append(ws.Files, "/"+f.Path)
		}
	}
	if ws.NFTTables == nil {
		ws.NFTTables = []string{}
	}
	sort.Strings(ws.Files)
	return ws
}

func guardOnly(from Manifest, version int64) (Manifest, bool) {
	h, ok := from.fileHash(hostexec.GuardBootFile)
	if !ok || !contains(from.NFTTables, hostexec.GuardTable) {
		return Manifest{}, false
	}
	m := Manifest{Schema: manifestSchema, Owner: "meridian", Node: from.Node, Version: version,
		Files:      []ManagedFile{{Path: hostexec.GuardBootFile, SHA256: h, Mode: fmt.Sprintf("%04o", hostMode(hostexec.GuardBootFile))}},
		Interfaces: []string{}, Units: []string{}, NFTTables: []string{hostexec.GuardTable}, RouteTables: []int{}, Sidecars: []string{},
		Origin: OriginWithdrawn}
	return m, true
}

// Withdraw takes the gateway down to the LAN guard in one host transaction
// (see the package comment above). A second call on a withdrawn gateway
// re-runs only the agent's checks (forwarding off, guard loaded).
func (a Applier) Withdraw() (*WithdrawResult, error) {
	rt, err := a.runtime()
	if err != nil {
		return nil, err
	}
	unlock, err := a.begin()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := a.probe(rt); err != nil {
		return nil, err
	}
	from, err := a.Installed()
	if err != nil {
		return nil, err
	}
	switch {
	case from.Empty():
		if fi, err := os.Stat(filepath.Join(a.hostRoot(), "usr", "local", "sbin", "meridian-up.sh")); err == nil && fi.Mode().IsRegular() {
			return nil, ErrWithdrawLegacy
		}
		return nil, ErrNothingInstalled
	case from.Withdrawn():
		res := &WithdrawResult{State: "already_withdrawn", Removed: WithdrawPlan(Manifest{}), Kept: GatewayKept(true)}
		res.Host = &HostReport{Transaction: "check-" + randID(), Kind: "withdraw", FromVersion: from.Version, ToVersion: from.Version}
		if rt != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			r, err := rt.Do(ctx, hostexec.Request{Action: hostexec.ActionWithdraw, RequestID: res.Host.Transaction})
			cancel()
			res.Host.Steps, res.Host.Warnings = r.Steps, r.Warnings
			if err == nil && !r.OK {
				err = errors.New(r.Error)
			}
			if err != nil {
				return res, fmt.Errorf("网关已撤回，但复查失败（转发关闭或兜底表未得到确认）：%w", err)
			}
		}
		res.Host.Committed = true
		return res, nil
	}
	to, ok := guardOnly(from, a.nextVersion())
	if !ok {
		return nil, ErrNoGuardFile
	}
	installed, err := readNodeFiles(a.installedDir(), a.localID())
	if err != nil {
		return nil, err
	}
	body, ok := installed[hostexec.GuardBootFile]
	if !ok {
		return nil, fmt.Errorf("%w（已安装副本里缺少该文件）", ErrNoGuardFile)
	}
	// Compensation re-installs from the installed copy: every WireGuard
	// config needs the gateway key, every secret placeholder its secret.
	// Checked before anything changes, so a failure can always be undone.
	if _, err := a.prepareHost(installed); err != nil {
		return nil, fmt.Errorf("撤回失败时需要用已安装副本恢复，但现在无法恢复它（%v）；已拒绝，宿主没有改动", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	to.CreatedAt = now
	snaps := a.snapshots()
	j := &journal{ID: newTxnID(), Kind: "withdraw", Install: true, Phase: phasePrepared,
		From: from, To: to, Before: snaps, After: snaps, Started: now}
	t := &txn{a: a, j: j, toFiles: map[string]string{hostexec.GuardBootFile: body}, rt: rt, rep: a.newReport(j)}
	if err := t.execute("撤回"); err != nil {
		return nil, err
	}
	return &WithdrawResult{State: "withdrawn", Removed: WithdrawPlan(from), Kept: GatewayKept(true), Host: t.rep}, nil
}

// WithdrawGuard removes the guard a withdraw kept: table inet meridian_guard
// (the agent turns forwarding off first) and its boot file. Only on a
// withdrawn gateway. Afterwards nothing of the Meridian data plane is left
// in the manifest; forwarding stays off until something else turns it on.
func (a Applier) WithdrawGuard() (*WithdrawResult, error) {
	rt, err := a.runtime()
	if err != nil {
		return nil, err
	}
	unlock, err := a.begin()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := a.probe(rt); err != nil {
		return nil, err
	}
	from, err := a.Installed()
	if err != nil {
		return nil, err
	}
	if from.Empty() {
		return &WithdrawResult{State: "not_installed", Removed: WithdrawPlan(Manifest{}), Kept: GatewayKept(false)}, nil
	}
	if !from.Withdrawn() {
		return nil, ErrNotWithdrawn
	}
	to := Manifest{Schema: manifestSchema, Owner: "meridian", Node: from.Node, Version: a.nextVersion(),
		Files: []ManagedFile{}, Interfaces: []string{}, Units: []string{}, NFTTables: []string{}, RouteTables: []int{}, Sidecars: []string{}}
	now := time.Now().UTC().Format(time.RFC3339)
	snaps := a.snapshots()
	j := &journal{ID: newTxnID(), Kind: "withdraw_guard", Install: true, Phase: phasePrepared,
		From: from, To: to, Before: snaps, After: snaps, Started: now}
	t := &txn{a: a, j: j, toFiles: map[string]string{}, rt: rt, rep: a.newReport(j)}
	if err := t.execute("移除兜底表"); err != nil {
		return nil, err
	}
	removed := WithdrawPlan(Manifest{})
	removed.Files = []string{"/" + hostexec.GuardBootFile}
	removed.NFTTables = []string{hostexec.GuardTable}
	return &WithdrawResult{State: "guard_released", Removed: removed, Kept: GatewayKept(false), Host: t.rep}, nil
}
