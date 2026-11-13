package apply

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
)

// fakeKernel answers sysctl reads like a gateway after meridian-up.sh ran:
// every key the files set, forwarding on, plus whatever the test overrides.
type fakeKernel map[string]string

func (k fakeKernel) read(key string) (string, error) {
	if v, ok := k[key]; ok {
		return v, nil
	}
	return "", errors.New("no such key")
}

// An existing gateway: deploy/debian/install.sh wrote its own
// 99-meridian.conf (with a stale line the compiled file no longer has). The
// first panel install rewrites the whole file, reads every key back from the
// kernel and says what is in effect, what is not, and what is stale.
func TestInstallReportsManagedSysctlEffectiveState(t *testing.T) {
	r := newRig(t)
	old := "net.ipv4.ip_forward=0\nnet.ipv6.conf.all.forwarding=0\nnet.ipv4.conf.default.accept_redirects=0\nnet.ipv6.conf.eth7.accept_ra=2\n"
	dest := filepath.Join(r.host, filepath.FromSlash(SysctlFile))
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	b := compileTopo(t, defaults.Example())
	files := nodeFiles(b.Files, "gw")
	kernel := fakeKernel{}
	for _, l := range parseSysctlFile(files[SysctlFile]) {
		kernel[l.key] = l.val
	}
	for _, l := range parseSysctlFile(files[ForwardingFile]) {
		kernel[l.key] = l.val
	}
	kernel["net.ipv4.conf.default.accept_redirects"] = "0"
	// Someone (Docker, another sysctl file) changed one key after up.
	kernel["net.ipv4.conf.all.rp_filter"] = "1"
	// The per-interface accept_ra key does not exist (interface absent).
	var raKey string
	for _, l := range parseSysctlFile(files[SysctlFile]) {
		if strings.HasSuffix(l.key, ".accept_ra") {
			raKey = l.key
			delete(kernel, l.key)
		}
	}
	if raKey == "" {
		t.Fatal("compiled gateway sysctl has no accept_ra line")
	}

	ap := r.applier()
	ap.ReadSysctl = kernel.read
	res, err := ap.Apply(b, false)
	if err != nil {
		t.Fatal(err)
	}
	// Written: the file on the host is exactly the compiled one.
	if got := readHost(t, r.host, SysctlFile); got != files[SysctlFile] {
		t.Fatalf("host file not replaced whole:\n%s", got)
	}
	rep := res.Host.Sysctl
	if rep == nil || !rep.Checked {
		t.Fatalf("no checked sysctl report: %+v", rep)
	}
	state := map[string]SysctlEntry{}
	for _, e := range rep.Written {
		state[e.File+" "+e.Key] = e
	}
	sys, fwd := "/"+SysctlFile, "/"+ForwardingFile
	if e := state[sys+" net.ipv4.conf.all.rp_filter"]; e.State != SysctlDiffers || e.Got != "1" || e.Want != "2" {
		t.Fatalf("rp_filter: %+v", e)
	}
	if e := state[sys+" "+raKey]; e.State != SysctlMissing {
		t.Fatalf("accept_ra: %+v", e)
	}
	if e := state[sys+" net.ipv4.ip_forward"]; e.State != SysctlBootOnly || e.Want != "0" || e.Got != "1" {
		t.Fatalf("boot forwarding line: %+v", e)
	}
	if e := state[fwd+" net.ipv4.ip_forward"]; e.State != SysctlInEffect {
		t.Fatalf("forwarding.conf: %+v", e)
	}
	if e := state[sys+" net.ipv4.conf.all.send_redirects"]; e.State != SysctlInEffect {
		t.Fatalf("send_redirects: %+v", e)
	}
	if rep.Problems != 2 {
		t.Fatalf("problems %d: %+v", rep.Problems, rep.Written)
	}
	// Stale: lines only the old file had, with their current kernel value.
	if len(rep.Removed) != 2 || rep.Removed[0].Key != "net.ipv4.conf.default.accept_redirects" || rep.Removed[0].Got != "0" ||
		rep.Removed[1].Key != "net.ipv6.conf.eth7.accept_ra" || rep.Removed[1].State != SysctlStale || rep.Removed[1].Got != "" {
		t.Fatalf("removed %+v", rep.Removed)
	}
	// Shown: each problem and the stale lines are warnings of the install.
	w := strings.Join(res.Host.Warnings, "\n")
	for _, want := range []string{"net.ipv4.conf.all.rp_filter 现在是 1", raKey, "net.ipv6.conf.eth7.accept_ra", "保留原值直到重启"} {
		if !strings.Contains(w, want) {
			t.Fatalf("warning %q missing:\n%s", want, w)
		}
	}

	// A second install with everything in effect: no problems, nothing stale.
	kernel["net.ipv4.conf.all.rp_filter"] = "2"
	kernel[raKey] = "2"
	res, err = ap.Apply(b, false)
	if err != nil {
		t.Fatal(err)
	}
	if rep := res.Host.Sysctl; rep == nil || rep.Problems != 0 || len(rep.Removed) != 0 {
		t.Fatalf("second install: %+v", rep)
	}
	for _, w := range res.Host.Warnings {
		if strings.Contains(w, "内核") {
			t.Fatalf("unexpected sysctl warning: %s", w)
		}
	}
}

// A test host root without ReadSysctl: the files are written, the kernel is
// not read, and the report says so instead of claiming an effect.
func TestSysctlReportNotCheckedWithoutKernel(t *testing.T) {
	r := newRig(t)
	res, err := r.applier().Apply(compileTopo(t, defaults.Example()), false)
	if err != nil {
		t.Fatal(err)
	}
	rep := res.Host.Sysctl
	if rep == nil || rep.Checked || rep.Reason == "" || rep.Problems != 0 {
		t.Fatalf("%+v", rep)
	}
	for _, e := range rep.Written {
		if e.State == SysctlInEffect || e.Got != "" {
			t.Fatalf("claimed an effect without reading the kernel: %+v", e)
		}
	}
}

func TestProcSysctlPathKeepsInterfaceDots(t *testing.T) {
	for key, want := range map[string]string{
		"net.ipv4.ip_forward":                  "/proc/sys/net/ipv4/ip_forward",
		"net.ipv6.conf.all.forwarding":         "/proc/sys/net/ipv6/conf/all/forwarding",
		"net.ipv4.conf.eth0.100.rp_filter":     "/proc/sys/net/ipv4/conf/eth0.100/rp_filter",
		"net.ipv6.conf.ens192.accept_ra":       "/proc/sys/net/ipv6/conf/ens192/accept_ra",
		"net.ipv4.neigh.eth0.gc_stale_time":    "/proc/sys/net/ipv4/neigh/eth0/gc_stale_time",
		"net.ipv4.conf.default.send_redirects": "/proc/sys/net/ipv4/conf/default/send_redirects",
	} {
		if got := procSysctlPath(key); got != filepath.FromSlash(want) {
			t.Errorf("%s: %s", key, got)
		}
	}
	if got := parseSysctlFile("# c\n; c\n-net.ipv4.ip_forward = 1\nnet/ipv6/conf/all/forwarding=0\nbogus\n"); len(got) != 2 || got[0].key != "net.ipv4.ip_forward" || got[0].val != "1" || got[1].key != "net.ipv6.conf.all.forwarding" {
		t.Fatalf("%+v", got)
	}
}
