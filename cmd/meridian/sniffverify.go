package main

// Hidden subcommands for deploy/verify-sniff-systemd.sh. They print or write
// nothing a gateway install uses; they exist so that the real-systemd check
// starts exactly what the install would start, rendered by the same code
// (compile.RenderSniffUnit, RenderSniffAccountUnit, RenderSniffAccountScript)
// with temporary names, ids and port, and reads the status socket with the
// host agent's own reader (hostexec.ReadSniffSocket).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/sniff"
)

// sniffVerifyRender writes, for the given names:
//
//	<unit-dir>/<unit>, <unit-dir>/<account-unit>   the two units
//	<script>                                       the account script (0755)
//	<fixture-dir>/decide.json, targets.json        a synthetic rule pair
//
// The forwarder's lists directory is the fixture directory.
func sniffVerifyRender(args []string) int {
	fs := flag.NewFlagSet("sniff-verify-render", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var s compile.SniffUnitSpec
	var unitDir, fixtureDir string
	fs.StringVar(&unitDir, "unit-dir", "", "directory the two unit files are written to")
	fs.StringVar(&fixtureDir, "fixture-dir", "", "directory of the synthetic snapshot and target file (readable by the account)")
	fs.StringVar(&s.Unit, "unit", "", "forwarder unit name")
	fs.StringVar(&s.AccountUnit, "account-unit", "", "account unit name")
	fs.StringVar(&s.User, "user", "", "account name")
	fs.IntVar(&s.UID, "uid", 0, "uid and gid")
	fs.StringVar(&s.AccountScript, "script", "", "account script path (not under /run)")
	fs.StringVar(&s.RuntimeDir, "runtime-dir", "", "RuntimeDirectory name")
	fs.StringVar(&s.Binary, "binary", "/usr/local/bin/meridian", "meridian executable the unit runs")
	fs.StringVar(&s.Listen, "listen", "", "forwarder address:port")
	fs.StringVar(&s.NeighIf, "neigh-if", "", "interface for client MAC lookup")
	fs.StringVar(&s.FwmarkAcceptOn, "fwmark-accept-on", "", "tcp_fwmark_accept value written at start (0 or 1)")
	fs.StringVar(&s.FwmarkAcceptOff, "fwmark-accept-off", "", "tcp_fwmark_accept value written after stop (0 or 1)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: meridian sniff-verify-render --unit-dir D --fixture-dir D --unit U --account-unit U --user N --uid N --script P --runtime-dir N --listen A:P --fwmark-accept-on 0|1 --fwmark-accept-off 0|1 [--binary P] [--neigh-if IF]")
		return 2
	}
	s.Ports = []int{80, 443}
	// The journal under a temporary StateDirectory of the same name
	// (/var/lib/<runtime-dir>; the script removes it).
	s.StateDir = s.RuntimeDir
	s.Snapshot = filepath.Join(fixtureDir, "decide.json")
	s.Targets = filepath.Join(fixtureDir, "targets.json")
	s.ListsDir = fixtureDir
	if err := s.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "meridian sniff-verify-render:", err)
		return 2
	}
	if !filepath.IsAbs(unitDir) {
		fmt.Fprintln(os.Stderr, "meridian sniff-verify-render: --unit-dir must be absolute")
		return 2
	}
	snap, targets := sniff.VerifyFixture()
	for _, f := range []struct {
		path string
		body string
		mode os.FileMode
	}{
		{filepath.Join(unitDir, s.Unit), compile.RenderSniffUnit(s), 0o644},
		{filepath.Join(unitDir, s.AccountUnit), compile.RenderSniffAccountUnit(s), 0o644},
		{s.AccountScript, compile.RenderSniffAccountScript(s), 0o755},
		{s.Snapshot, string(snap), 0o644},
		{s.Targets, string(targets), 0o644},
	} {
		if err := writeNew(f.path, f.body, f.mode); err != nil {
			fmt.Fprintln(os.Stderr, "meridian sniff-verify-render:", err)
			return 1
		}
	}
	fmt.Println(s.StatusSocket())
	return 0
}

// writeNew writes a file that must not exist yet (the script only renders
// into names it chose and checked to be free).
func writeNew(path, body string, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(body); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// sniffVerifyRead reads a status socket the way the host agent does and
// prints the health record. Exit 0: both reads answered with JSON; 1:
// absent, refused or not answered.
func sniffVerifyRead(args []string) int {
	fs := flag.NewFlagSet("sniff-verify-read", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	sock := fs.String("socket", "", "status socket")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || !strings.HasPrefix(*sock, "/") {
		fmt.Fprintln(os.Stderr, "usage: meridian sniff-verify-read --socket /run/<dir>/status.sock")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st := hostexec.ReadSniffSocket(ctx, *sock)
	err := error(nil)
	switch {
	case !st.Present:
		err = errors.New("no socket at " + *sock)
	case st.Error != "":
		err = errors.New(st.Error)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "meridian sniff-verify-read:", err)
		return 1
	}
	out, _ := json.Marshal(st.Health)
	fmt.Println(string(out))
	return 0
}

// sniffSelfCheckCmd ("meridian sniff-selfcheck --socket S --targets F") has
// the forwarder behind S run its path self-check for the rule pair whose
// target file is F, judges it like the install does
// (hostexec.EvaluateSniffCheck) and prints line-oriented evidence for the
// generated verify script: the marker, "verdict <code>", "default <target>
// <status>", "reason <text>", "failing <target>: <reason>", "note <text>",
// "target <target> <status> <outcome>…". Exit 0: the default target passed;
// 3: it failed, or no result for these rules came in time; 4: not
// evaluated (no socket, unreadable target file, bad usage).
func sniffSelfCheckCmd(args []string) int {
	fs := flag.NewFlagSet("sniff-selfcheck", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	sock := fs.String("socket", "", "status socket")
	targets := fs.String("targets", "", "target file")
	wait := fs.Duration("wait", 10*time.Second, "wait for the forwarder to load the rule pair")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || !strings.HasPrefix(*sock, "/") || !strings.HasPrefix(*targets, "/") || *wait <= 0 || *wait > time.Minute {
		fmt.Fprintln(os.Stderr, "usage: meridian sniff-selfcheck --socket /run/<dir>/status.sock --targets /etc/meridian/sniff/targets.json [--wait 10s]")
		return 4
	}
	fmt.Println(sniff.SelfCheckMarker)
	b, err := os.ReadFile(*targets)
	if err != nil {
		fmt.Println("verdict unavailable")
		fmt.Println("reason cannot read the target file:", err)
		return 4
	}
	sum := sha256.Sum256(b)
	want := hex.EncodeToString(sum[:])
	ctx, cancel := context.WithTimeout(context.Background(), *wait+sniff.SelfCheckBudget+15*time.Second)
	defer cancel()
	rep := &hostexec.SniffCheckReport{RequestedAt: time.Now(), TargetsSHA256: want}
	res, code, err := sniff.InstalledSelfCheck(ctx, *sock, want, *wait)
	rep.ReadAt = time.Now()
	if err != nil {
		rep.Code, rep.Error = code, err.Error()
	}
	rep.Result = res
	v := hostexec.EvaluateSniffCheck(rep, want)
	fmt.Println("verdict", v.Code)
	if res != nil {
		st := "none"
		if d := res.DefaultResult(); d != nil {
			st = d.Status
		}
		fmt.Printf("default %s %s\n", res.Default, st)
		for _, t := range res.Targets {
			var outs []string
			for _, p := range t.Resolvers {
				outs = append(outs, p.Server+"="+p.Outcome)
			}
			if t.Connect != nil {
				outs = append(outs, "tcp:"+t.Connect.Server+"="+t.Connect.Outcome)
			}
			fmt.Printf("target %s %s %s\n", t.Target, t.Status, strings.Join(outs, " "))
		}
	}
	if v.Reason != "" {
		fmt.Println("reason", v.Reason)
	}
	for _, f := range v.Failing {
		fmt.Println("failing", f)
	}
	for _, n := range v.Notes {
		fmt.Println("note", n)
	}
	switch {
	case v.OK:
		return 0
	case code == sniff.CheckNoSocket:
		return 4
	}
	return 3
}
