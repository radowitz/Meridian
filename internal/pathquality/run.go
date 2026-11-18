package pathquality

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Default paths on the gateway (the compiled failover script passes them
// explicitly).
const (
	ConfigPath = "/etc/meridian/path-quality.json"
	StatePath  = "/run/meridian/pathq/state.json"
	StatusPath = "/run/meridian/upstream"
)

// LoadState reads a saved state (nil when missing or unreadable: the
// controller then starts from NewState).
func LoadState(path string) *State {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var st State
	if json.Unmarshal(b, &st) != nil {
		return nil
	}
	return &st
}

// writeAtomic writes via a temporary file in the same directory.
func writeAtomic(path string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pathq-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	return os.Rename(name, path)
}

// RunStep is "meridian path-step": one pass of measure → decide → stage.
// Only the locked shell applier may publish these candidate files after applying
// every route and nft operation. State/status are inputs, never outputs here.
//
// printing the decision for the shell (exit 0), or exiting non-zero with
// nothing on stdout (the shell then uses its fallback for this pass).
//
//	meridian path-step --config F --state F --status F [--now EPOCH]
//
// --now fixes the pass's clock (tests drive passes without waiting).
func RunStep(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("path-step", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", ConfigPath, "compiled path-quality config")
	statePath := fs.String("state", StatePath, "controller state file")
	statusPath := fs.String("status", StatusPath, "upstream status record")
	candidate := fs.String("candidate", "", "private candidate directory supplied by the locked applier")
	qosPath := fs.String("qos", QoSPath, "QoS verdict file of the speed tests")
	nowFlag := fs.Int64("now", 0, "pass time (epoch seconds; tests)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *candidate == "" {
		fmt.Fprintln(stderr, "path-step: a candidate directory and no positional arguments are required")
		return 2
	}
	c, err := LoadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "path-step:", err)
		return 2
	}
	now := time.Now().Unix()
	if *nowFlag > 0 {
		now = *nowFlag
	}
	st := LoadState(*statePath)
	if st == nil {
		st = stateFromAppliedStatus(c, *statusPath, now)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	m := Measurer{QoSPath: *qosPath}.Measure(ctx, c, st, now)
	st, d := Step(c, st, m)
	out := FormatDecision(d)
	if _, err := ParseDecision(c, out); err != nil {
		// Never hand the shell something it would refuse anyway.
		fmt.Fprintln(stderr, "path-step: internal decision refused:", err)
		return 3
	}
	b, err := json.Marshal(st)
	if err == nil {
		err = writeAtomic(filepath.Join(*candidate, "state"), b, 0o600)
	}
	if err != nil {
		fmt.Fprintln(stderr, "path-step: candidate state:", err)
		return 4
	}
	if err := writeAtomic(filepath.Join(*candidate, "status"), []byte(FormatStatus(c, st, now, "go")), 0o644); err != nil {
		fmt.Fprintln(stderr, "path-step: candidate status:", err)
		return 4
	}
	if _, err := io.WriteString(stdout, out); err != nil {
		return 4
	}
	return 0
}

// A shell fallback has no Go measurement history. Seed only the last applied
// carrying decision and its clock, so returning to Go cannot invent a switch.
func stateFromAppliedStatus(c Config, path string, now int64) *State {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	st := NewState(c, now)
	lines := strings.Split(string(b), "\n")
	if len(lines) == 0 || lines[0] != StatusHeader2 {
		return nil
	}
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "path":
			st.Upstream = f[1]
		case "designated":
			st.Designated = f[1]
		case "since":
			st.UpstreamSince, _ = strconv.ParseInt(f[1], 10, 64)
		case "switched":
			st.LastSwitch, _ = strconv.ParseInt(f[1], 10, 64)
		case "relay":
			if len(f) < 6 {
				return nil
			}
			r := st.Relays[f[1]]
			if r == nil {
				return nil
			}
			r.Leg = f[2]
			r.Weight, err = strconv.Atoi(f[4])
			if err != nil {
				return nil
			}
		}
	}
	if _, err := ParseDecision(c, FormatDecision(decisionOf(c, st))); err != nil {
		return nil
	}
	return st
}
