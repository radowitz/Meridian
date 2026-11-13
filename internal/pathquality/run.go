package pathquality

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

// RunStep is "meridian path-step": one pass of measure → decide → record,
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
	nowFlag := fs.Int64("now", 0, "pass time (epoch seconds; tests)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "path-step: unexpected arguments")
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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	m := Measurer{}.Measure(ctx, c, st, now)
	st, d := Step(c, st, m)
	out := FormatDecision(d)
	if _, err := ParseDecision(c, out); err != nil {
		// Never hand the shell something it would refuse anyway.
		fmt.Fprintln(stderr, "path-step: internal decision refused:", err)
		return 3
	}
	b, err := json.Marshal(st)
	if err == nil {
		err = writeAtomic(*statePath, b, 0o600)
	}
	if err != nil {
		fmt.Fprintln(stderr, "path-step: state:", err)
	}
	if err := writeAtomic(*statusPath, []byte(FormatStatus(c, st, now, "go")), 0o644); err != nil {
		fmt.Fprintln(stderr, "path-step: status:", err)
	}
	if _, err := io.WriteString(stdout, out); err != nil {
		return 4
	}
	return 0
}
