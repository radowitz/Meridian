package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/radowitz/meridian/internal/api"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/store"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "host-agent" {
		hostAgent()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "host-restore" {
		os.Exit(hostRestore(os.Args[2:]))
	}
	bind := env("MERIDIAN_BIND", "192.168.100.88:8787")
	if err := api.CheckBind(bind); err != nil {
		log.Fatal(err)
	}
	data := env("MERIDIAN_DATA", "/var/lib/meridian")
	if err := os.MkdirAll(data, 0o750); err != nil {
		log.Fatal(err)
	}
	token, err := api.LoadOrCreateToken(os.Getenv("MERIDIAN_TOKEN"), filepath.Join(data, "panel.token"))
	if err != nil {
		log.Fatal(err)
	}
	st, err := store.Open(filepath.Join(data, "meridian.db"))
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()
	hostClient := &hostexec.Client{
		Socket:    env("MERIDIAN_HOST_SOCKET", hostexec.DefaultSocket),
		TokenFile: env("MERIDIAN_HOST_TOKEN_FILE", hostexec.DefaultTokenFile),
	}
	srv := &api.Server{
		Store:   st,
		DataDir: data,
		WebDir:  os.Getenv("MERIDIAN_WEB_DIR"),
		Token:   token,
		// Every host runtime action goes through meridian-host. If it is not
		// reachable, installs and runtime rollbacks fail explicitly.
		Host: hostClient,
		// Unlock probes go through the same agent (/v1/probe), so the panel
		// container needs no NET_ADMIN / NET_RAW of its own.
		Prober: hostClient,
	}
	// A host transaction interrupted by a restart is compensated (or its
	// commit finished) before the panel serves requests. A failure is logged
	// and the journal kept; the panel then refuses new installs until the
	// operator recovers from the panel.
	if rep, err := srv.RecoverHost(); err != nil {
		log.Printf("unfinished host transaction could not be recovered: %v", err)
	} else if rep != nil {
		log.Printf("recovered host transaction %s (compensated=%v committed=%v)", rep.Transaction, rep.Compensated, rep.Committed)
	}
	srv.StartUnlockScheduler()
	log.Printf("meridian panel listening on %s (LAN only). token file: %s", bind, filepath.Join(data, "panel.token"))
	if err := http.ListenAndServe(bind, srv.Handler()); err != nil {
		log.Fatal(err)
	}
}

// hostAgent runs the host execution boundary. It must run on the host as
// root under deploy/debian/meridian-host.service; it listens only on a
// root-only Unix socket.
func hostAgent() {
	sock := env("MERIDIAN_HOST_SOCKET", hostexec.DefaultSocket)
	tokenFile := env("MERIDIAN_HOST_TOKEN_FILE", hostexec.DefaultTokenFile)
	if _, err := hostexec.LoadOrCreateToken(tokenFile); err != nil {
		log.Fatal(err)
	}
	uid := 0
	agent := &hostexec.Agent{
		// Re-read per request so rotating the token file needs no restart.
		Token:      func() (string, error) { return hostexec.LoadOrCreateToken(tokenFile) },
		LedgerPath: env("MERIDIAN_HOST_LEDGER", hostexec.DefaultLedger),
		PeerUID:    &uid,
	}
	l, err := hostexec.ListenUnix(sock)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("meridian host agent listening on %s (actions: activate, health, rollback; read-only probe)", sock)
	if err := agent.Serve(l); err != nil {
		log.Fatal(err)
	}
}

// hostRestore is run as root by deploy/debian/install.sh after an upgrade of
// a host whose data plane was running: it checks the data plane through
// meridian-host and, unless --health-only, re-activates it through the same
// agent action the panel uses when the check fails (hostexec.RestoreDataPlane).
// Exit 0 healthy, 1 not, 2 usage.
func hostRestore(args []string) int {
	mayActivate := true
	for _, a := range args {
		switch a {
		case "--health-only":
			mayActivate = false
		default:
			fmt.Fprintln(os.Stderr, "usage: meridian host-restore [--health-only]")
			return 2
		}
	}
	c := &hostexec.Client{
		Socket:    env("MERIDIAN_HOST_SOCKET", hostexec.DefaultSocket),
		TokenFile: env("MERIDIAN_HOST_TOKEN_FILE", hostexec.DefaultTokenFile),
	}
	var fwd func() (bool, error)
	if mayActivate {
		fwd = hostexec.ProcForwarding
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	id := fmt.Sprintf("upgrade-%d", time.Now().UnixNano())
	rep, err := hostexec.RestoreDataPlane(ctx, c, fwd, mayActivate, id)
	for _, st := range rep.Steps {
		state := "ok  "
		switch {
		case st.Skipped:
			state = "skip"
		case !st.OK:
			state = "FAIL"
		}
		fmt.Printf("%s %s %s\n", state, st.Name, firstLine(st.Detail))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "meridian-restore-failed:", err)
		return 1
	}
	if rep.Activated {
		fmt.Println("meridian-restore-ok: data plane re-activated through meridian-host and healthy")
	} else {
		fmt.Println("meridian-restore-ok: data plane healthy, nothing restarted")
	}
	return 0
}

func firstLine(s string) string {
	for i, r := range s {
		if r == '\n' {
			return s[:i]
		}
	}
	return s
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
