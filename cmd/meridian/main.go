package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/api"
	"github.com/radowitz/meridian/internal/artifacts"
	"github.com/radowitz/meridian/internal/hostexec"
	"github.com/radowitz/meridian/internal/lists"
	"github.com/radowitz/meridian/internal/pathquality"
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
	if len(os.Args) > 1 && os.Args[1] == "lists-update" {
		os.Exit(listsUpdate(os.Args[2:]))
	}
	// One pass of the gateway's relay-sharing controller, run by the
	// compiled meridian-failover.sh (root, on the host, independent of the
	// panel container). The script calls it with MERIDIAN_BIND=- so that an
	// older binary without this subcommand stops at the bind check below
	// with no side effect and the script uses its own fallback.
	if len(os.Args) > 1 && os.Args[1] == "path-step" {
		os.Exit(pathquality.RunStep(os.Args[2:], os.Stdout, os.Stderr))
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
		// Servers, SSH credentials and Cloudflare accounts with their
		// secrets: outside the snapshots, 0700/0600. Docker uses a volume of
		// its own (deploy/docker-compose.yml); default <data>/secrets.
		SecretsDir: os.Getenv("MERIDIAN_SECRETS_DIR"),
		WebDir:     os.Getenv("MERIDIAN_WEB_DIR"),
		Token:      token,
		// Every host runtime action goes through meridian-host. If it is not
		// reachable, installs and runtime rollbacks fail explicitly.
		Host: hostClient,
		// Unlock probes go through the same agent (/v1/probe), so the panel
		// container needs no NET_ADMIN / NET_RAW of its own.
		Prober: hostClient,
		// List updates ("update now") run on the host through the agent's
		// fixed list action (/v1/lists).
		Lists: hostClient,
		// Remote-access peer status (handshake, transfer) is read through
		// the agent's parameterless /v1/remote-access/status.
		RemoteStatus: hostClient,
		Upstream:     hostClient,
		// The gateway install pre-check is the agent's read-only
		// /v1/preflight (paths validated, fixed programs).
		HostPreflight: hostClient,
		// Panel-delivered binaries (wstunnel, SmartDNS): verified against the
		// pins compiled into this binary (internal/artifacts) at startup and
		// again before every transfer. The image ships them read-only at
		// artifacts.DefaultDir; MERIDIAN_ARTIFACTS_DIR names another
		// directory (air-gapped hosts) whose files must match the same pins.
		Artifacts: artifacts.Load(env("MERIDIAN_ARTIFACTS_DIR", artifacts.DefaultDir)),
	}
	for _, a := range srv.Artifacts.Statuses() {
		if a.Available {
			log.Printf("artifact %s %s %s ok (sha256 %s)", a.Name, a.Version, a.Arch, a.SHA256[:12])
		} else {
			log.Printf("artifact %s %s %s unavailable: %s (installs that need it are refused)", a.Name, a.Version, a.Arch, a.Error)
		}
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
	// Old Mesh credential file and topology ssh_* fields move into the
	// credential store (idempotent; errors name no secret).
	for _, err := range srv.MigrateCredentials() {
		log.Printf("credential migration incomplete: %v", err)
	}
	// Legacy exit pools become region groups (idempotent; one row write).
	if rep, err := st.MigrateRegionGroups(); err != nil {
		log.Printf("region-group migration failed: %v", err)
	} else if rep.Changed {
		log.Printf("region-group migration: created groups %v, %d rules, %d nodes", rep.CreatedGroups, rep.Rules, rep.Nodes)
	}
	srv.StartUnlockScheduler()
	// WSS certificates: a rotation starts on its own 30 days before expiry
	// (the panel then shows which ends to re-install, in order).
	srv.StartWSSScheduler()
	// At boot the LAN address may not exist yet (ifupdown allow-hotplug +
	// DHCP; Docker starts the container before the lease). Wait for it,
	// bounded and with one log line every 10 s, instead of crash-looping
	// on "bind: cannot assign requested address". Never falls back to
	// 0.0.0.0. On timeout the process exits with meridian-bind-not-ready.
	wait := api.DefaultBindWait
	if v := os.Getenv("MERIDIAN_BIND_WAIT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 {
			log.Fatalf("MERIDIAN_BIND_WAIT=%q: want a duration such as 180s", v)
		}
		wait = d
	}
	ln, err := api.ListenLAN(context.Background(), bind, wait, log.Printf)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("meridian panel listening on %s (LAN only). token file: %s", bind, filepath.Join(data, "panel.token"))
	if err := http.Serve(ln, srv.Handler()); err != nil {
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
	log.Printf("meridian host agent listening on %s (actions: activate, health, rollback, list update; read-only probe)", sock)
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

// listsUpdate is what the generated meridian-update-geosite.sh /
// meridian-update-chnroute.sh run (as root): one request to meridian-host's
// fixed list action, the same path as the panel's "update now". It takes
// only enumerated values and managed names; every one is checked again by
// the agent. Exit 0 every list updated, 1 nothing updated (or refused),
// 2 some lists kept their previous version.
func listsUpdate(args []string) int {
	fs := flag.NewFlagSet("lists-update", flag.ContinueOnError)
	kinds := fs.String("lists", "geosite,chnroute", "geosite and/or chnroute, comma separated")
	policy := fs.String("policy", string(lists.DefaultPolicy), "domestic | overseas | automatic")
	geosite := fs.String("geosite", "", "v2fly category names, comma separated (with geosite)")
	var kws []lists.Keyword
	fs.Func("keyword", "id=keyword (repeatable, with geosite)", func(v string) error {
		id, kw, ok := strings.Cut(v, "=")
		if !ok {
			return fmt.Errorf("want id=keyword")
		}
		kws = append(kws, lists.Keyword{ID: id, Value: kw})
		return nil
	})
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return 1
	}
	req := hostexec.ListsRequest{
		RequestID: fmt.Sprintf("cli-%d", time.Now().UnixNano()),
		Policy:    *policy,
		Lists:     splitComma(*kinds),
		Geosite:   splitComma(*geosite),
		Keywords:  kws,
	}
	c := &hostexec.Client{
		Socket:    env("MERIDIAN_HOST_SOCKET", hostexec.DefaultSocket),
		TokenFile: env("MERIDIAN_HOST_TOKEN_FILE", hostexec.DefaultTokenFile),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	rep, err := c.UpdateLists(ctx, req)
	for _, l := range rep.Lists {
		switch {
		case l.Updated:
			fmt.Printf("updated %s from %s (%d entries) %s\n", l.List, l.Source, l.Count, l.URL)
		default:
			fmt.Printf("kept    %s: %s\n", l.List, l.Error)
		}
	}
	if rep.DNSRestart != "" {
		fmt.Printf("restarted %s\n", rep.DNSRestart)
	}
	for _, w := range rep.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	switch {
	case err != nil:
		fmt.Fprintln(os.Stderr, "lists-not-updated:", err)
		return 1
	case rep.OK:
		fmt.Println("lists-updated")
		return 0
	case rep.Partial:
		fmt.Fprintln(os.Stderr, "lists-partial: some lists kept their previous version")
		return 2
	default:
		fmt.Fprintln(os.Stderr, "lists-not-updated:", rep.Error)
		return 1
	}
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
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
