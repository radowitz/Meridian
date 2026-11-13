package credentials

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/model"
)

func wssStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Two listeners (relay "ali", hub "hub"), three links; "gw" dials two.
var testEnds = []model.WSSEnd{
	{LinkID: "gw-ali", ListenerID: "ali", DialerID: "gw"},
	{LinkID: "ali-hub", ListenerID: "hub", DialerID: "ali"},
	{LinkID: "gw-hub", ListenerID: "hub", DialerID: "gw"},
}

func TestWSSPathGeneration(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 2000; i++ {
		p, err := GenerateWSSPath()
		if err != nil {
			t.Fatal(err)
		}
		if !wssGenPathRe.MatchString(p) || len(p) != 2*WSSPathBytes || !ValidWSSPath(p) {
			t.Fatalf("bad path %q", p)
		}
		if seen[p] {
			t.Fatal("duplicate path")
		}
		seen[p] = true
	}
	for _, bad := range []string{"", "a b", "../x", "x/y", "x.y", "a$", strings.Repeat("a", 129), "\"x\"", "x|y"} {
		if ValidWSSPath(bad) {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestWSSCertParameters(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	name, _ := GenerateWSSServerName()
	if !strings.HasSuffix(name, ".invalid") || len(name) != len("w0123456789abcdef.invalid") {
		t.Fatalf("name %q", name)
	}
	c, key, err := GenerateWSSCert(name, now)
	if err != nil {
		t.Fatal(err)
	}
	if !ValidWSSKey(key) || ValidWSSKey(c.CertPEM) {
		t.Fatal("key check")
	}
	blk, _ := pem.Decode([]byte(c.CertPEM))
	x, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := x.PublicKey.(*ecdsa.PublicKey)
	switch {
	case !ok || pub.Curve != elliptic.P256():
		t.Fatal("not P-256")
	case x.SignatureAlgorithm != x509.ECDSAWithSHA256:
		t.Fatal("signature")
	case x.IsCA || !x.BasicConstraintsValid:
		t.Fatal("must be a non-CA end-entity certificate")
	case len(x.DNSNames) != 1 || x.DNSNames[0] != name || x.Subject.CommonName != name || len(x.IPAddresses) != 0:
		t.Fatalf("names %v %v", x.DNSNames, x.IPAddresses)
	case len(x.ExtKeyUsage) != 1 || x.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth:
		t.Fatal("eku")
	case x.SerialNumber.BitLen() < 64:
		t.Fatal("serial")
	case !x.NotAfter.Equal(now.Add(model.WSSCertValidity)) || !x.NotBefore.Equal(now.Add(-48*time.Hour)):
		t.Fatalf("validity %v %v", x.NotBefore, x.NotAfter)
	case c.Fingerprint != WSSFingerprint(blk.Bytes) || len(c.Fingerprint) != 95:
		t.Fatal("fingerprint")
	}
	if c2, _, _ := GenerateWSSCert(name, now); c2.Fingerprint == c.Fingerprint || c2.Serial == c.Serial {
		t.Fatal("two certificates are equal")
	}
}

// The trust model the client unit configures (wstunnel: rustls with the
// trust file as the only root store, name from --tls-sni-override) mirrored
// with Go's TLS stack: the pinned certificate with the right name is
// accepted; another self-signed certificate, the wrong name and an expired
// certificate are rejected. The real wstunnel binary is exercised by the
// opt-in test in internal/compile (MERIDIAN_WSTUNNEL_BIN).
func TestWSSTrustModelRejectsOthers(t *testing.T) {
	name, _ := GenerateWSSServerName()
	good, goodKey, _ := GenerateWSSCert(name, time.Now())
	other, otherKey, _ := GenerateWSSCert(name, time.Now())
	old, oldKey, _ := GenerateWSSCert(name, time.Now().Add(-2*model.WSSCertValidity))
	dial := func(serverCert, serverKey string, trust []string, verifyName string) error {
		pair, err := tls.X509KeyPair([]byte(serverCert), []byte(serverKey))
		if err != nil {
			t.Fatal(err)
		}
		ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}})
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			c, err := ln.Accept()
			if err == nil {
				_ = c.(*tls.Conn).Handshake()
				c.Close()
			}
		}()
		pool := x509.NewCertPool()
		for _, p := range trust {
			pool.AppendCertsFromPEM([]byte(p))
		}
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", ln.Addr().String(), &tls.Config{RootCAs: pool, ServerName: verifyName})
		if err == nil {
			c.Close()
		}
		return err
	}
	if err := dial(good.CertPEM, goodKey, []string{good.CertPEM}, name); err != nil {
		t.Fatalf("pinned certificate refused: %v", err)
	}
	// Overlap during a rotation: either certificate is accepted.
	if err := dial(other.CertPEM, otherKey, []string{good.CertPEM, other.CertPEM}, name); err != nil {
		t.Fatalf("overlap trust refused: %v", err)
	}
	if err := dial(other.CertPEM, otherKey, []string{good.CertPEM}, name); err == nil {
		t.Fatal("another self-signed certificate was accepted")
	}
	if err := dial(good.CertPEM, goodKey, []string{good.CertPEM}, "w0000000000000000.invalid"); err == nil {
		t.Fatal("the wrong name was accepted")
	}
	if err := dial(old.CertPEM, oldKey, []string{old.CertPEM}, name); err == nil {
		t.Fatal("an expired certificate was accepted")
	}
}

func TestEnsureWSSGeneratesAndIsIdempotent(t *testing.T) {
	s := wssStore(t)
	changed, err := s.EnsureWSS(testEnds, nil, nil)
	if err != nil || !changed {
		t.Fatal(changed, err)
	}
	st := s.WSSState()
	if len(st.Listeners) != 2 || !st.Migrated {
		t.Fatalf("%+v", st)
	}
	sec, err := s.WSSSecrets()
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]bool{}
	for _, l := range st.Listeners {
		if l.Legacy || l.Rotating() || !strings.HasSuffix(l.ServerName, ".invalid") || l.Cert.KeySecretID == "" {
			t.Fatalf("%+v", l)
		}
		if !ValidWSSKey(sec[l.Cert.KeySecretID]) {
			t.Fatal("key not stored")
		}
		for _, k := range l.Links {
			v := sec[k.Path.SecretID]
			if !wssGenPathRe.MatchString(v) || paths[v] {
				t.Fatalf("path of %s: %q", k.LinkID, v)
			}
			paths[v] = true
		}
	}
	if st.Listeners[0].ServerName == st.Listeners[1].ServerName || st.Listeners[0].Cert.Fingerprint == st.Listeners[1].Cert.Fingerprint {
		t.Fatal("listeners share material")
	}
	before, _ := json.Marshal(st)
	if changed, err := s.EnsureWSS(testEnds, nil, nil); err != nil || changed {
		t.Fatal("second run changed", changed, err)
	}
	after, _ := json.Marshal(s.WSSState())
	if string(before) != string(after) {
		t.Fatal("not idempotent")
	}
	// The index holds no secret; the secret files are 0600.
	idx, _ := os.ReadFile(filepath.Join(s.Dir(), "index.json"))
	for id, v := range sec {
		for _, line := range strings.Split(v, "\n") {
			if len(line) >= 16 && strings.Contains(string(idx), line) {
				t.Fatalf("secret %s in index.json", id)
			}
		}
		fi, err := os.Stat(s.secretPath(id, 1))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", id, err, fi.Mode())
		}
	}
	// A removed link and listener are dropped; their secrets become unused.
	if _, err := s.EnsureWSS(testEnds[:1], nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(s.WSSState().Listeners) != 1 || len(s.WSSUnusedSecrets()) != 3 {
		t.Fatalf("unused %v", s.WSSUnusedSecrets())
	}
	if err := s.DeleteWSSSecrets(s.WSSUnusedSecrets()); err != nil || len(s.WSSUnusedSecrets()) != 0 {
		t.Fatal(err)
	}
	s2, err := Open(s.Dir())
	if err != nil || len(s2.WSSSecretIDs()) != 2 {
		t.Fatalf("reopen: %v %v", err, s2.WSSSecretIDs())
	}
}

// works reports whether a client of k installed at cs talks to the server
// installed at ss: the prefix it sends is accepted and the certificate the
// server presents is among its trust roots. A legacy client (stage 0 of a
// migration) sends the old prefix and verifies nothing.
func works(l *model.WSSListener, k *model.WSSLink, ss, cs int, legacyClient bool) bool {
	if ss == model.WSSStageNone || cs == model.WSSStageNone {
		return true
	}
	accepted := l.ServerPaths(k, ss)
	if l.Legacy && ss == 0 {
		return legacyClient // the old server, the old client
	}
	if legacyClient {
		return k.Legacy != nil && contains(accepted, k.Legacy.SecretID)
	}
	if !contains(accepted, l.ClientPath(k, cs)) {
		return false
	}
	presented := l.ServerCert(ss).Fingerprint
	for _, c := range l.ClientTrust(cs) {
		if c.Fingerprint == presented {
			return true
		}
	}
	return false
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func install(t *testing.T, s *Store, node string, ok, unknown bool) {
	t.Helper()
	st := s.WSSState()
	var ps []WSSPartyStage
	for i := range st.Listeners {
		l := &st.Listeners[i]
		if l.NodeID == node {
			ps = append(ps, WSSPartyStage{ListenerID: l.NodeID, Party: model.WSSPartyServer, NodeID: node, Stage: l.TargetServer()})
		}
		for j := range l.Links {
			k := &l.Links[j]
			if k.DialerID == node {
				ps = append(ps, WSSPartyStage{ListenerID: l.NodeID, Party: model.WSSClientParty(k.LinkID), NodeID: node, Stage: l.TargetClient(k)})
			}
		}
	}
	if err := s.RecordWSSInstall(node, ps, ok, unknown, "test"); err != nil {
		t.Fatal(err)
	}
}

// Runtime model: what each party actually runs (the stage it was last
// installed at; a failed install changes nothing, an "unknown" one may
// have applied the target or not).
type runtime map[string]int

func (r runtime) check(t *testing.T, l *model.WSSListener, k *model.WSSLink, step string) {
	t.Helper()
	ss, cs := r[model.WSSPartyServer], r[model.WSSClientParty(k.LinkID)]
	if !works(l, k, ss, cs, false) {
		t.Fatalf("%s: server stage %d and client stage %d of %s do not fit", step, ss, cs, k.LinkID)
	}
}

func TestWSSCertRotationNeverBreaksTheCarrier(t *testing.T) {
	for seed := int64(0); seed < 60; seed++ {
		rng := rand.New(rand.NewSource(seed))
		s := wssStore(t)
		if _, err := s.EnsureWSS(testEnds, nil, nil); err != nil {
			t.Fatal(err)
		}
		// Every party installed once (idle, stage 0).
		for _, n := range []string{"gw", "ali", "hub"} {
			install(t, s, n, true, false)
		}
		before := lis(s, "hub").Cert
		// Snapshot of the listener material at rotation start: the runtime
		// keeps running the stage it installed, judged against the
		// rotation's material even after the state commits.
		if seed%2 == 0 {
			if _, err := s.RegenerateWSSCert("hub", model.WSSReasonCert); err != nil {
				t.Fatal(err)
			}
		} else {
			if _, err := s.RegenerateWSSPath("gw-hub"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.RegenerateWSSCert("hub", model.WSSReasonCert); err != nil {
				t.Fatal(err)
			}
		}
		rot := *lis(s, "hub")
		rt := runtime{model.WSSPartyServer: 0, model.WSSClientParty("gw-hub"): 0, model.WSSClientParty("ali-hub"): 0}
		for step := 0; step < 200 && lis(s, "hub").Rotating(); step++ {
			node := []string{"gw", "ali", "hub"}[rng.Intn(3)]
			cur := *lis(s, "hub")
			outcome := rng.Intn(10) // 0-6 ok, 7-8 compensated, 9 unknown
			targets := map[string]int{}
			if node == "hub" {
				targets[model.WSSPartyServer] = cur.TargetServer()
			}
			for j := range cur.Links {
				if cur.Links[j].DialerID == node {
					targets[model.WSSClientParty(cur.Links[j].LinkID)] = cur.TargetClient(&cur.Links[j])
				}
			}
			switch {
			case outcome <= 6:
				install(t, s, node, true, false)
				for p, v := range targets {
					rt[p] = v
				}
			case outcome <= 8:
				install(t, s, node, false, false)
			default:
				install(t, s, node, false, true)
				if rng.Intn(2) == 0 {
					for p, v := range targets {
						rt[p] = v
					}
				}
			}
			for j := range rot.Links {
				rt.check(t, &rot, &rot.Links[j], fmt.Sprintf("seed %d step %d", seed, step))
			}
		}
		l := lis(s, "hub")
		if l.Rotating() {
			// Only unknown outcomes can keep it open this long; one more
			// successful round finishes it.
			for i := 0; i < 8 && l.Rotating(); i++ {
				install(t, s, []string{"hub", "gw", "ali"}[i%3], true, false)
				l = lis(s, "hub")
			}
		}
		if l.Rotating() || l.Cert.Fingerprint == before.Fingerprint {
			t.Fatalf("seed %d: rotation did not finish: %+v", seed, l.Installed)
		}
		for p, v := range l.Installed {
			if v != 0 {
				t.Fatalf("seed %d: %s at %d after commit", seed, p, v)
			}
		}
		// The old key and (seed odd) the old path are no longer named.
		unused := strings.Join(s.WSSUnusedSecrets(), " ")
		if !strings.Contains(unused, before.KeySecretID) {
			t.Fatalf("old key still in use: %s", unused)
		}
	}
}

// The exact sequence the panel lists, with an interruption between the
// two ends and a failed install in the middle.
func TestWSSRotationSequenceAndCompensation(t *testing.T) {
	s := wssStore(t)
	s.EnsureWSS(testEnds[:1], nil, nil)
	install(t, s, "ali", true, false)
	install(t, s, "gw", true, false)
	if _, err := s.RegenerateWSSPath("gw-ali"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegenerateWSSPath("gw-ali"); err == nil || !strings.Contains(err.Error(), "正在轮换") {
		t.Fatal("second rotation must be refused while one is open")
	}
	l := lis(s, "ali")
	if steps := l.NextSteps(); len(steps) != 2 || steps[0].To != 1 || steps[1].To != 1 {
		t.Fatalf("steps %+v", steps)
	}
	// Only the server is updated, then the client fails (compensated):
	// both keep working on adjacent stages and the panel shows it.
	install(t, s, "ali", true, false)
	install(t, s, "gw", false, false)
	l = lis(s, "ali")
	if !l.Inconsistent() || l.InstalledStage(model.WSSPartyServer) != 1 || l.InstalledStage("client:gw-ali") != 0 {
		t.Fatalf("%+v", l.Installed)
	}
	if !works(l, &l.Links[0], 1, 0, false) {
		t.Fatal("server 1 / client 0 must fit")
	}
	if l.TargetServer() != 1 {
		t.Fatal("the server must not run ahead of the client by two stages")
	}
	if r := l.Results[len(l.Results)-1]; r.OK || r.NodeID != "gw" {
		t.Fatalf("failure not recorded: %+v", r)
	}
	for _, n := range []string{"gw", "ali", "gw", "ali", "gw"} {
		install(t, s, n, true, false)
	}
	l = lis(s, "ali")
	if l.Rotating() || l.Inconsistent() {
		t.Fatalf("not finished: %+v", l.Installed)
	}
	// Cancelling is only possible before any end installed new material.
	s.RegenerateWSSCert("ali", model.WSSReasonCert)
	if err := s.CancelWSSRotation("ali"); err != nil {
		t.Fatal(err)
	}
	s.RegenerateWSSCert("ali", model.WSSReasonCert)
	install(t, s, "gw", true, false)
	if err := s.CancelWSSRotation("ali"); err == nil {
		t.Fatal("cancel after a party advanced must be refused")
	}
}

func TestWSSRotationWithNothingDeployedReplacesAtOnce(t *testing.T) {
	s := wssStore(t)
	s.EnsureWSS(testEnds, nil, nil)
	before := lis(s, "ali").Cert.Fingerprint
	l, err := s.RegenerateWSSCert("ali", model.WSSReasonCert)
	if err != nil || l.Rotating() || l.Cert.Fingerprint == before {
		t.Fatalf("%v %+v", err, l)
	}
}

func TestWSSRollbackAndWithdrawMarks(t *testing.T) {
	s := wssStore(t)
	s.EnsureWSS(testEnds[:1], nil, nil)
	install(t, s, "ali", true, false)
	install(t, s, "gw", true, false)
	s.MarkWSSNode("gw", model.WSSStageUnknown, "rollback")
	l := lis(s, "ali")
	if lo, hi, _ := l.StageRange("client:gw-ali"); !l.Inconsistent() || lo != 0 || hi != 0 || len(l.Uncertain) != 1 {
		t.Fatal("rollback must make the end uncertain")
	}
	s.RegenerateWSSCert("ali", model.WSSReasonCert)
	l = lis(s, "ali")
	if l.TargetServer() != 1 {
		t.Fatal("unknown counts as stage 0 for the other end")
	}
	install(t, s, "ali", true, false)
	install(t, s, "gw", true, false)
	install(t, s, "ali", true, false)
	install(t, s, "gw", true, false)
	if l = lis(s, "ali"); l.Rotating() {
		t.Fatalf("%+v", l.Installed)
	}
	s.MarkWSSNode("gw", model.WSSStageNone, "withdrawn")
	if lis(s, "ali").InstalledStage("client:gw-ali") != model.WSSStageNone {
		t.Fatal("withdraw")
	}
}

func TestWSSExpiryTickWithInjectedClock(t *testing.T) {
	s := wssStore(t)
	now := time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return now }
	s.EnsureWSS(testEnds[:1], nil, nil)
	install(t, s, "ali", true, false)
	install(t, s, "gw", true, false)
	exp := lis(s, "ali").Cert.NotAfter
	now = exp.Add(-model.WSSRotateBefore - time.Hour)
	if started, _ := s.WSSExpiryTick(); len(started) != 0 {
		t.Fatal("rotated too early")
	}
	now = exp.Add(-model.WSSRotateBefore + time.Hour)
	started, err := s.WSSExpiryTick()
	l := lis(s, "ali")
	if err != nil || len(started) != 1 || l.Pending == nil || l.RotationReason != model.WSSReasonExpiry {
		t.Fatalf("%v %v %+v", started, err, l)
	}
	if !l.Pending.NotAfter.After(exp) {
		t.Fatal("new certificate does not outlive the old one")
	}
	if again, _ := s.WSSExpiryTick(); len(again) != 0 {
		t.Fatal("a second tick must not start another rotation")
	}
}

func TestWSSLegacyMigration(t *testing.T) {
	deployed := map[string]bool{"gw": true, "ali": true}
	legacy := map[string]WSSLegacy{"ali": {Path: "old-fixed-prefix"}, "hub": {Path: "bad path with spaces"}}
	s := wssStore(t)
	if _, err := s.EnsureWSS(testEnds, legacy, func(n string) bool { return deployed[n] }); err != nil {
		t.Fatal(err)
	}
	st := s.WSSState()
	ali, hub := st.Listener("ali"), st.Listener("hub")
	// ali and its dialer gw ran the old version; hub's dialers did too
	// (gw, ali), but its prefix is no plain token: no overlap for it.
	if !ali.Legacy || ali.Links[0].Legacy == nil || ali.InstalledStage(model.WSSPartyServer) != 0 || ali.InstalledStage("client:gw-ali") != 0 {
		t.Fatalf("ali %+v", ali)
	}
	if !hub.Legacy || hub.Link("gw-hub").Legacy != nil || hub.InstalledStage(model.WSSPartyServer) != model.WSSStageNone {
		t.Fatalf("hub %+v", hub)
	}
	sec, _ := s.WSSSecrets()
	if sec[ali.Links[0].Legacy.SecretID] != "old-fixed-prefix" {
		t.Fatal("legacy prefix not stored")
	}
	// Idempotent; a later run never makes a listener legacy.
	before, _ := json.Marshal(st)
	if changed, _ := s.EnsureWSS(testEnds, legacy, func(string) bool { return true }); changed {
		t.Fatal("second migration changed the state")
	}
	after, _ := json.Marshal(s.WSSState())
	if string(before) != string(after) {
		t.Fatal("not idempotent")
	}
	// The server first: old and new prefixes, new certificate; the old
	// client still works, then the new client, then the server drops the
	// old prefix.
	if ali.TargetServer() != 1 || ali.TargetClient(&ali.Links[0]) != 3 {
		t.Fatal("targets")
	}
	if !works(ali, &ali.Links[0], 1, 0, true) {
		t.Fatal("the old client must keep working against server stage 1")
	}
	install(t, s, "ali", true, false)
	install(t, s, "gw", true, false)
	ali = lis(s, "ali")
	if !works(ali, &ali.Links[0], 1, 3, false) || ali.TargetServer() != 3 {
		t.Fatal("new client against server stage 1")
	}
	install(t, s, "ali", true, false)
	ali = lis(s, "ali")
	if ali.Legacy || ali.Rotating() || ali.Links[0].Legacy != nil {
		t.Fatalf("migration not finished: %+v", ali)
	}
	if !strings.Contains(strings.Join(s.WSSUnusedSecrets(), " "), "wssp-") {
		t.Fatal("legacy prefix still in use")
	}
	// Nothing deployed: no legacy state at all.
	s2 := wssStore(t)
	s2.EnsureWSS(testEnds, legacy, func(string) bool { return false })
	for _, l := range s2.WSSState().Listeners {
		if l.Legacy {
			t.Fatal("undeployed listener made legacy")
		}
	}
}

func TestWSSDialerChangeResetsClient(t *testing.T) {
	s := wssStore(t)
	s.EnsureWSS(testEnds[:1], nil, nil)
	install(t, s, "gw", true, false)
	path := lis(s, "ali").Links[0].Path
	s.EnsureWSS([]model.WSSEnd{{LinkID: "gw-ali", ListenerID: "ali", DialerID: "other"}}, nil, nil)
	l := lis(s, "ali")
	if l.InstalledStage("client:gw-ali") != model.WSSStageNone || l.Links[0].Path != path {
		t.Fatalf("%+v", l)
	}
}

func lis(s *Store, id string) *model.WSSListener {
	st := s.WSSState()
	return st.Listener(id)
}
