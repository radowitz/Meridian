package credentials

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSOCKSCredentialLifecycle(t *testing.T) {
	s, dir := open(t)
	user, pass := "router-user", "S0cks.Pass-word"
	c, err := s.CreateSOCKSCredential("马来西亚路由器", "", SOCKSSecretInput{Username: user, Password: pass})
	if err != nil {
		t.Fatal(err)
	}
	if !ValidSOCKSValue(user) || !strings.HasPrefix(c.ID, SOCKSIDPrefix+"-") || !c.SecretSet {
		t.Fatalf("credential %+v", c)
	}
	// The metadata (index, list) never carries the material.
	b, _ := json.Marshal(s.SOCKSCredentials())
	idx, _ := os.ReadFile(filepath.Join(dir, "index.json"))
	for _, txt := range []string{string(b), string(idx)} {
		if strings.Contains(txt, user) || strings.Contains(txt, pass) {
			t.Fatalf("material in metadata: %s", txt)
		}
	}
	// The secret file is the only place, mode 0600.
	hits := grepDir(t, dir, pass)
	if len(hits) != 1 {
		t.Fatalf("password stored in %v", hits)
	}
	if fi, _ := os.Stat(hits[0]); fi.Mode().Perm() != 0o600 {
		t.Fatalf("secret file mode %v", fi.Mode().Perm())
	}
	sec, err := s.SOCKSSecrets([]string{c.ID})
	if err != nil || sec[c.ID+"-user"] != user || sec[c.ID+"-pass"] != pass || !IsSOCKSSecretID(c.ID+"-user") || IsSOCKSSecretID(c.ID) {
		t.Fatalf("secrets %v %v", sec, err)
	}
	// Rotation replaces both halves; the old ones are gone from disk.
	if _, err := s.RotateSOCKSCredential(c.ID, SOCKSSecretInput{Username: "u2", Password: "p2-new"}); err != nil {
		t.Fatal(err)
	}
	if hits := grepDir(t, dir, pass); len(hits) != 0 {
		t.Fatalf("old password left in %v", hits)
	}
	sec, _ = s.SOCKSSecrets([]string{c.ID})
	if sec[c.ID+"-user"] != "u2" || sec[c.ID+"-pass"] != "p2-new" {
		t.Fatalf("rotated %v", sec)
	}
	// Characters that would need escaping are refused, never echoed.
	for _, bad := range []string{"", "has space", "a@b", "x:y", `q"uote`, "back\\slash", "50%", "a&b", strings.Repeat("a", 256)} {
		_, err := s.CreateSOCKSCredential("bad", "", SOCKSSecretInput{Username: "u", Password: bad})
		if codeOf(err) != CodeInvalid || (bad != "" && strings.Contains(err.Error(), bad)) {
			t.Errorf("password %q: %v", bad, err)
		}
	}
	// Delete refused while referenced, allowed afterwards.
	err = s.DeleteSOCKSCredential(c.ID, []Ref{{Kind: "node", ID: "myext", Name: "马来西亚"}})
	if codeOf(err) != CodeInUse || !strings.Contains(err.Error(), "马来西亚") {
		t.Fatalf("delete in use: %v", err)
	}
	if err := s.DeleteSOCKSCredential(c.ID, nil); err != nil {
		t.Fatal(err)
	}
	if hits := grepDir(t, dir, "p2-new"); len(hits) != 0 {
		t.Fatalf("material left after delete: %v", hits)
	}
	if _, err := s.SOCKSSecrets([]string{c.ID}); codeOf(err) != CodeNotFound {
		t.Fatalf("secrets of a deleted credential: %v", err)
	}
	// Reopening keeps the store consistent (orphan cleanup keeps live files).
	c2, _ := s.CreateSOCKSCredential("again", "", SOCKSSecretInput{Username: "u", Password: "pw"})
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if sec, err := s2.SOCKSSecrets([]string{c2.ID}); err != nil || sec[c2.ID+"-pass"] != "pw" {
		t.Fatalf("after reopen: %v %v", sec, err)
	}
}

// legacySOCKS makes s look like a store written before SOCKS versions were
// tracked: the same credentials, no baseline in the index.
func legacySOCKS(t *testing.T, s *Store) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneIndex(s.idx)
	next.SOCKSBaseline = nil
	if err := s.commit(next, nil); err != nil {
		t.Fatal(err)
	}
	s.socksMigErr = ""
}

// breakIndex makes every index write fail (the index path becomes a
// non-empty directory, so the atomic rename onto it is refused whatever
// the user); the returned function puts the index file back.
func breakIndex(t *testing.T, dir string) func() {
	t.Helper()
	idx, bak := filepath.Join(dir, "index.json"), filepath.Join(dir, "index.json.bak")
	if err := os.Rename(idx, bak); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(idx, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	return func() {
		t.Helper()
		if err := os.RemoveAll(idx); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(bak, idx); err != nil {
			t.Fatal(err)
		}
	}
}

func baselineOf(s *Store) *socksBaseline {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.idx.SOCKSBaseline == nil {
		return nil
	}
	b := *s.idx.SOCKSBaseline
	b.Gens = map[string]int{}
	for k, v := range s.idx.SOCKSBaseline.Gens {
		b.Gens[k] = v
	}
	return &b
}

func sameBaseline(a, b *socksBaseline) bool {
	if a == nil || b == nil || a.At != b.At || len(a.Gens) != len(b.Gens) {
		return false
	}
	for k, v := range a.Gens {
		if b.Gens[k] != v {
			return false
		}
	}
	return true
}

// The baseline: taken once from a store that has none, with the ids and
// generations of that moment; a failed write is reported and leaves the
// store untracked; a restart retries, and never takes it again once it is
// there; the first rotation of a baselined credential makes it tracked,
// later ones keep it so; a credential created afterwards is tracked from
// the start. The baseline itself never changes.
func TestSOCKSVersionBaselineMigration(t *testing.T) {
	s, dir := open(t)
	clock := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	tick := func() time.Time { clock = clock.Add(time.Minute); return clock }
	s.Now = tick
	in := func(n string) SOCKSSecretInput { return SOCKSSecretInput{Username: "u-" + n, Password: "p-" + n} }
	a, err := s.CreateSOCKSCredential("a", "", in("a1"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := s.CreateSOCKSCredential("b", "", in("b1"))
	// b was rotated twice before versions were tracked.
	for _, n := range []string{"b2", "b3"} {
		if _, err := s.RotateSOCKSCredential(b.ID, in(n)); err != nil {
			t.Fatal(err)
		}
	}
	legacySOCKS(t, s)
	if tr := s.SOCKSTracking(); tr.Ready || tr.Error != "" {
		t.Fatalf("legacy store: %+v", tr)
	}
	for id, v := range s.SOCKSVersions([]string{a.ID, b.ID}) {
		if v.Tracked || v.Baseline != 0 {
			t.Fatalf("%s tracked without a baseline: %+v", id, v)
		}
	}

	// The write fails: reported, remembered, nothing tracked, nothing on disk.
	restore := breakIndex(t, dir)
	err = s.MigrateSOCKSVersions()
	if codeOf(err) != CodeStorage || !strings.Contains(err.Error(), "版本基线") {
		t.Fatalf("failed migration: %v", err)
	}
	for _, sec := range []string{"u-a1", "p-a1", "p-b3"} {
		if strings.Contains(err.Error(), sec) {
			t.Fatalf("error carries material: %v", err)
		}
	}
	if tr := s.SOCKSTracking(); tr.Ready || tr.Error == "" {
		t.Fatalf("after a failed migration: %+v", tr)
	}
	if baselineOf(s) != nil || s.SOCKSVersions([]string{a.ID})[a.ID].Tracked {
		t.Fatal("a failed migration left a baseline")
	}
	restore()
	if raw, _ := os.ReadFile(filepath.Join(dir, "index.json")); strings.Contains(string(raw), "socks_version_baseline") {
		t.Fatal("a failed migration reached the index file")
	}

	// Restart: the migration runs again and succeeds.
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.Now = tick
	if baselineOf(s) != nil {
		t.Fatal("reopening took a baseline by itself")
	}
	if err := s.MigrateSOCKSVersions(); err != nil {
		t.Fatal(err)
	}
	base := baselineOf(s)
	if base == nil || len(base.Gens) != 2 || base.Gens[a.ID] != 1 || base.Gens[b.ID] != 3 || base.At == "" {
		t.Fatalf("baseline %+v", base)
	}
	if tr := s.SOCKSTracking(); !tr.Ready || tr.Since != base.At || tr.Error != "" {
		t.Fatalf("tracking %+v", tr)
	}
	vs := s.SOCKSVersions([]string{a.ID, b.ID, "socks-000000000000"})
	if len(vs) != 2 || vs[a.ID] != (SOCKSVersion{Version: 1, Baseline: 1}) || vs[b.ID] != (SOCKSVersion{Version: 3, Baseline: 3}) {
		t.Fatalf("un-rotated baseline credentials: %+v", vs)
	}
	// The index holds ids and counters only, in a 0600 file.
	raw, _ := os.ReadFile(filepath.Join(dir, "index.json"))
	if !strings.Contains(string(raw), "socks_version_baseline") {
		t.Fatal("the baseline is not in the index")
	}
	for _, sec := range []string{"u-a1", "p-a1", "u-b3", "p-b3"} {
		if strings.Contains(string(raw), sec) {
			t.Fatal("material in the index")
		}
	}
	if fi, _ := os.Stat(filepath.Join(dir, "index.json")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("index mode %v", fi.Mode().Perm())
	}

	// Called again, and after another restart: not taken again.
	if err := s.MigrateSOCKSVersions(); err != nil || !sameBaseline(base, baselineOf(s)) {
		t.Fatalf("second migration: %v %+v", err, baselineOf(s))
	}
	// First rotation since the baseline: tracked. A later one: still, +1.
	if _, err := s.RotateSOCKSCredential(a.ID, in("a2")); err != nil {
		t.Fatal(err)
	}
	if v := s.SOCKSVersions([]string{a.ID})[a.ID]; v != (SOCKSVersion{Version: 2, Baseline: 1, Tracked: true}) {
		t.Fatalf("first rotation: %+v", v)
	}
	if v := s.SOCKSVersions([]string{b.ID})[b.ID]; v.Tracked {
		t.Fatalf("b is tracked without having been rotated: %+v", v)
	}
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.Now = tick
	if err := s.MigrateSOCKSVersions(); err != nil || !sameBaseline(base, baselineOf(s)) {
		t.Fatalf("migration after a restart retook the baseline: %v %+v", err, baselineOf(s))
	}
	if _, err := s.RotateSOCKSCredential(a.ID, in("a3")); err != nil {
		t.Fatal(err)
	}
	if v := s.SOCKSVersions([]string{a.ID})[a.ID]; v != (SOCKSVersion{Version: 3, Baseline: 1, Tracked: true}) {
		t.Fatalf("later rotation: %+v", v)
	}
	// A new credential is tracked from creation and is not in the baseline.
	c, err := s.CreateSOCKSCredential("c", "", in("c1"))
	if err != nil {
		t.Fatal(err)
	}
	if v := s.SOCKSVersions([]string{c.ID})[c.ID]; v != (SOCKSVersion{Version: 1, Tracked: true}) {
		t.Fatalf("new credential: %+v", v)
	}
	// Metadata changes and a deletion leave the baseline alone.
	name := "renamed"
	if _, err := s.UpdateSOCKSCredential(b.ID, CredentialPatch{Name: &name}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSOCKSCredential(b.ID, nil); err != nil {
		t.Fatal(err)
	}
	if !sameBaseline(base, baselineOf(s)) {
		t.Fatalf("the baseline changed: %+v", baselineOf(s))
	}

	// A committed baseline survives later failures: the migration has
	// nothing to write, a rotation that cannot be stored is refused and
	// changes neither the version nor the baseline.
	restore = breakIndex(t, dir)
	if err := s.MigrateSOCKSVersions(); err != nil {
		t.Fatalf("migration with a baseline wrote: %v", err)
	}
	if _, err := s.RotateSOCKSCredential(a.ID, in("a4")); codeOf(err) != CodeStorage {
		t.Fatalf("rotation on a broken store: %v", err)
	}
	if v := s.SOCKSVersions([]string{a.ID})[a.ID]; v.Version != 3 || !sameBaseline(base, baselineOf(s)) {
		t.Fatalf("after a refused rotation: %+v", v)
	}
	restore()
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !sameBaseline(base, baselineOf(s)) || s.SOCKSVersions([]string{a.ID})[a.ID].Version != 3 {
		t.Fatal("the committed baseline was not kept")
	}
	// The secret read at the install boundary carries the same state.
	sec, vers, err := s.SOCKSSecretsVersioned([]string{a.ID, c.ID})
	if err != nil || sec[a.ID+"-pass"] != "p-a3" || vers[a.ID] != (SOCKSVersion{Version: 3, Baseline: 1, Tracked: true}) || vers[c.ID].Version != 1 {
		t.Fatalf("versioned secrets: %v %+v", err, vers)
	}
	if _, _, err := s.SOCKSSecretsVersioned([]string{"socks-000000000000"}); codeOf(err) != CodeNotFound {
		t.Fatalf("unknown: %v", err)
	}
}

// Without an explicit migration (it failed, or has not run), the first
// rotation or creation writes the baseline in the same index write: the
// generations from before it, so that very rotation is already tracked.
func TestSOCKSVersionBaselineWithFirstChange(t *testing.T) {
	in := func(n string) SOCKSSecretInput { return SOCKSSecretInput{Username: "u-" + n, Password: "p-" + n} }
	// Rotation first.
	s, dir := open(t)
	a, _ := s.CreateSOCKSCredential("a", "", in("a1"))
	b, _ := s.CreateSOCKSCredential("b", "", in("b1"))
	legacySOCKS(t, s)
	// A rotation that cannot be stored takes no baseline either.
	restore := breakIndex(t, dir)
	if _, err := s.RotateSOCKSCredential(a.ID, in("a2")); codeOf(err) != CodeStorage {
		t.Fatalf("rotation on a broken store: %v", err)
	}
	if baselineOf(s) != nil || s.SOCKSVersions([]string{a.ID})[a.ID].Version != 1 {
		t.Fatal("a refused rotation left a baseline or a version")
	}
	restore()
	if _, err := s.RotateSOCKSCredential(a.ID, in("a2")); err != nil {
		t.Fatal(err)
	}
	base := baselineOf(s)
	if base == nil || base.Gens[a.ID] != 1 || base.Gens[b.ID] != 1 {
		t.Fatalf("baseline %+v", base)
	}
	vs := s.SOCKSVersions([]string{a.ID, b.ID})
	if vs[a.ID] != (SOCKSVersion{Version: 2, Baseline: 1, Tracked: true}) || vs[b.ID] != (SOCKSVersion{Version: 1, Baseline: 1}) {
		t.Fatalf("%+v", vs)
	}
	if err := s.MigrateSOCKSVersions(); err != nil || !sameBaseline(base, baselineOf(s)) {
		t.Fatal("the migration replaced the baseline a rotation wrote")
	}
	// Creation first: the new credential is outside the baseline.
	s, _ = open(t)
	a, _ = s.CreateSOCKSCredential("a", "", in("a1"))
	legacySOCKS(t, s)
	c, err := s.CreateSOCKSCredential("c", "", in("c1"))
	if err != nil {
		t.Fatal(err)
	}
	base = baselineOf(s)
	if base == nil || len(base.Gens) != 1 || base.Gens[a.ID] != 1 {
		t.Fatalf("baseline %+v", base)
	}
	vs = s.SOCKSVersions([]string{a.ID, c.ID})
	if vs[a.ID].Tracked || vs[c.ID] != (SOCKSVersion{Version: 1, Tracked: true}) {
		t.Fatalf("%+v", vs)
	}
	// A brand-new store: an empty baseline, everything tracked.
	s, _ = open(t)
	if err := s.MigrateSOCKSVersions(); err != nil {
		t.Fatal(err)
	}
	if base := baselineOf(s); base == nil || len(base.Gens) != 0 {
		t.Fatalf("empty store baseline %+v", base)
	}
	n, _ := s.CreateSOCKSCredential("n", "", in("n1"))
	if v := s.SOCKSVersions([]string{n.ID})[n.ID]; !v.Tracked || v.Baseline != 0 {
		t.Fatalf("%+v", v)
	}
}

// Migration and rotations race: whichever comes first, the baseline is
// written once, holds every credential at a generation it really had, and
// a credential is tracked exactly when it was rotated past it.
func TestSOCKSVersionMigrationRacesRotation(t *testing.T) {
	for round := 0; round < 8; round++ {
		s, _ := open(t)
		var ids []string
		for i := 0; i < 4; i++ {
			c, err := s.CreateSOCKSCredential("c", "", SOCKSSecretInput{Username: "u", Password: "p"})
			if err != nil {
				t.Fatal(err)
			}
			ids = append(ids, c.ID)
		}
		legacySOCKS(t, s)
		const rotations = 3
		var wg sync.WaitGroup
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := s.MigrateSOCKSVersions(); err != nil {
					t.Error(err)
				}
			}()
		}
		for _, id := range ids[:3] {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < rotations; i++ {
					if _, err := s.RotateSOCKSCredential(id, SOCKSSecretInput{Username: "u", Password: "p"}); err != nil {
						t.Error(err)
					}
				}
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.SOCKSVersions(ids)
			_, _, _ = s.SOCKSSecretsVersioned(ids)
			_ = s.SOCKSTracking()
		}()
		wg.Wait()
		base := baselineOf(s)
		if base == nil || len(base.Gens) != len(ids) {
			t.Fatalf("baseline %+v", base)
		}
		vs := s.SOCKSVersions(ids)
		for i, id := range ids {
			v, want := vs[id], 1
			if i < 3 {
				want = 1 + rotations
			}
			if v.Version != want || v.Baseline < 1 || v.Baseline > v.Version || v.Baseline != base.Gens[id] || v.Tracked != (v.Version > v.Baseline) {
				t.Fatalf("round %d %s: %+v (baseline %+v)", round, id, v, base)
			}
		}
		if vs[ids[3]].Tracked {
			t.Fatalf("an un-rotated credential is tracked: %+v", vs[ids[3]])
		}
	}
}
