// Package wsstest gives tests a resolved bundle: WSS material generated in
// a throw-away credential store, the WSS tokens resolved and the secrets
// returned for the install boundary. Test support only.
package wsstest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/model"
)

// Material holds what Resolve produced.
type Material struct {
	Store   *credentials.Store
	State   model.WSSState
	Secrets map[string]string
	Plan    *compile.WSSPlan
}

// Store opens a credential store in a temp dir and generates the WSS
// material of topo.
func Store(t testing.TB, topo model.Topology) *credentials.Store {
	t.Helper()
	cs, err := credentials.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs.EnsureWSS(compile.WSSEnds(topo), nil, nil); err != nil {
		t.Fatal(err)
	}
	return cs
}

// Resolve returns b with the WSS tokens resolved from fresh material.
func Resolve(t testing.TB, topo model.Topology, b *compile.Bundle) (*compile.Bundle, Material) {
	t.Helper()
	return ResolveWith(t, Store(t, topo), b)
}

// ResolveWith resolves b from cs's state.
func ResolveWith(t testing.TB, cs *credentials.Store, b *compile.Bundle) (*compile.Bundle, Material) {
	t.Helper()
	st := cs.WSSState()
	rb, plan := compile.ResolveWSS(b, st)
	if len(plan.Missing) > 0 {
		t.Fatalf("unresolved WSS tokens: %v", plan.Missing)
	}
	sec, err := cs.WSSSecrets()
	if err != nil {
		t.Fatal(err)
	}
	return rb, Material{Store: cs, State: st, Secrets: sec, Plan: plan}
}

// Compile compiles topo and resolves the WSS tokens.
func Compile(t testing.TB, topo model.Topology) (*compile.Bundle, Material) {
	t.Helper()
	b, err := compile.Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	return Resolve(t, topo, b)
}

// Stable material: one certificate per listener and one path per link,
// generated once per test process and reused, so two compiles of the same
// topology in one test resolve to identical bundles.
var stable = struct {
	sync.Mutex
	names   map[string]string
	certs   map[string]model.WSSCert
	secrets map[string]string
}{names: map[string]string{}, certs: map[string]model.WSSCert{}, secrets: map[string]string{}}

func stableID(prefix, id string) string {
	sum := sha256.Sum256([]byte(prefix + "\x00" + id))
	return prefix + "-" + hex.EncodeToString(sum[:6])
}

// StableState returns a WSS state for topo built from the stable
// material (every party idle).
func StableState(t testing.TB, topo model.Topology) model.WSSState {
	t.Helper()
	st, err := stableState(topo)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func stableState(topo model.Topology) (model.WSSState, error) {
	stable.Lock()
	defer stable.Unlock()
	var st model.WSSState
	st.Migrated = true
	for _, e := range compile.WSSEnds(topo) {
		l := st.Listener(e.ListenerID)
		if l == nil {
			c, ok := stable.certs[e.ListenerID]
			if !ok {
				name, err := credentials.GenerateWSSServerName()
				if err != nil {
					return st, err
				}
				var key string
				c, key, err = credentials.GenerateWSSCert(name, time.Now())
				if err != nil {
					return st, err
				}
				c.KeySecretID = stableID(credentials.WSSKeyIDPrefix, e.ListenerID)
				stable.certs[e.ListenerID] = c
				stable.names[e.ListenerID] = name
				stable.secrets[c.KeySecretID] = key
			}
			st.Listeners = append(st.Listeners, model.WSSListener{NodeID: e.ListenerID, ServerName: stable.names[e.ListenerID], Cert: c})
			l = &st.Listeners[len(st.Listeners)-1]
		}
		id := stableID(credentials.WSSPathIDPrefix, e.LinkID)
		if _, ok := stable.secrets[id]; !ok {
			v, err := credentials.GenerateWSSPath()
			if err != nil {
				return st, err
			}
			stable.secrets[id] = v
		}
		l.Links = append(l.Links, model.WSSLink{LinkID: e.LinkID, DialerID: e.DialerID, Path: model.WSSPath{SecretID: id}})
	}
	st.Sort()
	return st, nil
}

// StableSecrets returns every stable secret generated so far.
func StableSecrets() map[string]string {
	stable.Lock()
	defer stable.Unlock()
	out := make(map[string]string, len(stable.secrets))
	for k, v := range stable.secrets {
		out[k] = v
	}
	return out
}

// StableResolve resolves b from the stable material of topo.
func StableResolve(t testing.TB, topo model.Topology, b *compile.Bundle) *compile.Bundle {
	t.Helper()
	rb, err := StableResolveErr(topo, b)
	if err != nil {
		t.Fatal(err)
	}
	return rb
}

// StableResolveErr is StableResolve with an error instead of t.
func StableResolveErr(topo model.Topology, b *compile.Bundle) (*compile.Bundle, error) {
	st, err := stableState(topo)
	if err != nil {
		return nil, err
	}
	rb, plan := compile.ResolveWSS(b, st)
	if len(plan.Missing) > 0 {
		return nil, fmt.Errorf("unresolved WSS tokens: %v", plan.Missing)
	}
	return rb, nil
}

// StableCompile compiles topo and resolves it from the stable material.
func StableCompile(t testing.TB, topo model.Topology) *compile.Bundle {
	t.Helper()
	b, err := StableCompileErr(topo)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// StableCompileErr is StableCompile with an error instead of t.
func StableCompileErr(topo model.Topology) (*compile.Bundle, error) {
	b, err := compile.Compile(topo)
	if err != nil {
		return nil, err
	}
	return StableResolveErr(topo, b)
}
