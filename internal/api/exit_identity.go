package api

// Exit identity: what a probe result is evidence about.
//
// A result is stored with the digest of the exit's identity at the time the
// job was created (exitIdentity). The identity is the configuration that
// decides where the probe's traffic actually leaves: the exit's WireGuard
// endpoint and peer public key, its public addresses, the effective
// compiled outer legs (endpoint with the port really used: a link's wg_port
// overrides the node's listen_port), the NAT egress interface, the managed server's
// address/port, a nested exit's relay, an external exit's SOCKS target and
// carrier, and the gateway-side carrier that selects the exit (fwmark,
// transit addresses, resolver, TCP-only). Secrets (private keys, PSKs,
// SOCKS credentials) and display fields (names, coordinates, tags, notes)
// are not part of it: renaming an exit keeps its results.
//
// The matrix and 采用 accept a result only when its digest equals the
// exit's current one; a result without a digest (stored before digests
// existed) or with another one is 未测 and never recommended. There is no
// extra lifetime: the existing result TTL still applies.
//
// A job freezes each exit's probe parameters and digest when it is created
// and never re-reads them by exit ID. Every identity change bumps the
// exit's generation (identityGen); a job's results are written with the
// frozen digest only when the generation is the one seen at creation, so a
// change during the run invalidates them even if it is undone before the
// run ends. Results are kept per job sequence: an older job finishing late
// never replaces a newer job's result.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/model"
)

// identityVersion prefixes every digest; a change of the field list bumps
// it, so digests of another version never match.
const identityVersion = "v2"

// identityFields is the documented field list of identityVersion.
var identityFields = []string{
	"role", "endpoint_v4", "endpoint_v6", "endpoint_host", "public_key", "listen_port", "wan_interface (effective: default eth0)",
	"legs (compiled: link, transport, mode, dialer>listener, effective endpoint incl. link wg_port / ingress_v4 / mesh address, wss failover leg port, wss_listen_port, outer v6)",
	"egress_v4", "egress_v6", "server.address", "server.port",
	"via_exit (relay: endpoint, public key, server)",
	"external.carrier (carrier: endpoint, public key, server)", "external.socks_address", "external.socks_port", "external.interface",
	"probe.mark", "probe.transit_v4", "probe.transit_v6", "probe.resolver", "probe.tcp_only",
}

type identityPeer struct {
	EndpointV4   string   `json:"ep4,omitempty"`
	EndpointV6   string   `json:"ep6,omitempty"`
	EndpointHost string   `json:"eph,omitempty"`
	PublicKey    string   `json:"pk,omitempty"`
	ListenPort   int      `json:"lp,omitempty"`
	Server       string   `json:"srv,omitempty"`
	WAN          string   `json:"wan,omitempty"`
	Legs         []string `json:"legs,omitempty"`
}

type identityInput struct {
	Role     string        `json:"role"`
	Self     identityPeer  `json:"self"`
	EgressV4 bool          `json:"e4"`
	EgressV6 bool          `json:"e6"`
	Via      *identityPeer `json:"via,omitempty"`
	Carrier  *identityPeer `json:"carrier,omitempty"`
	SOCKS    string        `json:"socks,omitempty"`
	SOCKSIf  string        `json:"socks_if,omitempty"`
	Probe    *struct {
		Mark      uint32 `json:"mark"`
		TransitV4 string `json:"t4,omitempty"`
		TransitV6 string `json:"t6,omitempty"`
		Resolver  string `json:"res,omitempty"`
		TCPOnly   bool   `json:"tcp,omitempty"`
	} `json:"probe,omitempty"`
}

func peerOf(t model.Topology, servers map[string]model.Server, legs map[string][]string, id string) identityPeer {
	n, ok := t.NodeByID(id)
	if !ok {
		return identityPeer{}
	}
	p := identityPeer{EndpointV4: n.EndpointV4, EndpointV6: n.EndpointV6, EndpointHost: n.EndpointHost, PublicKey: n.PublicKey, ListenPort: n.ListenPort,
		WAN: compile.EgressInterface(n), Legs: legs[n.ID]}
	if sv, ok := servers[n.ServerID]; ok && n.ServerID != "" {
		p.Server = sv.Address + ":" + strconv.Itoa(sv.Port)
	} else if n.SSHHost != "" {
		p.Server = n.SSHHost + ":" + strconv.Itoa(n.SSHPort)
	}
	return p
}

// exitIdentities is the current identity digest of every exit that can be
// probed (compile.ProbeExits); exits missing from it have no identity.
func exitIdentities(t model.Topology, servers map[string]model.Server) map[string]string {
	out := map[string]string{}
	exits, err := compile.ProbeExits(t)
	if err != nil {
		return out
	}
	legs, err := compile.EgressLegs(t)
	if err != nil {
		return out
	}
	for id, pe := range exits {
		out[id] = exitIdentity(t, servers, legs, pe)
	}
	return out
}

// exitIdentity is the digest of one exit's identity (see the file comment).
func exitIdentity(t model.Topology, servers map[string]model.Server, legs map[string][]string, pe compile.ProbeExit) string {
	n, ok := t.NodeByID(pe.ID)
	if !ok {
		return ""
	}
	in := identityInput{Role: string(n.Role), Self: peerOf(t, servers, legs, n.ID), EgressV4: n.EgressV4, EgressV6: n.EgressV6}
	if n.ViaExit != "" {
		v := peerOf(t, servers, legs, n.ViaExit)
		in.Via = &v
	}
	if n.External != nil {
		c := peerOf(t, servers, legs, n.External.Carrier)
		in.Carrier = &c
		in.SOCKS = n.External.SOCKSAddress + ":" + strconv.Itoa(n.External.SOCKSPort)
		in.SOCKSIf = n.External.Interface
	}
	in.Probe = &struct {
		Mark      uint32 `json:"mark"`
		TransitV4 string `json:"t4,omitempty"`
		TransitV6 string `json:"t6,omitempty"`
		Resolver  string `json:"res,omitempty"`
		TCPOnly   bool   `json:"tcp,omitempty"`
	}{pe.Mark, pe.TransitV4, pe.TransitV6, pe.Resolver, pe.TCPOnly}
	buf, _ := json.Marshal(in)
	sum := sha256.Sum256(buf)
	return identityVersion + ":" + hex.EncodeToString(sum[:16])
}

// serverMap is the managed servers by ID (nil when the credential store
// cannot be opened).
func (s *Server) serverMap() map[string]model.Server {
	cs, err := s.credStore()
	if err != nil {
		return nil
	}
	return serversByID(cs.Servers())
}

func serversByID(list []model.Server) map[string]model.Server {
	out := map[string]model.Server{}
	for _, sv := range list {
		out[sv.ID] = sv
	}
	return out
}

// noteIdentities computes the current identities of t's exits, bumps the
// generation of every exit whose identity changed since last seen, and
// returns both. The first call registers a store hook so that every later
// topology write is seen, including one undone before the next look.
func (s *Server) noteIdentities(t model.Topology) (map[string]string, map[string]uint64) {
	servers := s.serverMap()
	s.identOnce.Do(func() {
		s.Store.OnSave(func(next model.Topology) {
			// Under the store lock: use the credential store only when it
			// is already open (it is, once serverMap above ran).
			s.credMu.Lock()
			cs := s.creds
			s.credMu.Unlock()
			var servers map[string]model.Server
			if cs != nil {
				servers = serversByID(cs.Servers())
			}
			s.observeIdentities(exitIdentities(next, servers))
		})
	})
	return s.observeIdentities(exitIdentities(t, servers))
}

func (s *Server) observeIdentities(cur map[string]string) (map[string]string, map[string]uint64) {
	s.identMu.Lock()
	defer s.identMu.Unlock()
	if s.identLast == nil {
		s.identLast, s.identGen = map[string]string{}, map[string]uint64{}
	}
	for id, d := range cur {
		if old, ok := s.identLast[id]; ok && old != d {
			s.identGen[id]++
		}
		s.identLast[id] = d
	}
	for id := range s.identLast {
		if _, ok := cur[id]; !ok {
			delete(s.identLast, id)
			s.identGen[id]++
		}
	}
	gens := map[string]uint64{}
	for id, g := range s.identGen {
		gens[id] = g
	}
	out := map[string]string{}
	for id, d := range cur {
		out[id] = d
	}
	return out, gens
}

// identityChanged notes a change outside the topology (a managed server's
// address or port) for every exit.
func (s *Server) identityChanged() {
	t, err := s.topology()
	if err != nil {
		return
	}
	s.noteIdentities(t)
}
