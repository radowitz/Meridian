package compile

import (
	"fmt"
	"sort"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/validate"
)

// ProbeExit is what the panel's unlock probe needs to leave through one exit
// from the gateway: the exit's fwmark and transit addresses (the same ones
// meridian-routes.sh puts on lo and the hub selects by), its tunnel resolver
// and what the egress must look like.
type ProbeExit struct {
	ID         string
	Region     string
	Mark       uint32
	TransitV4  string
	TransitV6  string
	Resolver   string // DNSULA (PeerULA for external exits); queried from TransitV6 on UDP/TCP 53
	EgressV4   bool
	EgressV6   bool
	EndpointV4 string
	EndpointV6 string
	// TCPOnly: an external SOCKS exit (only TCP over IPv4 reaches its
	// proxy; UDP is refused on its carrier).
	TCPOnly bool
}

// ProbeExits returns every exit's probe parameters, keyed by node id. The
// values come from the same plan the gateway files are rendered from.
func ProbeExits(t model.Topology) (map[string]ProbeExit, error) {
	tunnels, err := buildTunnels(t)
	if err != nil {
		return nil, err
	}
	out := map[string]ProbeExit{}
	for _, e := range planExits(t, tunnels) {
		out[e.Node.ID] = ProbeExit{
			ID: e.Node.ID, Region: e.Node.Region, Mark: e.Mark,
			TransitV4: e.TransitV4, TransitV6: e.TransitV6, Resolver: e.DNSULA,
			EgressV4: e.Node.EgressV4, EgressV6: e.Node.EgressV6,
			EndpointV4: e.Node.EndpointV4, EndpointV6: e.Node.EndpointV6,
			TCPOnly: e.External,
		}
	}
	return out, nil
}

// EgressLegs is, per node id, the effective outer WireGuard legs the node
// takes part in as compiled: link, transport/mode, which end dials, the
// endpoint the dialer really uses (peerEndpoint: the listener's
// EndpointV4/IngressV4/EndpointV6/EndpointHost/Mesh address with the
// effective port — link wg_port over the node's listen_port over the
// slot default), the WSS failover leg port and the listener's WSS server
// port. Sorted, for identity digests: any override that changes where a
// leg's packets go changes the list.
func EgressLegs(t model.Topology) (map[string][]string, error) {
	tunnels, err := buildTunnels(t)
	if err != nil {
		return nil, err
	}
	ports := map[string]validate.LinkPorts{}
	for _, lp := range validate.TunnelPorts(t) {
		ports[lp.LinkID] = lp
	}
	out := map[string][]string{}
	for _, tun := range tunnels {
		lis, dia := tun.Listener(), tun.Dialer()
		leg := fmt.Sprintf("%s|%s|%s|%s>%s|ep=%s|wg=%d|wssleg=%d|wss=%d|v6=%t|mesh=%s",
			tun.LinkID, tun.Transport, tun.Mode, dia.ID, lis.ID,
			peerEndpoint(tun, dia), tun.WGPort, ports[tun.LinkID].WSSLeg, lis.WSSListenPort, tun.OuterV6, tun.MeshAddr)
		out[lis.ID] = append(out[lis.ID], leg)
		out[dia.ID] = append(out[dia.ID], leg)
	}
	for id := range out {
		sort.Strings(out[id])
	}
	return out, nil
}

// EgressInterface is the interface an exit's NAT sends traffic out of
// (wan_interface, default eth0), exactly as rendered.
func EgressInterface(n model.Node) string { return exitWAN(n) }
