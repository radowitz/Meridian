package compile

import "github.com/radowitz/meridian/internal/model"

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
	Resolver   string // tunnel ULA of the exit's resolver; empty when none
	EgressV4   bool
	EgressV6   bool
	EndpointV4 string
	EndpointV6 string
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
		}
	}
	return out, nil
}
