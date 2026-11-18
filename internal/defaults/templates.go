package defaults

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/radowitz/meridian/internal/model"
)

// Topology templates for a first configuration (docs/architecture.md「直连出口与单中继」).
// Each one starts from Empty() and asks only for what its shape needs; no
// template names a provider, a region or a network of its own. The output
// is an ordinary topology: it goes through the same validation as any
// other before it is saved or compiled.
const (
	// TemplateDirect: gateway → exits. No relay, no hub.
	TemplateDirect = "direct"
	// TemplateRelay: gateway → one domestic server → exits. The domestic
	// server selects the exit, so in the topology it is the (only) hub.
	TemplateRelay = "relay"
	// TemplateRelayHub: gateway → relay → hub → exits, with an optional
	// backup hub, reached by the gateway over WSS or through a backup
	// group of relays.
	TemplateRelayHub = "relay_hub"
	// TemplateIX: gateway → relay → IX line (a managed hub on the line)
	// → exits, with an optional backup hub the gateway reaches over WSS.
	TemplateIX = "ix"
)

// TemplateField is one input a template asks for. Key is the JSON path in
// TemplateInput ("exits[].endpoint_v4" for a per-exit field).
type TemplateField struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	Kind     string `json:"kind"` // text, interface, ipv4, ipv4_prefix, server, region, list
	Required bool   `json:"required"`
}

// Template describes one template for the wizard.
type Template struct {
	ID     string          `json:"id"`
	Name   string          `json:"name"`
	Nodes  []string        `json:"nodes"` // the roles, in path order, for the diagram
	Fields []TemplateField `json:"fields"`
}

// TemplateGateway is the gateway's network, confirmed by the operator
// (first-run input or confirmed detection).
type TemplateGateway struct {
	LANInterface string `json:"lan_interface"`
	LANIPv4      string `json:"lan_ipv4"`    // address with prefix length
	RouterIPv4   string `json:"router_ipv4"` // the home router (next hop for domestic traffic)
	ServerID     string `json:"server_id,omitempty"`
}

// TemplateServer is one remote server of the template: a relay, a hub or
// an exit. ServerID links the node to a saved server (SSH target and
// credential); it may be filled in later.
type TemplateServer struct {
	Name         string `json:"name"`
	EndpointV4   string `json:"endpoint_v4"`
	IngressV4    string `json:"ingress_v4,omitempty"` // IX template: the line's domestic ingress
	Region       string `json:"region,omitempty"`     // exits: the region group it joins
	WANInterface string `json:"wan_interface,omitempty"`
	ServerID     string `json:"server_id,omitempty"`
}

// TemplateInput is everything a template may use. Each template reads
// only its own fields (Template.Fields); the others must be empty.
type TemplateInput struct {
	Gateway TemplateGateway  `json:"gateway"`
	Exits   []TemplateServer `json:"exits"`
	Relay   *TemplateServer  `json:"relay,omitempty"`
	Hub     *TemplateServer  `json:"hub,omitempty"`
	// BackupHub (relay_hub, ix) is optional. BackupRelays (relay_hub
	// only) puts the backup hub behind its own relays instead of a WSS
	// tunnel from the gateway.
	BackupHub    *TemplateServer  `json:"backup_hub,omitempty"`
	BackupRelays []TemplateServer `json:"backup_relays,omitempty"`
	// DefaultRegion is the region group that takes foreign traffic no rule
	// matches; it must be the region of at least one exit.
	DefaultRegion string `json:"default_region"`
}

// TemplateError is a missing or malformed input, by field key.
type TemplateError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (e *TemplateError) Error() string { return e.Field + ": " + e.Message }

var gatewayFields = []TemplateField{
	{Key: "gateway.lan_interface", Label: "局域网网卡", Kind: "interface", Required: true},
	{Key: "gateway.lan_ipv4", Label: "网关局域网地址", Kind: "ipv4_prefix", Required: true},
	{Key: "gateway.router_ipv4", Label: "主路由器地址", Kind: "ipv4", Required: true},
}

var exitFields = []TemplateField{
	{Key: "exits[].name", Label: "出口名称", Kind: "text", Required: true},
	{Key: "exits[].region", Label: "地区", Kind: "region", Required: true},
	{Key: "exits[].endpoint_v4", Label: "出口公网 IPv4", Kind: "ipv4", Required: true},
	{Key: "exits[].server_id", Label: "服务器", Kind: "server"},
	{Key: "default_region", Label: "默认出口地区", Kind: "region", Required: true},
}

func serverFields(prefix, label string, required bool) []TemplateField {
	return []TemplateField{
		{Key: prefix + ".name", Label: label + "名称", Kind: "text", Required: required},
		{Key: prefix + ".endpoint_v4", Label: label + "公网 IPv4", Kind: "ipv4", Required: required},
		{Key: prefix + ".server_id", Label: label + "服务器", Kind: "server"},
	}
}

func joinFields(parts ...[]TemplateField) []TemplateField {
	var out []TemplateField
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// Templates lists the four templates in the order the wizard offers them.
func Templates() []Template {
	return []Template{
		{ID: TemplateDirect, Name: "直连出口", Nodes: []string{"gateway", "exit"},
			Fields: joinFields(gatewayFields, exitFields)},
		{ID: TemplateRelay, Name: "单中继", Nodes: []string{"gateway", "relay", "exit"},
			Fields: joinFields(gatewayFields, serverFields("relay", "中继", true), exitFields)},
		{ID: TemplateRelayHub, Name: "中继 + 枢纽", Nodes: []string{"gateway", "relay", "hub", "exit"},
			Fields: joinFields(gatewayFields, serverFields("relay", "中继", true), serverFields("hub", "枢纽", true), exitFields,
				serverFields("backup_hub", "备用枢纽", false), serverFields("backup_relays[]", "备用中继", false))},
		{ID: TemplateIX, Name: "IX 专线", Nodes: []string{"gateway", "relay", "ix", "exit"},
			Fields: joinFields(gatewayFields, serverFields("relay", "中继", true),
				[]TemplateField{
					{Key: "hub.name", Label: "专线枢纽名称", Kind: "text", Required: true},
					{Key: "hub.ingress_v4", Label: "专线国内入口 IPv4", Kind: "ipv4", Required: true},
					{Key: "hub.endpoint_v4", Label: "专线境外出口 IPv4", Kind: "ipv4", Required: true},
					{Key: "hub.server_id", Label: "专线枢纽服务器", Kind: "server"},
				}, exitFields, serverFields("backup_hub", "备用枢纽", false))},
	}
}

// TemplateByID finds a template.
func TemplateByID(id string) (Template, bool) {
	for _, t := range Templates() {
		if t.ID == id {
			return t, true
		}
	}
	return Template{}, false
}

// Template node IDs. They are fixed so a regenerated preview keeps its
// references; the operator may rename nodes afterwards.
const (
	tplGateway   = "gw"
	tplRelay     = "relay"
	tplHub       = "hub"
	tplBackupHub = "hub-backup"
	// tplWSSPort is the TCP port the relay and the backup hub accept WSS
	// on. Any free port works; 443 is what networks let through most often.
	tplWSSPort = 443
)

// GenerateTemplate builds the topology of template id from in. It checks
// only the template's own inputs (presence and syntax); the result still
// has to pass validate.Run like any other topology.
func GenerateTemplate(id string, in TemplateInput) (model.Topology, error) {
	if _, ok := TemplateByID(id); !ok {
		return model.Topology{}, &TemplateError{Field: "template", Message: "没有这个模板：" + id}
	}
	if err := checkTemplateInput(id, in); err != nil {
		return model.Topology{}, err
	}
	t := Empty()
	gw := in.Gateway
	host := strings.SplitN(gw.LANIPv4, "/", 2)[0]
	t.Settings.LANInterface = gw.LANInterface
	t.Settings.GatewayLANIP = gw.LANIPv4
	t.Settings.ROSIPv4 = gw.RouterIPv4
	t.Settings.PanelBind = host + ":8787"
	t.Settings.DefaultGroup = regionGroupID(in.DefaultRegion)
	t.Nodes = append(t.Nodes, model.Node{
		ID: tplGateway, Name: "网关", Role: model.RoleGateway, Managed: true, X: 0, Y: 200,
		LANInterface: gw.LANInterface, LANIPv4: gw.LANIPv4, UnderlayNextHop: gw.RouterIPv4,
		PathV4: true, ServerID: gw.ServerID,
	})
	link := func(from, to string, tr model.Transport, standby bool) {
		t.Links = append(t.Links, model.Link{ID: from + "-" + to, From: from, To: to, Transport: tr, Enabled: true, Standby: standby})
	}
	server := func(id string, role model.Role, s TemplateServer, x, y int) model.Node {
		return model.Node{
			ID: id, Name: s.Name, Role: role, Managed: true, X: float64(x), Y: float64(y),
			WANInterface: s.WANInterface, EndpointV4: s.EndpointV4, PathV4: true, ServerID: s.ServerID,
		}
	}
	// carriers are the nodes the exits hang off (the gateway, or the hubs).
	var carriers []string
	switch id {
	case TemplateDirect:
		carriers = []string{tplGateway}
	case TemplateRelay:
		hub := server(tplRelay, model.RoleHub, *in.Relay, 250, 200)
		hub.HubTier = model.HubPrimary
		t.Nodes = append(t.Nodes, hub)
		link(tplGateway, tplRelay, model.TransportDirectWG, false)
		carriers = []string{tplRelay}
	case TemplateRelayHub, TemplateIX:
		relay := server(tplRelay, model.RoleRelay, *in.Relay, 220, 200)
		relay.WSSListenPort = tplWSSPort
		hub := server(tplHub, model.RoleHub, *in.Hub, 440, 200)
		hub.HubTier = model.HubPrimary
		if id == TemplateIX {
			hub.IXLine = true
			hub.IngressV4 = in.Hub.IngressV4
		}
		t.Nodes = append(t.Nodes, relay, hub)
		link(tplGateway, tplRelay, model.TransportUDPWSSFailover, false)
		link(tplRelay, tplHub, model.TransportDirectWG, false)
		carriers = []string{tplHub}
		if in.BackupHub != nil {
			bh := server(tplBackupHub, model.RoleHub, *in.BackupHub, 440, 360)
			bh.HubTier = model.HubBackup
			bh.WSSListenPort = tplWSSPort
			t.Nodes = append(t.Nodes, bh)
			carriers = append(carriers, tplBackupHub)
			if len(in.BackupRelays) == 0 {
				// The gateway's own standby WSS to the backup hub.
				link(tplGateway, tplBackupHub, model.TransportIXReplacementWSS, true)
			}
			for i, r := range in.BackupRelays {
				rid := fmt.Sprintf("relay-backup-%d", i+1)
				n := server(rid, model.RoleRelay, r, 220, 320+120*i)
				n.WSSListenPort = tplWSSPort
				t.Nodes = append(t.Nodes, n)
				link(tplGateway, rid, model.TransportUDPWSSFailover, false)
				link(rid, tplBackupHub, model.TransportWGOverWSS, false)
			}
		}
	}
	x := 680 // exits right of the last column
	switch id {
	case TemplateDirect:
		x = 300
	case TemplateRelay:
		x = 500
	}
	members := map[string][]string{}
	var regions []string
	for i, e := range in.Exits {
		eid := fmt.Sprintf("exit-%d", i+1)
		n := server(eid, model.RoleExit, e, x, 80+120*i)
		n.Region = e.Region
		n.EgressV4 = true
		t.Nodes = append(t.Nodes, n)
		for _, c := range carriers {
			link(c, eid, model.TransportDirectWG, false)
		}
		g := regionGroupID(e.Region)
		if _, ok := members[g]; !ok {
			regions = append(regions, e.Region)
		}
		members[g] = append(members[g], eid)
	}
	sort.Strings(regions)
	for _, r := range regions {
		g := regionGroupID(r)
		t.Groups = append(t.Groups, model.RegionGroup{ID: g, Name: r, Region: r, Mode: model.GroupAuto, Members: members[g]})
	}
	return t, nil
}

// regionGroupID is the region group a region's exits join.
func regionGroupID(region string) string {
	return strings.ToLower(strings.TrimSpace(region))
}

func checkTemplateInput(id string, in TemplateInput) error {
	bad := func(field, msg string) error { return &TemplateError{Field: field, Message: msg} }
	gw := in.Gateway
	if strings.TrimSpace(gw.LANInterface) == "" || strings.ContainsAny(gw.LANInterface, " /'\"") || len(gw.LANInterface) > 15 {
		return bad("gateway.lan_interface", "填写网关局域网网卡名")
	}
	p, err := netip.ParsePrefix(gw.LANIPv4)
	if err != nil || !p.Addr().Is4() || p.Bits() < 8 || p.Bits() > 30 {
		return bad("gateway.lan_ipv4", "填写带前缀长度的 IPv4 地址，例如 192.0.2.10/24")
	}
	r, err := netip.ParseAddr(gw.RouterIPv4)
	if err != nil || !r.Is4() || !p.Masked().Contains(r) || r == p.Addr() {
		return bad("gateway.router_ipv4", "主路由器地址要在网关局域网里，且不是网关自己")
	}
	if len(in.Exits) == 0 {
		return bad("exits", "至少需要一个出口")
	}
	regions := map[string]bool{}
	for i, e := range in.Exits {
		k := fmt.Sprintf("exits[%d]", i)
		if err := checkServer(k, e); err != nil {
			return err
		}
		g := regionGroupID(e.Region)
		if g == "" || strings.ContainsAny(g, " /'\"") || len(g) > 24 {
			return bad(k+".region", "填写地区（例如 jp）")
		}
		regions[g] = true
	}
	if !regions[regionGroupID(in.DefaultRegion)] {
		return bad("default_region", "默认出口地区要是某个出口的地区")
	}
	needRelay := id != TemplateDirect
	needHub := id == TemplateRelayHub || id == TemplateIX
	switch {
	case needRelay && in.Relay == nil:
		return bad("relay", "这个模板需要一台中继")
	case !needRelay && in.Relay != nil:
		return bad("relay", "直连出口模板没有中继")
	case needHub && in.Hub == nil:
		return bad("hub", "这个模板需要一台枢纽")
	case !needHub && in.Hub != nil:
		return bad("hub", "这个模板没有枢纽")
	case !needHub && in.BackupHub != nil:
		return bad("backup_hub", "这个模板没有备用枢纽")
	case id != TemplateRelayHub && len(in.BackupRelays) > 0:
		return bad("backup_relays", "只有「中继 + 枢纽」模板可以经备用中继到达备用枢纽")
	case len(in.BackupRelays) > 0 && in.BackupHub == nil:
		return bad("backup_relays", "备用中继需要备用枢纽")
	}
	if in.Relay != nil {
		if err := checkServer("relay", *in.Relay); err != nil {
			return err
		}
	}
	if in.Hub != nil {
		if err := checkServer("hub", *in.Hub); err != nil {
			return err
		}
		if id == TemplateIX {
			if a, err := netip.ParseAddr(in.Hub.IngressV4); err != nil || !a.Is4() {
				return bad("hub.ingress_v4", "填写专线国内入口的 IPv4")
			}
		} else if in.Hub.IngressV4 != "" {
			return bad("hub.ingress_v4", "只有 IX 专线模板有国内入口地址")
		}
	}
	if in.BackupHub != nil {
		if err := checkServer("backup_hub", *in.BackupHub); err != nil {
			return err
		}
	}
	for i, r := range in.BackupRelays {
		if err := checkServer(fmt.Sprintf("backup_relays[%d]", i), r); err != nil {
			return err
		}
	}
	return nil
}

func checkServer(key string, s TemplateServer) error {
	if strings.TrimSpace(s.Name) == "" {
		return &TemplateError{Field: key + ".name", Message: "填写名称"}
	}
	if a, err := netip.ParseAddr(s.EndpointV4); err != nil || !a.Is4() {
		return &TemplateError{Field: key + ".endpoint_v4", Message: "填写公网 IPv4"}
	}
	if strings.TrimSpace(s.WANInterface) == "" {
		return &TemplateError{Field: key + ".wan_interface", Message: "填写 WAN 网卡"}
	}
	if strings.ContainsAny(s.WANInterface, " /'\"") || len(s.WANInterface) > 15 {
		return &TemplateError{Field: key + ".wan_interface", Message: "网卡名不合法"}
	}
	return nil
}
