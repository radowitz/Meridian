// Package defaults holds the example topology and the geosite default table
// from the approved design. Addresses are documentation prefixes only.
package defaults

import "github.com/radowitz/meridian/internal/model"

func keepalive(n int) *int { return &n }

// DefaultRules is the automatic table. Manual rules outrank these.
// AI services go to the US pool, Netflix/Disney+ to Hong Kong residential,
// Taiwan-only services to TW, and everything else to the HK pool (hk-ix first).
func DefaultRules() []model.Rule {
	return []model.Rule{
		{
			ID: "auto-openai", Name: "OpenAI / ChatGPT", Manual: false, Priority: 100,
			Enabled: true, MatchType: model.MatchGeosite, MatchValue: "openai",
			Geosite: "openai", TargetGroup: "us",
			Domains: []string{"openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com"},
			Notes:   "池内其他 US；全部不可用则告警，不改到其他国家",
		},
		{
			ID: "auto-anthropic", Name: "Claude / Anthropic", Manual: false, Priority: 110,
			Enabled: true, MatchType: model.MatchGeosite, MatchValue: "anthropic",
			Geosite: "anthropic", TargetGroup: "us",
			Domains: []string{"claude.ai", "anthropic.com"},
		},
		{
			ID: "auto-gemini", Name: "Gemini", Manual: false, Priority: 120,
			Enabled: true, MatchType: model.MatchDomain, MatchValue: "gemini.google.com",
			TargetGroup: "us",
			Domains: []string{
				"gemini.google.com",
				"aistudio.google.com",
				"generativelanguage.googleapis.com",
			},
			Notes: "只纳入 Gemini 与相关 API，不要把整个 geosite:google 送去美国",
		},
		{
			ID: "auto-copilot", Name: "Microsoft Copilot", Manual: false, Priority: 130,
			Enabled: true, MatchType: model.MatchDomain, MatchValue: "copilot.microsoft.com",
			TargetGroup: "us",
			Domains:     []string{"copilot.microsoft.com"},
			Notes:       "收窄到 Copilot，避免误伤整个 Microsoft 365",
		},
		{
			ID: "auto-perplexity", Name: "Perplexity", Manual: false, Priority: 140,
			Enabled: true, MatchType: model.MatchGeosite, MatchValue: "perplexity",
			Geosite: "perplexity", TargetGroup: "us",
			Domains: []string{"perplexity.ai"},
		},
		{
			ID: "auto-grok", Name: "Grok", Manual: false, Priority: 150,
			Enabled: true, MatchType: model.MatchDomain, MatchValue: "grok.x.ai",
			TargetGroup: "us",
			Domains:     []string{"grok.x.ai", "x.ai"},
			Notes:       "默认不把整个 X/Twitter 钉死到 US",
		},
		{
			ID: "auto-netflix", Name: "Netflix", Manual: false, Priority: 200,
			Enabled: true, MatchType: model.MatchGeosite, MatchValue: "netflix",
			Geosite: "netflix", TargetGroup: "hk-residential",
			RequireResidential: true,
			Domains:            []string{"netflix.com", "netflix.net", "nflxvideo.net", "nflximg.net"},
			Notes:              "必须是 residential；失败只告警，不暗中换国家",
		},
		{
			ID: "auto-disney", Name: "Disney+", Manual: false, Priority: 210,
			Enabled: true, MatchType: model.MatchGeosite, MatchValue: "disney",
			Geosite: "disney", TargetGroup: "hk-residential",
			RequireResidential: true,
			Domains:            []string{"disneyplus.com", "disney-plus.net", "dssott.com"},
		},
		{
			ID: "auto-mytvsuper", Name: "MyTV SUPER / Viu", Manual: false, Priority: 220,
			Enabled: true, MatchType: model.MatchGeosite, MatchValue: "mytvsuper",
			Geosite: "mytvsuper", TargetGroup: "hk",
			Domains: []string{"mytvsuper.com"},
			Notes:   "优先 hk-ix；若解锁要求家宽，再改走 residential",
		},
		{
			ID: "auto-bahamut", Name: "巴哈姆特", Manual: false, Priority: 300,
			Enabled: true, MatchType: model.MatchGeosite, MatchValue: "bahamut",
			Geosite: "bahamut", TargetGroup: "tw",
			Domains: []string{"ani.gamer.com.tw", "gamer.com.tw"},
			Notes:   "失败则标记不可用，不改走日本",
		},
		{
			ID: "auto-kktv", Name: "KKTV", Manual: false, Priority: 310,
			Enabled: true, MatchType: model.MatchSuffix, MatchValue: "kktv.me",
			TargetGroup: "tw",
			Domains:     []string{"kktv.me"},
		},
		{
			ID: "auto-linetv", Name: "LINE TV", Manual: false, Priority: 320,
			Enabled: true, MatchType: model.MatchSuffix, MatchValue: "linetv.tw",
			TargetGroup: "tw",
			Domains:     []string{"linetv.tw"},
		},
		{
			ID: "auto-hami", Name: "Hami Video", Manual: false, Priority: 330,
			Enabled: true, MatchType: model.MatchSuffix, MatchValue: "hamivideo.hinet.net",
			TargetGroup: "tw",
			Domains:     []string{"hamivideo.hinet.net"},
		},
		{
			ID: "auto-abema", Name: "Abema / Niconico / TVer", Manual: false, Priority: 400,
			Enabled: true, MatchType: model.MatchGeosite, MatchValue: "abema",
			Geosite: "abema", TargetGroup: "jp",
			Domains: []string{"abema.tv"},
		},
	}
}

// Example is a valid Phase-1 topology using documentation addresses.
// Replace every endpoint before a real apply. Do not commit real keys.
func Example() model.Topology {
	rules := DefaultRules()
	rules = append(rules, model.Rule{
		ID: "manual-example", Name: "示例：钉死 api.example.com 到美国",
		Manual: true, Priority: 10, Enabled: true,
		MatchType: model.MatchDomain, MatchValue: "api.example.com",
		TargetGroup: "us-pin",
		Domains:     []string{"api.example.com"},
		Notes:       "手动规则优先于自动表。example.com 是文档域名。",
	})

	return model.Topology{
		Settings: model.Settings{
			LANInterface:    "eth0",
			GatewayLANIP:    "192.168.100.88/24",
			ROSIPv4:         "192.168.100.1",
			ROSv6LLA:        "fe80::1",
			LANIPv6Prefix:   "2001:db8:100::/64",
			ULAPrefix:       "fd66::/48",
			PanelBind:       "192.168.100.88:8787",
			DomesticDoT:     []string{"223.5.5.5", "1.12.12.12"},
			TransitV4Prefix: "10.66.200.0/24",
			TransitV6Prefix: "fd66:0:0:ff::/64",
			// 0 means the 6-hour default. NAT64 stays reserved and off so
			// the compiler does not install a translator route.
			NAT64: model.NAT64{Reserved: true, Enabled: false},
			// Foreign traffic no rule matched: the Hong Kong datacentre group.
			DefaultGroup: "hk",
		},
		Nodes: []model.Node{
			{
				ID: "gw", Name: "家宽网关", Role: model.RoleGateway, Region: "cn",
				Managed: true, X: 0, Y: 200,
				LANInterface: "eth0", LANIPv4: "192.168.100.88/24",
				LANIPv6Prefix: "2001:db8:100::/64", UnderlayNextHop: "192.168.100.1",
				PathV4: true, PathV6: false,
				SSHHost: "192.168.100.88", SSHPort: 22, SSHUser: "root",
				WSSPathPrefix: "example-wss-path-prefix",
				TLSCertPath:   "/etc/meridian/tls/fullchain.pem",
				TLSKeyPath:    "/etc/meridian/tls/privkey.pem",
			},
			{
				ID: "ali", Name: "阿里云上海", Role: model.RoleRelay, Region: "cn",
				Managed: true, X: 220, Y: 200,
				WANInterface: "eth0", EndpointV4: "203.0.113.10", ListenPort: 51820,
				PathV4: true, PathV6: false,
				SSHHost: "aliyun.example.invalid", SSHPort: 22, SSHUser: "root",
				WSSListenPort: 443, WSSPathPrefix: "example-wss-path-prefix",
				TLSCertPath: "/etc/meridian/tls/fullchain.pem",
				TLSKeyPath:  "/etc/meridian/tls/privkey.pem",
			},
			{
				ID: "ix", Name: "深港 IX", Role: model.RoleIX, Region: "cn",
				Managed: false, X: 440, Y: 200,
				PathV4: true, PathV6: false,
			},
			{
				ID: "hk-hub", Name: "香港枢纽", Role: model.RoleHub, Region: "hk",
				Managed: true, X: 660, Y: 200,
				WANInterface: "eth0", EndpointV4: "203.0.113.20", ListenPort: 51820,
				PathV4: true, PathV6: false,
				SSHHost: "hk-hub.example.invalid", SSHPort: 22, SSHUser: "root",
				WSSListenPort: 443, WSSPathPrefix: "example-wss-path-prefix",
				TLSCertPath: "/etc/meridian/tls/fullchain.pem",
				TLSKeyPath:  "/etc/meridian/tls/privkey.pem",
			},
			{
				ID: "hk-ix", Name: "香港出口（IX 绑定）", Role: model.RoleExit, Region: "hk",
				Managed: true, X: 900, Y: 40,
				WANInterface: "eth0", EndpointV4: "203.0.113.30", ListenPort: 51820,
				PathV4: true, PathV6: true, EgressV4: true, EgressV6: true,
				IXBound: true,
				SSHHost: "hk-ix.example.invalid", SSHPort: 22, SSHUser: "root",
			},
			{
				ID: "hk-2", Name: "香港出口（备）", Role: model.RoleExit, Region: "hk",
				Managed: true, X: 1100, Y: 40,
				WANInterface: "eth0", EndpointV4: "203.0.113.31", ListenPort: 51820,
				PathV4: true, PathV6: true, EgressV4: true, EgressV6: true,
				SSHHost: "hk-2.example.invalid", SSHPort: 22, SSHUser: "root",
			},
			{
				ID: "hk-resi", Name: "香港家宽", Role: model.RoleExit, Region: "hk",
				Managed: true, X: 900, Y: 160,
				WANInterface: "eth0",
				PathV4:       true, PathV6: true, EgressV4: true, EgressV6: true,
				NatDialOut: true, Residential: true,
				SSHHost: "hk-resi.example.invalid", SSHPort: 22, SSHUser: "root",
			},
			{
				ID: "hk-resi-2", Name: "香港家宽（备）", Role: model.RoleExit, Region: "hk",
				Managed: true, X: 1100, Y: 160,
				WANInterface: "eth0",
				PathV4:       true, PathV6: true, EgressV4: true, EgressV6: true,
				NatDialOut: true, Residential: true,
				SSHHost: "hk-resi-2.example.invalid", SSHPort: 22, SSHUser: "root",
			},
			{
				ID: "jp", Name: "日本出口", Role: model.RoleExit, Region: "jp",
				Managed: true, X: 900, Y: 280,
				WANInterface: "eth0", EndpointV4: "203.0.113.40", ListenPort: 51820,
				PathV4: true, PathV6: true, EgressV4: true, EgressV6: true,
				SSHHost: "jp.example.invalid", SSHPort: 22, SSHUser: "root",
			},
			{
				ID: "sg", Name: "新加坡出口", Role: model.RoleExit, Region: "sg",
				Managed: true, X: 900, Y: 380,
				WANInterface: "eth0", EndpointV4: "198.51.100.10", ListenPort: 51820,
				PathV4: true, PathV6: false, EgressV4: true, EgressV6: false,
				SSHHost: "sg.example.invalid", SSHPort: 22, SSHUser: "root",
			},
			{
				ID: "us", Name: "美国出口", Role: model.RoleExit, Region: "us",
				Managed: true, X: 900, Y: 480,
				WANInterface: "eth0", EndpointV4: "198.51.100.20", ListenPort: 51820,
				PathV4: true, PathV6: true, EgressV4: true, EgressV6: true,
				SSHHost: "us.example.invalid", SSHPort: 22, SSHUser: "root",
			},
			{
				ID: "us-2", Name: "美国出口（备）", Role: model.RoleExit, Region: "us",
				Managed: true, X: 1100, Y: 480,
				WANInterface: "eth0", EndpointV4: "198.51.100.21", ListenPort: 51820,
				PathV4: true, PathV6: true, EgressV4: true, EgressV6: true,
				SSHHost: "us-2.example.invalid", SSHPort: 22, SSHUser: "root",
			},
			{
				ID: "ds-relay", Name: "双栈中继", Role: model.RoleExit, Region: "hk",
				Managed: true, X: 900, Y: 680,
				WANInterface: "eth0", EndpointV4: "203.0.113.60", EndpointV6: "2001:db8::60",
				ListenPort: 51820,
				PathV4:     true, PathV6: true, EgressV4: true, EgressV6: true,
				DualstackRelay: true,
				SSHHost:        "ds-relay.example.invalid", SSHPort: 22, SSHUser: "root",
			},
			{
				ID: "v6-exit", Name: "纯 IPv6 出口", Role: model.RoleExit, Region: "us",
				Managed: true, X: 1100, Y: 680,
				WANInterface: "eth0", EndpointV6: "2001:db8::70", ListenPort: 51870,
				PathV4: false, PathV6: true, EgressV4: false, EgressV6: true,
				V6Workaround: model.WorkaroundDualstackRelay,
				SSHHost:      "v6-exit.example.invalid", SSHPort: 22, SSHUser: "root",
			},
			{
				ID: "v6-v4out", Name: "v6 入 v4 出", Role: model.RoleExit, Region: "us",
				Managed: true, X: 1100, Y: 780,
				WANInterface: "eth0",
				PathV4:       false, PathV6: true, EgressV4: true, EgressV6: false,
				V6Workaround: model.WorkaroundMesh,
				SSHHost:      "v6-v4out.example.invalid", SSHPort: 22, SSHUser: "root",
			},
			{
				ID: "tw", Name: "台湾出口", Role: model.RoleExit, Region: "tw",
				Managed: true, X: 900, Y: 580,
				WANInterface: "eth0",
				PathV4:       true, PathV6: false, EgressV4: true, EgressV6: false,
				NatDialOut: true,
				SSHHost:    "tw.example.invalid", SSHPort: 22, SSHUser: "root",
			},
		},
		Links: []model.Link{
			{
				ID: "gw-ali", Name: "家宽到阿里云", From: "gw", To: "ali",
				Transport: model.TransportUDPWSSFailover, Enabled: true,
				MTU: 1412, WSSMTU: 1360, WGPort: 51820, Keepalive: keepalive(25),
				FromV4: "10.66.1.1", ToV4: "10.66.1.2",
				FromULA: "fd66:0:0:1::1", ToULA: "fd66:0:0:1::2",
			},
			{
				ID: "ali-ix", Name: "阿里云接入 IX", From: "ali", To: "ix",
				Transport: model.TransportDedicatedLine, Enabled: true,
			},
			{
				ID: "ix-hub", Name: "IX 到香港枢纽", From: "ix", To: "hk-hub",
				Transport: model.TransportDirectWG, Enabled: true,
				MTU: 1420, WGPort: 51830, Keepalive: keepalive(25),
				FromV4: "10.66.2.1", ToV4: "10.66.2.2",
				FromULA: "fd66:0:0:2::1", ToULA: "fd66:0:0:2::2",
			},
			{
				ID: "ali-hub-wss", Name: "IX 替换 WSS（阿里云到枢纽）", From: "ali", To: "hk-hub",
				Transport: model.TransportIXReplacementWSS, Enabled: true, Standby: true,
				MTU: 1360, WGPort: 51840, Keepalive: keepalive(25),
				FromV4: "10.66.3.1", ToV4: "10.66.3.2",
				FromULA: "fd66:0:0:3::1", ToULA: "fd66:0:0:3::2",
			},
			{
				ID: "gw-hub-wss", Name: "IX 替换 WSS（家宽到枢纽）", From: "gw", To: "hk-hub",
				Transport: model.TransportIXReplacementWSS, Enabled: true, Standby: true,
				MTU: 1360, WGPort: 51841, Keepalive: keepalive(25),
				FromV4: "10.66.4.1", ToV4: "10.66.4.2",
				FromULA: "fd66:0:0:4::1", ToULA: "fd66:0:0:4::2",
			},
			{
				ID: "hub-hkix", Name: "枢纽到 IX 绑定港出口", From: "hk-hub", To: "hk-ix",
				Transport: model.TransportDirectWG, Enabled: true,
				MTU: 1420, WGPort: 51820, Keepalive: keepalive(25),
				FromV4: "10.66.10.1", ToV4: "10.66.10.2",
				FromULA: "fd66:0:0:10::1", ToULA: "fd66:0:0:10::2",
			},
			{
				ID: "hkresi-hub", Name: "香港家宽拨向枢纽", From: "hk-resi", To: "hk-hub",
				Transport: model.TransportDirectWG, Enabled: true,
				MTU: 1420, WGPort: 51851, Keepalive: keepalive(25),
				FromV4: "10.66.11.2", ToV4: "10.66.11.1",
				FromULA: "fd66:0:0:11::2", ToULA: "fd66:0:0:11::1",
			},
			{
				ID: "hub-jp", Name: "枢纽到日本", From: "hk-hub", To: "jp",
				Transport: model.TransportDirectWG, Enabled: true,
				MTU: 1420, WGPort: 51820, Keepalive: keepalive(25),
				FromV4: "10.66.20.1", ToV4: "10.66.20.2",
				FromULA: "fd66:0:0:20::1", ToULA: "fd66:0:0:20::2",
			},
			{
				ID: "hub-sg", Name: "枢纽到新加坡", From: "hk-hub", To: "sg",
				Transport: model.TransportDirectWG, Enabled: true,
				MTU: 1420, WGPort: 51820, Keepalive: keepalive(25),
				FromV4: "10.66.30.1", ToV4: "10.66.30.2",
				FromULA: "fd66:0:0:30::1", ToULA: "fd66:0:0:30::2",
			},
			{
				ID: "hub-us", Name: "枢纽到美国", From: "hk-hub", To: "us",
				Transport: model.TransportDirectWG, Enabled: true,
				MTU: 1420, WGPort: 51820, Keepalive: keepalive(25),
				FromV4: "10.66.40.1", ToV4: "10.66.40.2",
				FromULA: "fd66:0:0:40::1", ToULA: "fd66:0:0:40::2",
			},
			{
				ID: "tw-hub", Name: "台湾拨向枢纽", From: "tw", To: "hk-hub",
				Transport: model.TransportDirectWG, Enabled: true,
				MTU: 1420, WGPort: 51852, Keepalive: keepalive(25),
				FromV4: "10.66.50.2", ToV4: "10.66.50.1",
				FromULA: "fd66:0:0:50::2", ToULA: "fd66:0:0:50::1",
			},
			{
				ID: "hub-hkix-mesh", Name: "枢纽到港出口 Mesh 备路", From: "hk-hub", To: "hk-ix",
				Transport: model.TransportCFMesh, Enabled: true, Standby: true,
				MTU: 1280,
			},
			{
				ID: "hub-hk2", Name: "枢纽到备港出口", From: "hk-hub", To: "hk-2",
				Transport: model.TransportDirectWG, Enabled: true,
				MTU: 1420, WGPort: 51820, Keepalive: keepalive(25),
				FromV4: "10.66.12.1", ToV4: "10.66.12.2",
				FromULA: "fd66:0:0:12::1", ToULA: "fd66:0:0:12::2",
			},
			{
				ID: "hub-hk2-mesh", Name: "枢纽到备港出口 Mesh", From: "hk-hub", To: "hk-2",
				Transport: model.TransportCFMesh, Enabled: true, Standby: true,
				MTU: 1280,
			},
			{
				ID: "hkresi2-hub", Name: "香港家宽备机拨向枢纽", From: "hk-resi-2", To: "hk-hub",
				Transport: model.TransportDirectWG, Enabled: true,
				MTU: 1420, WGPort: 51853, Keepalive: keepalive(25),
				FromV4: "10.66.13.2", ToV4: "10.66.13.1",
				FromULA: "fd66:0:0:13::2", ToULA: "fd66:0:0:13::1",
			},
			{
				ID: "hub-us2", Name: "枢纽到美国备出口", From: "hk-hub", To: "us-2",
				Transport: model.TransportDirectWG, Enabled: true,
				MTU: 1420, WGPort: 51820, Keepalive: keepalive(25),
				FromV4: "10.66.41.1", ToV4: "10.66.41.2",
				FromULA: "fd66:0:0:41::1", ToULA: "fd66:0:0:41::2",
			},
			{
				ID: "hub-us-mesh", Name: "枢纽到美国 Mesh 备路", From: "hk-hub", To: "us",
				Transport: model.TransportCFMesh, Enabled: true, Standby: true,
				MTU: 1280,
			},
			{
				ID: "hub-dsrelay", Name: "枢纽到双栈中继", From: "hk-hub", To: "ds-relay",
				Transport: model.TransportDirectWG, Enabled: true,
				MTU: 1420, WGPort: 51820, Keepalive: keepalive(25),
				FromV4: "10.66.60.1", ToV4: "10.66.60.2",
				FromULA: "fd66:0:0:60::1", ToULA: "fd66:0:0:60::2",
			},
			{
				ID: "dsrelay-v6", Name: "双栈中继到纯 v6 出口", From: "ds-relay", To: "v6-exit",
				Transport: model.TransportDirectWG, Enabled: true,
				MTU: 1420, WGPort: 51870, Keepalive: keepalive(25),
				FromV4: "10.66.70.1", ToV4: "10.66.70.2",
				FromULA: "fd66:0:0:70::1", ToULA: "fd66:0:0:70::2",
			},
			{
				ID: "hub-v6v4-mesh", Name: "枢纽到 v6 入 v4 出（Mesh）", From: "hk-hub", To: "v6-v4out",
				Transport: model.TransportCFMesh, Enabled: true, Standby: true,
				MTU: 1280,
			},
		},
		Rules:  rules,
		Groups: ExampleGroups(),
	}
}

// ExampleGroups are the region groups of the example. They are what
// model.MigrateRegionGroups makes of the phase-2 pools (hk, hk-residential,
// us with an automatic and a pinned variant, …), with readable names.
// Hong Kong has two groups: datacentre and residential.
func ExampleGroups() []model.RegionGroup {
	return []model.RegionGroup{
		{
			ID: "hk", Name: "香港（机房）", Region: "hk", Mode: model.GroupAuto,
			Members: []string{"hk-ix", "hk-2"}, ExcludeResidential: true,
			Notes: "默认境外组。IX 绑定的 hk-ix 优先；家宽不进这个组。", MigratedFrom: "pool:hk#auto",
		},
		{
			ID: "hk-residential", Name: "香港（家宽）", Region: "hk", Mode: model.GroupAuto,
			Members: []string{"hk-resi", "hk-resi-2"}, RequireResidential: true,
			MigratedFrom: "pool:hk-residential#auto-resi",
		},
		{ID: "jp", Name: "日本", Region: "jp", Mode: model.GroupAuto, Members: []string{"jp"}, MigratedFrom: "pool:jp#auto"},
		{ID: "relay", Name: "双栈中继", Region: "hk", Mode: model.GroupAuto, Members: []string{"ds-relay"}, MigratedFrom: "pool:relay#auto"},
		{ID: "sg", Name: "新加坡", Region: "sg", Mode: model.GroupAuto, Members: []string{"sg"}, MigratedFrom: "pool:sg#auto"},
		{ID: "tw", Name: "台湾", Region: "tw", Mode: model.GroupAuto, Members: []string{"tw"}, MigratedFrom: "pool:tw#auto"},
		{ID: "us", Name: "美国", Region: "us", Mode: model.GroupAuto, Members: []string{"us", "us-2"}, MigratedFrom: "pool:us#auto"},
		{
			ID: "us-pin", Name: "美国（指定）", Region: "us", Mode: model.GroupManual,
			Members: []string{"us", "us-2"}, Chosen: "us", OnFailure: model.OnFailureFallback,
			Notes: "旧的钉死规则：指定 us，链路故障时临时回落到 us-2。", MigratedFrom: "pool:us#pin",
		},
		{ID: "v6", Name: "美国（纯 IPv6）", Region: "us", Mode: model.GroupAuto, Members: []string{"v6-exit"}, MigratedFrom: "pool:v6#auto"},
		{ID: "v6-nat", Name: "美国（v6 入 v4 出）", Region: "us", Mode: model.GroupAuto, Members: []string{"v6-v4out"}, MigratedFrom: "pool:v6-nat#auto"},
	}
}
