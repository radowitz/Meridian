export type Role = "gateway" | "relay" | "ix" | "hub" | "exit";

export type Transport =
  | "direct_wg"
  | "wg_over_wss"
  | "udp_wss_failover"
  | "ix_replacement_wss"
  | "dedicated_line"
  | "cf_mesh";

export interface Node {
  id: string;
  name: string;
  role: Role;
  region?: string;
  managed: boolean;
  x?: number;
  y?: number;
  lan_interface?: string;
  lan_ipv4?: string;
  lan_ipv6_prefix?: string;
  underlay_nexthop?: string;
  wan_interface?: string;
  path_v4: boolean;
  path_v6: boolean;
  egress_v4: boolean;
  egress_v6: boolean;
  nat_dial_out: boolean;
  residential: boolean;
  ix_bound: boolean;
  v6_workaround?: string;
  pool?: string;
  public_key?: string;
  private_key?: string;
  endpoint_v4?: string;
  listen_port?: number;
  ssh_host?: string;
  ssh_port?: number;
  ssh_user?: string;
  wss_listen_port?: number;
  wss_path_prefix?: string;
  tls_cert_path?: string;
  tls_key_path?: string;
}

export interface Link {
  id: string;
  name?: string;
  from: string;
  to: string;
  transport: Transport;
  enabled: boolean;
  standby: boolean;
  mtu?: number;
  wss_mtu?: number;
  wg_port?: number;
  keepalive?: number;
  from_v4?: string;
  to_v4?: string;
  from_ula?: string;
  to_ula?: string;
}

export interface Rule {
  id: string;
  name: string;
  manual: boolean;
  priority: number;
  enabled: boolean;
  overridden: boolean;
  match_type: string;
  match_value: string;
  source_mac?: string;
  source_ipv4?: string;
  source_ipv6?: string;
  target_pool?: string;
  target_exit?: string;
  mode: "pin" | "auto";
  require_residential: boolean;
  require_v6: boolean;
  notes?: string;
  domains?: string[];
  geosite?: string;
}

export interface Settings {
  draft: boolean;
  ix_replacement_mode: boolean;
  lan_interface: string;
  gateway_lan_ipv4: string;
  ros_ipv4: string;
  ros_v6_lla: string;
  lan_ipv6_prefix: string;
  ula_prefix: string;
  panel_bind: string;
  domestic_dot: string[];
  transit_v4_prefix: string;
  transit_v6_prefix: string;
}

export interface Topology {
  settings: Settings;
  nodes: Node[];
  links: Link[];
  rules: Rule[];
}

export interface Issue {
  code: string;
  severity: "error" | "warning";
  message: string;
  node_id?: string;
  link_id?: string;
  rule_id?: string;
  exit_id?: string;
}

export interface PathReport {
  exit_id: string;
  nodes: string[];
  links?: string[];
  mtu: number;
  mss4: number;
  mss6: number;
}

export const transportLabel: Record<Transport, string> = {
  direct_wg: "直连 WG",
  wg_over_wss: "WG over WSS",
  udp_wss_failover: "UDP + WSS",
  ix_replacement_wss: "IX 替换 WSS",
  dedicated_line: "IX 专线",
  cf_mesh: "Mesh 备路",
};

export const roleLabel: Record<Role, string> = {
  gateway: "网关",
  relay: "中继",
  ix: "IX",
  hub: "枢纽",
  exit: "出口",
};
