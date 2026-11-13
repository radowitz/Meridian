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
  dualstack_relay?: boolean;
  /** Legacy input only: merged into region groups on save, never returned. */
  pool?: string;
  pool_priority?: number;
  public_key?: string;
  private_key?: string;
  endpoint_v4?: string;
  endpoint_v6?: string;
  listen_port?: number;
  /** Managed server (GET /api/servers) this node runs on. When set, the
   * ssh_* fields stay empty: address and login live on the server. */
  server_id?: string;
  /** Pre-server SSH target; migrated into a server when the topology is saved. */
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
  /** wstunnel client port on 127.0.0.1 of the dialing end (default 52000 + link index). */
  wss_local_port?: number;
  keepalive?: number;
  from_v4?: string;
  to_v4?: string;
  from_ula?: string;
  to_ula?: string;
  /** cf_mesh only: CIDRs the exit end's Cloudflare Mesh node advertises. */
  mesh_routes?: string[];
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
  /** Exactly one of target_group / target_exit. */
  target_group?: string;
  target_exit?: string;
  /** Legacy input only (migrated into region groups); never returned. */
  target_pool?: string;
  mode?: "pin" | "auto";
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
  unlock_interval_sec?: number;
  nat64?: { reserved: boolean; enabled: boolean; prefix?: string };
  default_group?: string;
  /** List download source (GET/PUT /api/lists); empty means automatic. */
  list_source?: "domestic" | "overseas" | "automatic";
}

/** Region group (GET /api/region-groups has the live view). */
export interface RegionGroup {
  id: string;
  name: string;
  region?: string;
  members: string[];
  mode: "auto" | "manual";
  chosen?: string;
  on_failure?: "hold" | "fallback";
  require_residential?: boolean;
  exclude_residential?: boolean;
  require_v6?: boolean;
  notes?: string;
  migrated_from?: string;
}

export interface Topology {
  settings: Settings;
  nodes: Node[];
  links: Link[];
  rules: Rule[];
  region_groups?: RegionGroup[];
}

export interface Issue {
  code: string;
  severity: "error" | "warning";
  message: string;
  node_id?: string;
  link_id?: string;
  rule_id?: string;
  exit_id?: string;
  group_id?: string;
  device_id?: string;
  field?: string;
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

// ===========================================================================
// API views. Field names follow the Go handlers in internal/api/*.go; the
// backend is the source of truth. Secrets never appear in any of these:
// passwords, private keys, passphrases, API tokens and device private keys
// are write-only (requests may carry them, responses never do).
// ===========================================================================

/** A referrer in `in_use_by` (409 in_use and resource views). */
export interface Ref {
  /** node | server | credential | mesh_deployment | rule | settings | remote_device | group … */
  kind: string;
  id: string;
  name?: string;
}

/** Error body of every handler: `{error, code, field?, in_use_by?}` plus extras. */
export interface ApiErrorBody {
  error?: string;
  code?: string;
  field?: string;
  in_use_by?: Ref[];
  issues?: Issue[];
  [extra: string]: unknown;
}

// ---- Core / host -----------------------------------------------------------

export interface Meta {
  transports: string[];
  roles: string[];
  match_types: string[];
  modes: string[];
  on_failure: string[];
  phase: number;
  features: string[];
}

export interface HostStep {
  name: string;
  ok: boolean;
  skipped?: boolean;
  detail?: string;
}

export interface HostReport {
  transaction: string;
  kind: string;
  from_version: number;
  to_version: number;
  diff: Record<string, string[] | number[] | undefined>;
  steps?: HostStep[];
  warnings?: string[];
  committed: boolean;
  compensated?: boolean;
  /** Managed sysctl files as written and as read back from the kernel after a committed install / runtime rollback. */
  sysctl?: SysctlReport;
}

/** in_effect | differs | missing (no such key) | boot_only (boot-time forwarding=0) | stale (removed from the file) | not_checked */
export type SysctlState = "in_effect" | "differs" | "missing" | "boot_only" | "stale" | "not_checked";

export interface SysctlEntry {
  file: string;
  key: string;
  want?: string;
  got?: string;
  state: SysctlState;
}

export interface SysctlReport {
  /** The running kernel was read back after activation. */
  checked: boolean;
  reason?: string;
  written: SysctlEntry[];
  /** Keys the previous 99-meridian.conf set and the new one does not; the kernel keeps them until reboot. */
  removed?: SysctlEntry[];
  /** Written entries not in effect (differs or missing). */
  problems: number;
}

export interface InstalledManifest {
  /** The gateway was withdrawn: only the LAN guard is still installed. */
  withdrawn?: boolean;
  version: number;
  created_at?: string;
  files: number;
  interfaces: string[];
  units: string[];
  nft_tables: string[];
  route_tables: number[];
  dns: boolean;
  origin?: string;
}

export interface HostStatus {
  /** null: nothing installed on the gateway yet. */
  installed: InstalledManifest | null;
  pending: { id: string; kind: string; phase: string; error?: string; started: string; from_version: number; to_version: number } | null;
  agent: { ok: boolean; error?: string };
}

/** GET /api/status: the cheap read-only summary behind the top bar. */
/** withdrawn: the gateway was withdrawn down to the LAN guard (POST /api/host/withdraw). */
export type InstallStateCode = "in_sync" | "changed" | "not_installed" | "invalid" | "unknown" | "withdrawn";

export interface StatusJob {
  /** none | running | done | failed | cancelled | timeout | interrupted | published | compensating | compensation_failed | withdrawn | error */
  state: string;
  running: boolean;
  id?: string;
  started_at?: string;
  finished_at?: string;
  error?: string;
}

export interface PanelStatus {
  agent: { configured: boolean; ok: boolean; error?: string };
  /** A list update could run now (lists action configured and agent reachable). */
  lists_available: boolean;
  /** An unlock probe could run now (probe channel configured AND meridian-host answered). */
  probe_available: boolean;
  /** Why probe_available is false: not_configured | agent_unreachable. */
  probe_reason?: "not_configured" | "agent_unreachable";
  /** agent_unreachable: the agent's health error. */
  probe_error?: string;
  install: {
    /** Stored topology vs the INSTALLED manifest (not the applied snapshot). */
    state: InstallStateCode;
    installed_version: number | null;
    installed_at?: string;
    origin?: string;
    /** Something was applied (written to the data directory) before. */
    applied: boolean;
    /** Stored topology equals the last applied snapshot. */
    applied_matches: boolean;
    /** invalid: the compile error. */
    error?: string;
    issues?: Issue[];
  };
  pending: HostStatus["pending"];
  jobs: { lists: StatusJob; unlock: StatusJob; mesh: StatusJob };
  /** A previous snapshot exists, so a rollback has something to go back to. */
  previous_available?: boolean;
}

export interface TopologySaveResult {
  topology: Topology;
  issues: Issue[];
  paths: PathReport[];
  draft: boolean;
  migration_error?: string;
}

/** What an install would change on the gateway, by the installed manifest's file hashes. */
export interface InstalledDiff {
  files_added?: string[];
  files_changed?: string[];
  files_removed?: string[];
  interfaces_added?: string[];
  interfaces_removed?: string[];
  units_added?: string[];
  units_removed?: string[];
  nft_tables_added?: string[];
  nft_tables_removed?: string[];
  route_tables_added?: number[];
  route_tables_removed?: number[];
}

export interface DiffResult {
  /** "（没有变化）\n" when the compiled text equals the last applied one. */
  diff: string;
  order: string[];
  issues: Issue[];
  /** Against the installed manifest (null: nothing installed). */
  installed?: InstalledDiff | null;
}

export interface ApplyResult {
  dry_run: boolean;
  install: boolean;
  wrote?: string[];
  order: string[];
  diff: string;
  host?: HostReport;
}

export type RollbackMode = "runtime" | "snapshot";

export interface ProvisionResult {
  dry_run: boolean;
  node_id: string;
  script?: string;
  /** installed (only with 200) | refused | compensated | left_behind | unknown | not_started */
  outcome?: string;
  preflight_id?: string;
  /** What the failed run could not undo (MERIDIAN_LEFTOVER lines). */
  leftovers?: string[];
  /** What it kept on purpose (installed packages). */
  kept?: string[];
  [extra: string]: unknown;
}

// ---- Install pre-check (preflight) -----------------------------------------

export type FindingSeverity = "blocking" | "warning" | "info";

export interface PreflightFinding {
  severity: FindingSeverity;
  /** Stable code, e.g. forward_policy_drop, port_in_use, os_unsupported. */
  code: string;
  /** What was found. */
  message: string;
  /** What to do about it. */
  action?: string;
  /** The affected resource (interface, port, path, table …). */
  resource?: string;
  /** The topology field that resolves it (a port the node binds). */
  fix?: PreflightFix;
}

export interface PreflightFix {
  kind: "node" | "link";
  id: string;
  /** wg_port | listen_port | wss_listen_port | wss_local_port */
  field: string;
  label: string;
}

export interface PreflightChange {
  /** file | interface | listen | route | rule | nft | unit | package | sysctl | state */
  kind: string;
  /** create | replace | update | bind | add | enable | install | set */
  action: string;
  resource: string;
  detail?: string;
}

/** What a preflight result is bound to; execution is refused when it changes. */
export interface PreflightTarget {
  server_id: string;
  server_name: string;
  address: string;
  port: number;
  user: string;
  fingerprint: string;
  key_type?: string;
  credential_id: string;
  credential_name?: string;
  auth_method?: string;
}

export interface PreflightRecord {
  id: string;
  kind: "remote" | "gateway";
  node_id: string;
  node_name: string;
  role: string;
  target?: PreflightTarget;
  deployment: string;
  bundle: string;
  first_install: boolean;
  at: string;
  expires_at: string;
  host: { os?: string; arch?: string; kernel?: string; mem_total_kb: number; mem_avail_kb: number; complete: boolean; notes?: string[] };
  footprint: {
    files: string[];
    interfaces: { name: string; listen_port?: number; addresses: string[] }[];
    listens: { proto: string; addr: string; wildcard: boolean; port: number; owner: string }[];
    route_tables: number[];
    nft_tables: string[];
    units: string[];
    packages: { package: string; command: string }[];
    binaries: string[];
  };
  not_checked: string[];
  /** none | same | other | legacy | unknown */
  ownership: string;
  blocking: boolean;
  findings: PreflightFinding[];
  changes: PreflightChange[];
  counts: { blocking: number; warning: number; info: number };
}

/** How to get a login the server accepts. Public keys only. */
export interface LoginHelp {
  code: string;
  method: "password" | "key";
  user: string;
  address: string;
  credential_id?: string;
  credential_name?: string;
  /** The credential's public key, to append to authorized_keys. */
  public_key?: string;
  /** Panel-held key credentials (password credential, server wants keys). */
  key_credentials?: { id: string; name: string; public_key: string }[];
  steps: string[];
}

// ---- Servers ---------------------------------------------------------------

export type HostKeyState = "unknown" | "discovered" | "trusted" | "mismatch";

export interface HostKey {
  state: HostKeyState;
  /** Pinned fingerprint (trusted and mismatch). */
  fingerprint?: string;
  key_type?: string;
  pinned_at?: string;
  /** operator | mesh_journal */
  source?: string;
  /** Awaiting confirmation (discovered) or the conflicting key (mismatch). */
  seen_fingerprint?: string;
  seen_key_type?: string;
  seen_at?: string;
}

export interface ConnectionTest {
  at: string;
  ok: boolean;
  auth_method?: "password" | "key";
  /** unreachable | timeout | auth_failed (credential rejected) | auth_method_unavailable (server does not offer this login method) | host_key_mismatch | host_key_untrusted | command_failed | ssh_rate_limited (refused this source before the SSH banner) */
  code?: string;
  error?: string;
  /** ssh_rate_limited: the panel does not connect again before at + retry_after seconds. */
  retry_after?: number;
  os?: string;
  kernel?: string;
  arch?: string;
  duration_ms: number;
}

export type AuthMethod = "password" | "key";

export interface ServerView {
  id: string;
  name: string;
  address: string;
  port: number;
  user: string;
  auth: AuthMethod;
  credential_id?: string;
  credential: { id: string; name: string; kind: CredentialKind } | null;
  /** Omitted when empty (omitempty on the model). */
  tags?: string[];
  notes?: string;
  host_key: HostKey;
  created_at: string;
  updated_at: string;
  migrated_from?: string;
  last_test?: ConnectionTest | null;
  /** Credential selected and host key trusted. */
  operable: boolean;
  /** Operable and the last connection test passed. */
  ready: boolean;
  /** credential | host_key | connection_test */
  missing: string[];
  in_use_by: Ref[];
  node: Ref | null;
}

export interface ServerInput {
  name: string;
  address: string;
  port?: number;
  user?: string;
  auth: AuthMethod;
  credential_id?: string;
  tags?: string[];
  notes?: string;
}

export type ServerPatch = Partial<ServerInput>;

export interface HostKeyDiscovery {
  key_type: string;
  fingerprint: string;
  matches_pinned: boolean;
}

// ---- SSH credentials -------------------------------------------------------

export type CredentialKind = "password" | "private_key";

export interface SSHCredentialView {
  id: string;
  name: string;
  kind: CredentialKind;
  notes?: string;
  key_type?: string;
  /** authorized_keys line (private_key only). */
  public_key?: string;
  fingerprint?: string;
  comment?: string;
  has_passphrase?: boolean;
  generated?: boolean;
  secret_set: boolean;
  created_at: string;
  updated_at: string;
  rotated_at?: string;
  in_use_by: Ref[];
}

/** Secret part of a create or rotate request. Never stored in the browser. */
export type SSHSecretInput =
  | { kind: "password"; password: string }
  | { kind: "private_key"; private_key: string; passphrase?: string; comment?: string }
  | { kind: "private_key"; generate: true; comment?: string };

export type SSHCredentialCreate = SSHSecretInput & { name: string; notes?: string };

export interface SSHCredentialPatch {
  name?: string;
  notes?: string;
  comment?: string;
}

// ---- Cloudflare -------------------------------------------------------------

export interface PermissionProbe {
  name: string;
  endpoint: string;
  /** pass | denied | error | skipped */
  status: string;
  detail?: string;
}

export interface PermissionCheck {
  checked_at: string;
  /** Every probe that ran passed. Not a proof of write access. */
  ok: boolean;
  missing?: string[];
  detail?: string;
  /** active | disabled | expired | "" */
  token_status?: string;
  /** account | user */
  token_kind?: string;
  confirmed?: string[];
  unconfirmed?: string[];
  checks?: PermissionProbe[];
}

export interface CloudflareAccountView {
  id: string;
  name: string;
  account_id: string;
  notes?: string;
  token_set: boolean;
  permission_check?: PermissionCheck;
  created_at: string;
  updated_at: string;
  rotated_at?: string;
  migrated_from?: string;
  used_for_mesh: boolean;
  bound_deployment: Ref | null;
  in_use_by: Ref[];
}

export interface CloudflareAccountsView {
  accounts: CloudflareAccountView[];
  mesh_account: string | null;
}

export interface CloudflareAccountInput {
  name: string;
  account_id: string;
  api_token: string;
  notes?: string;
}

export interface CloudflareAccountPatch {
  name?: string;
  account_id?: string;
  notes?: string;
}

export interface CloudflareRequirements {
  permissions: { name: string; scope: string; why: string }[];
  how_to: string[];
  check: { does: string[]; does_not: string[] };
}

// ---- Mesh -------------------------------------------------------------------

export interface MeshIssue {
  code: string;
  message: string;
  node_id?: string;
  link_id?: string;
}

export interface MeshStage {
  name: string;
  /** pending | running | done | failed | skipped */
  status: string;
  started?: string;
  finished?: string;
  error?: string;
  detail?: string[];
}

/** SSH target a run pinned: where it connected and the host key it saw. */
export interface MeshHostPin {
  node_id: string;
  name?: string;
  role: string;
  server_id?: string;
  credential_id?: string;
  ssh_host: string;
  ssh_port: number;
  ssh_user: string;
  host_key?: string;
}

export interface MeshJournal {
  schema?: number;
  run_id: string;
  /** running | published | failed | compensating | compensation_failed | withdrawn */
  state: string;
  account_id?: string;
  account_ref?: string;
  hosts?: MeshHostPin[] | null;
  started: string;
  updated: string;
  fail_after?: string;
  stages: MeshStage[];
  nodes: { node_id: string; name: string; cf_id?: string; state: string; error?: string }[] | null;
  routes:
    | { link_id: string; exit_id: string; network: string; tunnel_id: string; comment: string; cf_id?: string; state: string; error?: string }[]
    | null;
  remotes: { node_id: string; host?: MeshHostPin; state: string; error?: string }[] | null;
  targets: string[] | null;
  error?: string;
  compensation_errors?: string[];
  /** Always "unverified". */
  dataplane: string;
}

export interface MeshPlan {
  addressing: {
    link_v4: string;
    host_v4: string;
    sidecar_v4: string;
    host_v6: string;
    sidecar_v6: string;
    v6_bits: number;
    host_mac: string;
    sidecar_mac: string;
    host_iface: string;
    sidecar_iface: string;
  };
  nodes:
    | {
        id: string;
        name: string;
        role: string;
        server_id?: string;
        credential_id?: string;
        ssh_host?: string;
        ssh_port?: number;
        ssh_user?: string;
        host_key?: string;
      }[]
    | null;
  routes: { link_id: string; exit_id: string; network: string }[] | null;
  return_v4: string[] | null;
  return_v6: string[] | null;
  issues: MeshIssue[] | null;
}

export interface MeshNodeReadiness {
  node_id: string;
  name: string;
  role: string;
  server_id: string;
  server_name: string;
  ready: boolean;
  /** server | credential | host_key */
  missing: string[];
  host_key?: string;
  auth_method?: string;
}

export interface MeshAccountSummary {
  id: string;
  name: string;
  account_id: string;
  /** request | selected */
  source: string;
  permission_check: PermissionCheck | null;
}

export interface MeshStatus {
  dataplane: string;
  dataplane_note: string;
  fault_injection: boolean;
  stages: string[];
  credentials?: { account_id?: string; token_set: boolean };
  credentials_error?: string;
  mesh_account: MeshAccountSummary | null;
  plan?: MeshPlan;
  plan_servers?: MeshNodeReadiness[];
  plan_error?: string;
  journal?: MeshJournal | null;
  journal_error?: string;
}

export interface MeshRunBody {
  account?: string;
  fail_after?: string;
}

/** Response of deploy / withdraw, also the body of their 409 / 502 errors. */
export interface MeshRunResult {
  journal?: MeshJournal | null;
  dataplane: string;
  dataplane_note: string;
  account?: MeshAccountSummary;
  error?: string;
  code?: string;
  stage?: string;
  compensated?: boolean;
  compensation_errors?: string[] | null;
  not_ready?: MeshNodeReadiness[];
}

// ---- Lists ------------------------------------------------------------------

export type ListsPolicy = "domestic" | "overseas" | "automatic";
export type ListKind = "geosite" | "chnroute";

export interface ListSourceInfo {
  name: string;
  geosite_base: string;
  chnroute_base: string;
}

export interface ListAttempt {
  source: string;
  url: string;
  ok: boolean;
  error?: string;
  duration_ms: number;
}

export interface PublishedList {
  source: string;
  url: string;
  updated_at: string;
  count: number;
  files?: number;
}

export interface ListResult {
  /** geosite:<name> | keyword:<id> | chnroute4 | chnroute6 */
  list: string;
  kind: string;
  updated: boolean;
  kept: boolean;
  source?: string;
  url?: string;
  count?: number;
  files?: number;
  dropped?: Record<string, number>;
  current?: PublishedList;
  attempts?: ListAttempt[];
  error?: string;
}

export interface ListsReport {
  policy: ListsPolicy;
  sources: string[];
  started_at: string;
  finished_at: string;
  ok: boolean;
  partial: boolean;
  lists: ListResult[] | null;
  error?: string;
  dns_changed: boolean;
  dns_restart?: string;
  warnings?: string[];
}

export interface ListsJob {
  id: string;
  /** running | done | failed */
  state: "running" | "done" | "failed";
  policy: ListsPolicy;
  lists: string[];
  started_at: string;
  finished_at?: string;
  report?: ListsReport;
  error?: string;
}

export interface ListsView {
  policy: ListsPolicy;
  /** false: never saved, the effective policy is the default. */
  saved: boolean;
  policies: ListsPolicy[];
  order: string[];
  sources: ListSourceInfo[];
  lists: { geosite: string[] | null; keywords: { id: string; keyword: string }[]; chnroute: string[] };
  host_available: boolean;
  job: ListsJob | null;
}

export interface ListsHostStatus {
  published: Record<string, PublishedList>;
  last?: ListsReport;
}

// ---- Region groups ------------------------------------------------------------

export interface GroupMemberView {
  id: string;
  name: string;
  region?: string;
  user_position: number;
  /** Effective position, -1 when excluded. */
  position: number;
  eligible: boolean;
  ix_bound: boolean;
  residential: boolean;
  egress_v6: boolean;
  switchable?: boolean;
  reasons: { code: string; message: string }[];
  target: boolean;
  /** The hub reported (actual.state "ok") that the group table uses this member. */
  actual_active: boolean;
  /** The panel's model puts the group on this member (面板推算, never an observation). */
  model_active: boolean;
  health: {
    up: boolean;
    fails: number;
    goods: number;
    last_ok: boolean | null;
    ok_since: string | null;
    last_at: string | null;
  } | null;
}

/**
 * The hub's own report for a group, read over SSH with a fixed command and
 * judged by the panel. Only state "ok" names the member actually in use;
 * every other state means unknown / not verified, with code and message.
 */
export type GroupActualState = "ok" | "stale" | "version_mismatch" | "switch_failed" | "unavailable" | "not_switchable" | "never_read";

export interface GroupActualView {
  state: GroupActualState;
  /** Machine reason for every state but ok (no_hub, hub_no_server, server_not_ready, ssh_failed, state_missing, parse_error, invalid_report, plan_unavailable, heartbeat_old, read_old, plan_differs, hop_failed, table_diverged, static_only, not_read, hub_identity_changed: the stored read was taken from another hub node, server, address, SSH port or pinned host key). */
  code?: string;
  ssh_code?: string;
  message?: string;
  /** ok only: member ID, "mmesh", or "" when the table is a blackhole. */
  active: string;
  hop?: string;
  reason?: string;
  alert: boolean;
  alert_message?: string;
  last_switch: string | null;
  running_since?: string;
  read_at: string | null;
  hub_reported_at: string | null;
  deployed_matches: boolean | null;
  clock_skew_sec?: number;
  /** switch_failed: what the hub said (unconfirmed). */
  reported?: { hop: string; active?: string; want?: string; failed_at?: string };
}

/** The panel's own computation of the hub's state machine (source "panel_model"). */
export interface GroupModelView {
  /** Member ID, "mmesh" (Mesh last hop) or "" (no member). */
  active: string;
  reason: string;
  alert: boolean;
  alert_message?: string;
  last_switch: string | null;
  /** false until health samples arrived. */
  observed: boolean;
  source: string;
  return_blocked_by?: string;
  return_not_before?: string;
}

export interface RegionGroupView extends RegionGroup {
  on_failure_effective?: "hold" | "fallback";
  is_default: boolean;
  effective_order: string[];
  target: string;
  target_reason: string;
  switchable: boolean;
  switch_order: string[];
  mesh_backup: boolean;
  fwmark?: string;
  table?: number;
  member_status: GroupMemberView[];
  actual: GroupActualView;
  model: GroupModelView;
  in_use_by: Ref[];
}

export interface GroupThresholds {
  fails_need: number;
  recovers_need: number;
  cooldown_sec: number;
}

export interface GroupHubState {
  hub_node?: string;
  hub_name?: string;
  server_id?: string;
  server_name?: string;
  /** The hub node has a managed server with a trusted key and a credential. */
  readable: boolean;
  not_readable_code?: string;
  not_readable_ssh_code?: string;
  not_readable_message?: string;
  last_read: {
    read_at: string;
    ok: boolean;
    error_code?: string;
    ssh_code?: string;
    /** ssh_rate_limited: the panel does not read the hub again before read_at + retry_after seconds. */
    retry_after?: number;
    error?: string;
    clock_skew_sec?: number;
    /** false: the read was taken from another hub identity (hub node, server, address, SSH port, pinned host key) and says nothing about the current hub. */
    current_hub?: boolean;
    identity_code?: string;
    identity_message?: string;
    ignored: string[];
  } | null;
  refreshing: boolean;
  loop_interval_sec: number;
  stale_after_sec: number;
  read_max_age_sec: number;
  skew_warn_sec: number;
  counts: Record<string, number>;
}

export interface RegionGroupsView {
  groups: RegionGroupView[];
  default_group: string;
  thresholds: GroupThresholds;
  hub_state: GroupHubState;
}

export type RegionGroupInput = Omit<RegionGroup, "migrated_from">;
export type RegionGroupPatch = Partial<RegionGroupInput>;

// ---- Remote access ------------------------------------------------------------

export type RemoteMode = "full" | "home";

export interface RemoteSettingsView {
  enabled: boolean;
  endpoint: string;
  listen_port: number;
  ipv4_prefix: string;
  ipv6_prefix: string;
  mtu: number;
  keepalive: number;
  interface: string;
  gateway_ipv4: string;
  gateway_ipv6: string;
  dns: string[];
  public_key: string;
  max_devices: number;
  device_count: number;
  defaults: { ipv4_prefix: string; ipv6_prefix: string; mtu: number; keepalive: number; mode: RemoteMode };
  /** mode → explanation */
  modes: Record<string, string>;
}

export interface RemoteSettingsPatch {
  enabled?: boolean;
  endpoint?: string;
  listen_port?: number;
  ipv4_prefix?: string;
  ipv6_prefix?: string;
  mtu?: number;
  keepalive?: number;
}

export interface RemoteDeviceRuntime {
  last_handshake_at: string | null;
  rx_bytes: number;
  tx_bytes: number;
  online: boolean;
}

export interface RemoteDeviceView {
  id: string;
  name: string;
  notes: string;
  mode: RemoteMode;
  enabled: boolean;
  public_key: string;
  ipv4: string;
  ipv6: string;
  preshared_key: boolean;
  created_at: string;
  updated_at: string;
  key_created_at: string;
  /** Always false: the configuration was shown once and is not stored. */
  config_available: boolean;
  config_outdated: boolean;
  runtime: RemoteDeviceRuntime | null;
  /** ok | disabled | not_installed | unavailable | not_read */
  runtime_state: string;
}

export interface RemoteRuntimeView {
  available: boolean;
  /** ok | disabled | agent_unavailable | interface_absent | error */
  state: string;
  reason?: string;
  interface: string;
  read_at?: string;
}

export interface RouterForward {
  protocol: string;
  external_port: number;
  internal_address: string;
  internal_port: number;
  description: string;
  ipv6_note: string;
}

export interface RemoteAccessView {
  settings: RemoteSettingsView;
  router_forward: RouterForward;
  devices: RemoteDeviceView[];
  runtime?: RemoteRuntimeView;
  issues: Issue[];
  apply_required?: boolean;
}

export interface RemoteDeviceInput {
  name: string;
  notes?: string;
  mode?: RemoteMode;
  enabled?: boolean;
  preshared_key?: boolean;
}

export interface RemoteDevicePatch {
  name?: string;
  notes?: string;
  mode?: RemoteMode;
  enabled?: boolean;
  preshared_key?: boolean;
}

/**
 * The one-time client configuration (contains the device private key).
 * Keep it in component state only; never persist, log or put it in a URL.
 */
export interface RemoteClientConfig {
  text: string;
  filename: string;
  mode: RemoteMode;
  explanation: string;
  shown_once: boolean;
}

export interface RemoteDeviceConfigResult {
  device: RemoteDeviceView;
  config: RemoteClientConfig;
  router_forward: RouterForward;
  apply_required: boolean;
}

// ---- Unlock -------------------------------------------------------------------

export interface UnlockView {
  services: { rule_id: string; name: string; pool: string; preferred: string; members: string[]; pin: boolean }[];
  states: Record<
    string,
    {
      pool?: string;
      active?: string;
      sched_fails?: number;
      active_fails?: number;
      demoted?: boolean;
      unavailable?: boolean;
      preferred?: string;
      /** Start of the preferred member's unbroken success streak while demoted. */
      preferred_ok_at?: string;
      preferred_seen_at?: string;
      backup_ok_at?: string;
    }
  >;
  history: {
    at: string;
    observed_at?: string;
    kind: string;
    service: string;
    exit_id: string;
    family?: string;
    ok: boolean;
    rejected?: string;
    note?: string;
  }[];
  next_run: string;
  interval_sec: number;
  pending_apply: boolean;
  decisions: Record<string, string>;
  /** Exits the unlock state mentions that are no longer in the topology. */
  removed_exits?: string[];
}

/** network_ok | unlocked | not_unlocked | failed | unknown | not_applicable (nothing sent: the check does not support the family) */
export type ProbeCategory = "network_ok" | "unlocked" | "not_unlocked" | "failed" | "unknown" | "not_applicable";
export type ProbeGrade = "platform_signal" | "reachability_only" | "unknown_response" | "error" | "not_applicable";
export type ProbeCapability = "region_verdict" | "verdict" | "reachability" | "unsupported";

export interface ProbePart {
  platform: string;
  primary?: boolean;
  category: ProbeCategory;
  grade: ProbeGrade;
  signal?: string;
  region?: string;
  status?: number;
  evidence?: string;
  error?: string;
}

export interface ProbeJobItem {
  service: string;
  service_name: string;
  exit_id: string;
  exit_region?: string;
  family: "ipv4" | "ipv6";
  /** queued | running | done | skipped */
  state: string;
  started_at?: string;
  finished_at?: string;
  category?: ProbeCategory;
  region?: string;
  evidence?: string;
  egress?: string;
  error?: string;
  /** accepted | accepted:inconclusive | rejected:<reason> | note:<text> | not_ingested:<why> */
  ingest?: string;
  grade?: ProbeGrade;
  signal?: string;
  capability?: ProbeCapability;
  /** "synthetic_only" in this build: not validated against real platforms. */
  validation?: string;
  status?: number;
  parts?: ProbePart[];
  egress_ip?: string;
  egress_basis?: string;
  egress_iface?: string;
  group?: string;
  group_mode?: string;
  in_group?: boolean;
  active_exit?: string;
}

export interface ProbeJob {
  id: string;
  kind: "manual" | "scheduled";
  /** running | done | cancelled | timeout | interrupted */
  state: string;
  created_at: string;
  finished_at?: string;
  error?: string;
  items: ProbeJobItem[];
}

export interface ProbeCatalogEntry {
  service: string;
  name: string;
  reachability: boolean;
  basis: string;
  capability?: ProbeCapability;
  returns?: ProbeCategory[];
  ipv4_only?: boolean;
  probeable?: boolean;
  platforms?: { name: string; checked: boolean; primary: boolean; note?: string }[];
  requests?: string[];
  hosts?: string[];
  combine?: string;
  limits?: string;
  sources?: { name: string; url: string; checked: string }[];
  validation?: string;
  validation_text?: string;
  enabled?: boolean;
  group?: string;
  group_mode?: string;
}

export interface ProbeJobsView {
  jobs: ProbeJob[];
  running: string;
  catalog: ProbeCatalogEntry[];
  available: boolean;
  validation?: string;
  validation_text?: string;
}

export interface ProbeCatalogView {
  catalog: ProbeCatalogEntry[];
  available: boolean;
  validation: string;
  validation_text: string;
  grades: ProbeGrade[];
  ingest_rule: string;
}

export interface ProbeResultRow extends ProbeJobItem {
  exit_name?: string;
  /** actual_active: the hub reported it in use; model_active: 面板推算. */
  exit_groups: { id: string; name: string; mode: string; actual_active?: string; model_active?: string }[];
  service_active?: string;
  is_active: boolean;
  ingestible: boolean;
  /** The exit was removed from the topology: history, never a current result. */
  exit_removed?: boolean;
}

export interface ProbeSelection {
  services?: string[];
  exits?: string[];
  groups?: string[];
  families?: ("ipv4" | "ipv6")[];
}

// ---- Leak check -----------------------------------------------------------------

export interface LeakItem {
  id: string;
  status: string;
  /** automated | integration | human | limitation */
  scope?: string;
  title: string;
  detail: string;
}

// ---- Deployments and withdraw (撤回) -----------------------------------------------

export type WithdrawMode = "manifest" | "journal" | "legacy";

/** The last withdraw / recovery of a node (internal/api/withdraw.go withdrawRecord). */
export interface WithdrawRecord {
  /** running | withdrawn | already_withdrawn | partial | refused | not_started | unknown | recovered | recovery_incomplete | abandoned */
  state: string;
  mode: string;
  run: string;
  at: string;
  finished?: string;
  code?: string;
  reason?: string;
  message?: string;
  removed?: string[];
  kept?: string[];
  leftovers?: string[];
  restored_previous?: boolean;
}

export interface WithdrawTarget {
  server_id: string;
  server_name: string;
  address: string;
  port: number;
  user: string;
  fingerprint: string;
  credential_id: string;
  credential_name?: string;
}

export interface WithdrawPlan {
  id: string;
  node_id: string;
  mode: WithdrawMode;
  target: WithdrawTarget;
  deployment: string;
  digest: string;
  owner?: string;
  items: string[];
  at: string;
  expires_at: string;
  already: boolean;
}

/** installed | left_behind | unknown | withdrawing | withdraw_interrupted | withdrawn | abandoned | withdraw_partial | not_installed */
export type DeploymentStatus = string;

/** One node deployment record (GET /api/deployments). */
export interface DeploymentView {
  node_id: string;
  node_name: string;
  in_topology: boolean;
  server_id: string;
  server_name?: string;
  current_server_id?: string;
  address: string;
  port: number;
  fingerprint: string;
  user?: string;
  credential_id?: string;
  deployment?: string;
  run: string;
  bundle: string;
  at: string;
  ok: boolean;
  code?: string;
  reason?: string;
  leftovers?: string[];
  kept?: string[];
  installed: boolean;
  outcome?: string;
  withdraw?: WithdrawRecord;
  on_host: boolean;
  status: DeploymentStatus;
  identity_problem?: string;
  mesh_bound?: string;
  plan?: WithdrawPlan;
}

export interface WithdrawSet {
  files: string[];
  interfaces: string[];
  units: string[];
  nft_tables: string[];
  route_tables: number[];
}

export interface GatewayWithdrawRecord {
  /** withdrawn | guard_released | already_withdrawn | not_installed | refused | compensated | uncompensated | check_failed */
  state: string;
  at: string;
  code?: string;
  message?: string;
  removed: WithdrawSet;
  kept: string[];
  host?: HostReport | null;
  compensated?: boolean;
  release_guard?: boolean;
  pending?: HostStatus["pending"];
}

export interface GatewayDeploymentView {
  installed: boolean;
  withdrawn: boolean;
  version?: number;
  origin?: string;
  plan: WithdrawSet;
  kept: string[];
  pending: HostStatus["pending"];
  last: GatewayWithdrawRecord | null;
  mesh_bound?: string;
  error?: string;
}

export interface DeploymentsView {
  nodes: DeploymentView[];
  gateway: GatewayDeploymentView;
}

export interface WithdrawRunResult {
  node_id: string;
  mode: WithdrawMode;
  outcome: string;
  code?: string;
  reason?: string;
  error?: string;
  message?: string;
  removed: string[];
  kept: string[];
  leftovers: string[];
  restored_previous?: boolean;
  output?: string;
  target?: WithdrawTarget;
}

export interface HostWithdrawResult {
  status: string;
  removed: WithdrawSet;
  kept: string[];
  host?: HostReport | null;
}
