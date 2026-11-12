import type { Issue, PathReport, Topology } from "./types";

const TOKEN_KEY = "meridian.token";

export function setToken(token: string) {
  sessionStorage.setItem(TOKEN_KEY, token.trim());
}

export function getToken() {
  return sessionStorage.getItem(TOKEN_KEY) || "";
}

function headers(json: boolean): HeadersInit {
  const h: Record<string, string> = {};
  const token = getToken();
  if (token) h.Authorization = `Bearer ${token}`;
  if (json) h["Content-Type"] = "application/json";
  return h;
}

async function parse<T>(res: Response): Promise<T> {
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const message = body.error || (res.status === 401 ? "需要面板口令" : `请求失败 ${res.status}`);
    const err = new Error(message) as Error & { issues?: Issue[]; body?: unknown; status?: number };
    err.issues = body.issues;
    err.body = body;
    err.status = res.status;
    throw err;
  }
  return body as T;
}

export function getTopology() {
  return fetch("/api/topology", { headers: headers(false) }).then((r) => parse<Topology>(r));
}

export function putTopology(topo: Topology, draft: boolean) {
  const url = draft ? "/api/topology?draft=1" : "/api/topology";
  return fetch(url, {
    method: "PUT",
    headers: headers(true),
    body: JSON.stringify(topo),
  }).then((r) =>
    parse<{ topology: Topology; issues: Issue[]; paths: PathReport[]; draft: boolean }>(r),
  );
}

export function validate(topo: Topology) {
  return fetch("/api/validate", {
    method: "POST",
    headers: headers(true),
    body: JSON.stringify(topo),
  }).then((r) => parse<{ issues: Issue[]; paths: PathReport[] }>(r));
}

export function diff(topo: Topology) {
  return fetch("/api/diff", {
    method: "POST",
    headers: headers(true),
    body: JSON.stringify(topo),
  }).then((r) => parse<{ diff: string; order: string[]; issues: Issue[] }>(r));
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
}

export function apply(dryRun: boolean, install: boolean) {
  return fetch("/api/apply", {
    method: "POST",
    headers: headers(true),
    body: JSON.stringify({ dry_run: dryRun, install }),
  }).then((r) =>
    parse<{ dry_run: boolean; install: boolean; wrote?: string[]; order: string[]; diff: string; host?: HostReport }>(r),
  );
}

// "runtime" restores the host (files, interfaces, units, nft tables) to the
// previous snapshot in one transaction; "snapshot" only swaps the data-dir
// snapshots and is refused by the backend once Meridian is installed on the
// host unless asked for explicitly. There is no implicit default.
export type RollbackMode = "runtime" | "snapshot";

export function rollback(mode: RollbackMode) {
  const body = mode === "runtime" ? { install: true } : { snapshot_only: true };
  return fetch("/api/rollback", { method: "POST", headers: headers(true), body: JSON.stringify(body) }).then((r) =>
    parse<{ status: string; mode: RollbackMode; host?: HostReport | null }>(r),
  );
}

export interface HostStatus {
  installed: {
    version: number;
    created_at?: string;
    files: number;
    interfaces: string[];
    units: string[];
    nft_tables: string[];
    route_tables: number[];
    dns: boolean;
  } | null;
  pending: { id: string; kind: string; phase: string; error?: string; started: string; from_version: number; to_version: number } | null;
  agent: { ok: boolean; error?: string };
}

export function hostStatus() {
  return fetch("/api/host", { headers: headers(false) }).then((r) => parse<HostStatus>(r));
}

export function recoverHost() {
  return fetch("/api/host/recover", { method: "POST", headers: headers(true), body: "{}" }).then((r) =>
    parse<{ status: string; host?: HostReport | null }>(r),
  );
}

export interface PoolView {
  id: string;
  preferred: string;
  residential: boolean;
  mesh_backup: boolean;
  fails_need: number;
  recovers_need: number;
  cooldown_sec: number;
  active?: string;
  members: { id: string; name: string; ix_bound: boolean; residential: boolean; priority: number; preferred: boolean; up?: boolean }[];
}

export function getPools() {
  return fetch("/api/pools", { headers: headers(false) }).then((r) => parse<{ pools: PoolView[] }>(r));
}

export interface UnlockView {
  services: { rule_id: string; name: string; pool: string; preferred: string; members: string[]; pin: boolean }[];
  states: Record<string, { active?: string; sched_fails?: number; demoted?: boolean; unavailable?: boolean; preferred?: string }>;
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
}

export function getUnlock() {
  return fetch("/api/unlock", { headers: headers(false) }).then((r) => parse<UnlockView>(r));
}

export function reportUnlock(body: unknown) {
  return fetch("/api/unlock/report", { method: "POST", headers: headers(true), body: JSON.stringify(body) }).then((r) =>
    parse<{ pending_apply: boolean; decisions: Record<string, string> }>(r),
  );
}

// ---- Panel-run unlock probes ------------------------------------------------
// The panel only names catalog services, exits and address families. The
// probe itself runs in meridian-host through the exit's own mark and transit
// address; no URL, host or command is ever sent from here.

/** network_ok | unlocked | not_unlocked | failed | unknown */
export type ProbeCategory = "network_ok" | "unlocked" | "not_unlocked" | "failed" | "unknown";

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
}

export interface ProbeJobsView {
  jobs: ProbeJob[];
  running: string;
  catalog: ProbeCatalogEntry[];
  available: boolean;
}

export interface ProbeSelection {
  services?: string[];
  exits?: string[];
  families?: ("ipv4" | "ipv6")[];
}

export function runUnlock(sel: ProbeSelection = {}) {
  return fetch("/api/unlock/run", { method: "POST", headers: headers(true), body: JSON.stringify(sel) }).then((r) =>
    parse<{ job: ProbeJob }>(r),
  );
}

export function getUnlockJobs() {
  return fetch("/api/unlock/jobs", { headers: headers(false) }).then((r) => parse<ProbeJobsView>(r));
}

export function cancelUnlockJob(id: string) {
  return fetch(`/api/unlock/jobs/${encodeURIComponent(id)}/cancel`, { method: "POST", headers: headers(true) }).then((r) =>
    parse<{ cancelled: string }>(r),
  );
}

export interface LeakItem {
  id: string;
  status: string;
  /** automated | integration | human | limitation */
  scope?: string;
  title: string;
  detail: string;
}

export function getLeakcheck() {
  return fetch("/api/leakcheck", { headers: headers(false) }).then((r) => parse<{ items: LeakItem[] }>(r));
}

export function provision(nodeId: string) {
  return fetch("/api/provision", {
    method: "POST",
    headers: headers(true),
    body: JSON.stringify({ node_id: nodeId, dry_run: true }),
  }).then((r) => parse<{ dry_run: boolean; script: string; node_id: string }>(r));
}

// ---- Mesh deployment (panel-driven) ----------------------------------------
// The Cloudflare API token is write-only: the backend never returns it.
// The SSH private key is sent per request and never stored.

export interface MeshIssue {
  code: string;
  message: string;
  node_id?: string;
  link_id?: string;
}

export interface MeshStage {
  name: string;
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
  ssh_host: string;
  ssh_port: number;
  ssh_user: string;
  host_key?: string;
}

export interface MeshJournal {
  run_id: string;
  state: string;
  /** Cloudflare account the run's nodes and routes live in. */
  account_id?: string;
  /** Withdrawal goes to exactly these targets and requires these host keys. */
  hosts?: MeshHostPin[] | null;
  started: string;
  updated: string;
  fail_after?: string;
  stages: MeshStage[];
  nodes: { node_id: string; name: string; cf_id?: string; state: string; error?: string }[] | null;
  routes: { link_id: string; exit_id: string; network: string; tunnel_id: string; comment: string; cf_id?: string; state: string; error?: string }[] | null;
  remotes: { node_id: string; host?: MeshHostPin; state: string; error?: string }[] | null;
  targets: string[] | null;
  error?: string;
  compensation_errors?: string[];
  /** Always "unverified": the panel has no Linux packet-forwarding evidence. */
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
  nodes: { id: string; name: string; role: string; ssh_host?: string; ssh_port?: number; ssh_user?: string }[] | null;
  routes: { link_id: string; exit_id: string; network: string }[] | null;
  return_v4: string[] | null;
  return_v6: string[] | null;
  issues: MeshIssue[] | null;
}

export interface MeshStatus {
  dataplane: string;
  dataplane_note: string;
  fault_injection: boolean;
  stages: string[];
  credentials?: { account_id?: string; token_set: boolean };
  credentials_error?: string;
  plan?: MeshPlan;
  plan_error?: string;
  journal?: MeshJournal | null;
  journal_error?: string;
}

export interface MeshRunBody {
  private_key_pem?: string;
  trust_new_host?: boolean;
  nodes?: Record<string, { ssh_host?: string; ssh_port?: number; ssh_user?: string }>;
  fail_after?: string;
}

export interface MeshRunResult {
  journal?: MeshJournal | null;
  dataplane: string;
  dataplane_note: string;
  error?: string;
  stage?: string;
  compensated?: boolean;
  compensation_errors?: string[] | null;
}

export function getMesh() {
  return fetch("/api/mesh", { headers: headers(false) }).then((r) => parse<MeshStatus>(r));
}

export function putMeshCredentials(accountId: string, apiToken: string) {
  return fetch("/api/mesh/credentials", {
    method: "PUT",
    headers: headers(true),
    body: JSON.stringify({ account_id: accountId, api_token: apiToken }),
  }).then((r) => parse<{ credentials: { account_id?: string; token_set: boolean } }>(r));
}

export function deleteMeshCredentials() {
  return fetch("/api/mesh/credentials", { method: "DELETE", headers: headers(false) }).then((r) =>
    parse<{ credentials: null }>(r),
  );
}

export function meshDeploy(body: MeshRunBody) {
  return fetch("/api/mesh/deploy", { method: "POST", headers: headers(true), body: JSON.stringify(body) }).then((r) =>
    parse<MeshRunResult>(r),
  );
}

/** A withdrawal only takes the SSH key: targets and host keys come from the journal. */
export function meshWithdraw(body: { private_key_pem?: string }) {
  return fetch("/api/mesh/withdraw", { method: "POST", headers: headers(true), body: JSON.stringify(body) }).then((r) =>
    parse<MeshRunResult>(r),
  );
}
