import type { ExitLatencyView } from "./ExitLatency";
// Typed client for every panel API. One request function, one error type.
//
// Secrets: request bodies may carry passwords, private keys, passphrases or
// API tokens; nothing here stores, caches or logs a request body, and no
// response carries a secret except the one-time remote-access device
// configuration (createRemoteDevice / regenerateRemoteDevice), which callers
// must keep in component state only.
//
// Panel access token: kept in a module variable and mirrored to
// sessionStorage (tab-scoped, cleared when the tab closes) so that a page
// refresh does not force re-entry. Never localStorage, never a URL.

import type {
  AcceptanceConfirmation,
  TrafficView,
  AcceptanceDrill,
  AcceptanceJob,
  AcceptanceResult,
  AcceptanceRunBody,
  AcceptanceSummary,
  AcceptanceView,
  AllocationView,
  ImportPreview,
  ImportRequest,
  RuleAnalysis,

  RuleSet,
  RuleSetView,
  RuleSetBulkJob,
  DNSLogClearError,
  DNSLogClearResidual,
  DNSLogJournalView,
  DNSLogQuery,
  DNSLogRecord,
  DNSLogView,
  LogRelatedQuery,
  LogRelatedView,
  LinkLogAnswer,
  LinkLogQuery,
  LinkLogView,
  SniffJournalRecord,
  SniffJournalQuery,
  SniffJournalView,
  SniffDeviceLabel,
  SniffSettings,
  SniffView,
  DNSView,
  DNSConfigText,
  DNSCheckResult,
  DNSAccountView,
  DNSExitRow,
  ExitDNSUpstream,
  RuleSetAuthInput,
  RuleTestResult,
  ApiErrorBody,
  ApplyResult,
  Carrying,
  CloudflareAccountInput,
  CloudflareAccountPatch,
  CloudflareAccountView,
  CloudflareAccountsView,
  CloudflareRequirements,
  DiffResult,
  DeployView,
  TunnelCandidates,
  TunnelPathNote,
  HostKeyDiscovery,
  HostReport,
  HostStatus,
  Issue,
  LeakItem,
  ListKind,
  ListsHostStatus,
  ListsJob,
  ListsPolicy,
  ListsView,
  MeshRunBody,
  MeshRunResult,
  MeshStatus,
  HostMeshDetection,
  Meta,
  PanelStatus,
  PathReport,
  PermissionCheck,
  ProbeCatalogView,
  ProbeJob,
  ProbeJobsView,
  ProbeResultRow,
  ProbeSelection,
  ProvisionResult,
  PreflightRecord,
  MTUAdoptResult,
  MTUChange,
  UplinkMTUView,
  LoginHelp,
  ArtifactView,
  Ref,
  RegionGroupInput,
  RegionGroupPatch,
  RegionGroupView,
  RegionGroupsView,
  RemoteAccessView,
  RemoteDeviceConfigResult,
  RemoteDeviceInput,
  RemoteDevicePatch,
  RemoteDeviceView,
  RemoteFastApply,
  RulesFastApply,
  RemoteRuntimeView,
  RemoteSettingsPatch,
  RollbackMode,
  SSHCredentialCreate,
  SSHCredentialPatch,
  SSHCredentialView,
  SSHSecretInput,
  SOCKSCredentialCreate,
  SOCKSCredentialPatch,
  SOCKSCredentialView,
  SOCKSRotateResult,
  SOCKSSecretInput,
  SOCKSVersionTracking,
  ServerInput,
  ServerPatch,
  ServerView,
  ConnectionTest,
  Topology,
  TopologySaveResult,
  UnlockMatrixView,
  UnlockView,
  DeploymentsView,
  HostWithdrawResult,
  WithdrawMode,
  WithdrawPlan,
  WithdrawRunResult,
  DeploymentView,
  WSSListenerView,
  WSSView,
  RulesAutoApplyView,
} from "./types";

// Re-exported for the components that still import them from here.
export type {
  HostReport,
  HostStatus,
  LeakItem,
  MeshJournal,
  MeshPlan,
  MeshRunBody,
  MeshRunResult,
  MeshStatus,
  ProbeCatalogEntry,
  ProbeCategory,
  ProbeJob,
  ProbeJobItem,
  ProbeJobsView,
  ProbePart,
  ProbeSelection,
  RollbackMode,
  UnlockMatrixView,
  UnlockView,
} from "./types";

// ---------------------------------------------------------------- token ---

const TOKEN_KEY = "meridian.token";
let memToken: string | null = null;

export function getToken(): string {
  if (memToken === null) {
    try {
      memToken = sessionStorage.getItem(TOKEN_KEY) || "";
    } catch {
      memToken = "";
    }
  }
  return memToken;
}

export function setToken(token: string) {
  memToken = token.trim();
  try {
    if (memToken) sessionStorage.setItem(TOKEN_KEY, memToken);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable: memory only */
  }
}

export function clearToken() {
  setToken("");
}

const unauthorizedListeners = new Set<() => void>();

/** Called whenever a request comes back 401. Returns an unsubscribe function. */
export function onUnauthorized(cb: () => void): () => void {
  unauthorizedListeners.add(cb);
  return () => unauthorizedListeners.delete(cb);
}

// ---------------------------------------------------------------- errors ---

/**
 * Every failed request throws this. `code` is the handler's machine-readable
 * code (see ui.tsx errorTitle for the Chinese wording), `inUseBy` the
 * referrers of a refused delete or change, `body` the whole error body (Mesh
 * and lists errors carry extra fields there).
 */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly field?: string;
  readonly inUseBy: Ref[];
  readonly issues?: Issue[];
  readonly body: ApiErrorBody;

  constructor(status: number, body: ApiErrorBody, fallbackCode = "") {
    const message =
      (typeof body.error === "string" && body.error) ||
      (status === 401 ? "需要面板口令" : status === 0 ? "无法连接面板服务" : `请求失败（HTTP ${status}）`);
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = (typeof body.code === "string" && body.code) || fallbackCode;
    this.field = typeof body.field === "string" ? body.field : undefined;
    this.inUseBy = Array.isArray(body.in_use_by) ? body.in_use_by : [];
    this.issues = Array.isArray(body.issues) ? body.issues : undefined;
    this.body = body;
  }
}

export function isApiError(e: unknown): e is ApiError {
  return e instanceof ApiError;
}

// --------------------------------------------------------------- request ---

type Method = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export async function request<T>(method: Method, path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
  const headers: Record<string, string> = {};
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  let res: Response;
  try {
    res = await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store",
      credentials: "same-origin",
      signal,
    });
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError") throw e;
    throw new ApiError(0, {}, "network");
  }
  const text = await res.text();
  let data: unknown = {};
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = {};
    }
  }
  if (!res.ok) {
    if (res.status === 401) unauthorizedListeners.forEach((cb) => cb());
    const errBody = data && typeof data === "object" ? (data as ApiErrorBody) : {};
    throw new ApiError(res.status, errBody, res.status === 401 ? "unauthorized" : "");
  }
  return data as T;
}

const enc = encodeURIComponent;

/** Mutations that only change the stored document say so. */
export interface ApplyRequired {
  apply_required?: boolean;
}

// ------------------------------------------------------------------ core ---

export const health = () => request<{ status: string; service: string }>("GET", "/api/health");
export const getMeta = () => request<Meta>("GET", "/api/meta");

// Panel initialisation (internal/api/setup.go). No token needed.
export interface SetupStatus {
  state: "setup_required" | "ready";
  admin: boolean;
  token_login: boolean;
}
export const getSetupStatus = () => request<SetupStatus>("GET", "/api/setup/status");
export const postSetup = (body: { code: string; username: string; password: string }) =>
  request<{ token: string }>("POST", "/api/setup", body);
export const postLogin = (body: { username: string; password: string }) =>
  request<{ token: string }>("POST", "/api/auth/login", body);
export const getTopology = () => request<Topology>("GET", "/api/topology");
/** Changes the administrator (current password required once one exists). */
export const putAdmin = (body: { current_password: string; username: string; password: string }) =>
  request<SetupStatus>("PUT", "/api/auth/admin", body);

// Topology templates (internal/api/templates.go).
export interface TemplateField {
  key: string;
  label: string;
  kind: string;
  required: boolean;
}
export interface TopologyTemplate {
  id: string;
  name: string;
  nodes: string[];
  fields: TemplateField[];
}
export interface TemplateServer {
  name: string;
  endpoint_v4: string;
  ingress_v4?: string;
  region?: string;
  /** The server's WAN NIC (detected by the connection test, confirmed here); empty means eth0. */
  wan_interface?: string;
  server_id?: string;
}
export interface TemplateGateway {
  lan_interface: string;
  lan_ipv4: string;
  router_ipv4: string;
}
/** The template answers besides the gateway block. */
export interface TemplateAnswers {
  exits: TemplateServer[];
  relay?: TemplateServer;
  hub?: TemplateServer;
  /** relay_hub, ix: optional backup hub. */
  backup_hub?: TemplateServer;
  /** relay_hub only: relays that reach the backup hub (none: the gateway's own standby WSS). */
  backup_relays?: TemplateServer[];
  default_region: string;
}
export interface TemplatePreview {
  template: string;
  topology: Topology;
  valid: boolean;
  issues: Issue[];
  paths: PathReport[];
}
export const getTemplates = () => request<{ templates: TopologyTemplate[] }>("GET", "/api/templates");
export const previewTemplate = (id: string, input: TemplateAnswers & { gateway: TemplateGateway }) =>
  request<TemplatePreview>("POST", `/api/templates/${enc(id)}/preview`, input);

// First-run setup wizard progress (internal/api/wizard.go). No secrets.
export type WizardStep = "gateway" | "template" | "servers" | "topology" | "preflight" | "install";
export interface WizardState {
  step: WizardStep;
  done: WizardStep[];
  gateway: TemplateGateway;
  template: string;
  input?: TemplateAnswers | null;
  topology_version?: string;
  preflight_id?: string;
  started?: boolean;
  completed?: boolean;
  updated_at?: string;
}
export interface WizardView {
  active: boolean;
  state: WizardState;
  detected: { lan_ip?: string };
}
export const getWizard = () => request<WizardView>("GET", "/api/setup/wizard");
export const putWizard = (st: WizardState) => {
  const body: Record<string, unknown> = { ...st };
  delete body.started;
  delete body.completed;
  delete body.updated_at;
  return request<WizardView>("PUT", "/api/setup/wizard", body);
};
export const completeWizard = () => request<WizardView>("POST", "/api/setup/wizard/complete", {});

/**
 * Blocks of the topology document that have their own endpoints. The
 * whole-document save never writes them and refuses (409
 * independent_resource_changed) a request that carries a value different
 * from the stored one — which a working copy loaded before such an
 * endpoint changed them would. The editors never change them, so the save
 * leaves them out ("omitted": the stored blocks stay).
 */
export const INDEPENDENT_FIELDS = ["rule_sets", "mihomo_import", "remote_access"] as const;

/** The document a whole-topology save sends: without the independent blocks (and without settings.sniff, settings.exit_dns, settings.dns_log, nodes[].exit_dns). */
export function topologyForSave(topo: Topology): Topology {
  const out: Record<string, unknown> = { ...topo };
  for (const k of INDEPENDENT_FIELDS) delete out[k];
  const settings: Record<string, unknown> = { ...topo.settings };
  delete settings.sniff;
  delete settings.exit_dns;
  delete settings.dns_log;
  out.settings = settings;
  // The exits' resolver upstream is written by PUT /api/dns/upstream only.
  out.nodes = (topo.nodes ?? []).map((n) => {
    if (!("exit_dns" in n)) return n;
    const c: Record<string, unknown> = { ...n };
    delete c.exit_dns;
    return c;
  });
  return out as unknown as Topology;
}

export function putTopology(topo: Topology, draft: boolean) {
  return request<TopologySaveResult>("PUT", draft ? "/api/topology?draft=1" : "/api/topology", topologyForSave(topo));
}

export const validate = (topo?: Topology) =>
  request<{ issues: Issue[]; paths: PathReport[] }>("POST", "/api/validate", topo ?? {});

/** What each link (and exit/group) holds in the working copy, with the slots a save would give it. Read-only. */
export const allocations = (topo?: Topology, signal?: AbortSignal) =>
  request<AllocationView>("POST", "/api/topology/allocations", topo ?? {}, signal);

export const compile = (topo?: Topology) => request<Record<string, unknown>>("POST", "/api/compile", topo ?? {});

/** Without a topology the stored document is compiled and compared. */
export const diff = (topo?: Topology) => request<DiffResult>("POST", "/api/diff", topo ?? {});

/** `preflightId`: the reviewed install pre-check (required for the first install to the gateway). */
export const apply = (dryRun: boolean, install: boolean, preflightId?: string) =>
  request<ApplyResult>("POST", "/api/apply", { dry_run: dryRun, install, ...(preflightId ? { preflight_id: preflightId } : {}) });

/** Read-only install pre-check of the gateway through meridian-host. */
export const hostPreflight = () => request<{ preflight: PreflightRecord }>("POST", "/api/host/preflight", {});
/** The binaries the panel delivers (pinned version, digest, verified copy or not). */
export const listArtifacts = () => request<{ artifacts: ArtifactView[] }>("GET", "/api/artifacts");

/**
 * "runtime" restores the host and the data directory in one transaction;
 * "snapshot" only swaps the data-dir snapshots (refused once installed unless
 * explicit). There is no implicit default.
 */
export function rollback(mode: RollbackMode) {
  const body = mode === "runtime" ? { install: true } : { snapshot_only: true };
  return request<{ status: string; mode: RollbackMode; host?: HostReport | null }>("POST", "/api/rollback", body);
}

/** Cheap, read-only: agent reachability, installed-vs-stored, pending transaction, job states. */
export const getExitLatency = () => request<ExitLatencyView>("GET", "/api/exits/latency");
export const measureExitLatency = () => request<ExitLatencyView>("POST", "/api/exits/latency", {});
export const getStatus = () => request<PanelStatus>("GET", "/api/status");
export const hostStatus = () => request<HostStatus>("GET", "/api/host");
export const recoverHost = () => request<{ status: string; host?: HostReport | null }>("POST", "/api/host/recover", {});

/**
 * Dry run by default; `dryRun: false` really connects and provisions. A run
 * takes the reviewed `preflightId` (required for a first install); the
 * server re-runs the preflight right before executing.
 */
export function provision(nodeId: string, opts: { dryRun?: boolean; generateKeys?: boolean; preflightId?: string } = {}) {
  return request<ProvisionResult>("POST", "/api/provision", {
    node_id: nodeId,
    dry_run: opts.dryRun ?? true,
    ...(opts.generateKeys ? { generate_keys: true } : {}),
    ...(opts.preflightId ? { preflight_id: opts.preflightId } : {}),
  });
}

// ---------------------------------------------- ordered deployment guide ---

/** The plan (nodes to install, in order, with reasons) and the open or last run. */
export const getDeploy = () => request<DeployView>("GET", "/api/deploy");
/** Starts a run of the plan the operator looked at (refused when the topology changed since). */
export const startDeploy = (topologyVersion?: string) =>
  request<DeployView>("POST", "/api/deploy/runs", topologyVersion ? { topology_version: topologyVersion } : {});
/** Read-only preflight of the run's current node (also the re-check after a failure). */
export const deployPreflight = (runId: string, nodeId: string) =>
  request<DeployView>("POST", `/api/deploy/runs/${enc(runId)}/preflight`, { node_id: nodeId });
/** The operator's confirmation of one node: installs it with exactly the reviewed preflight. */
export const deployInstall = (runId: string, nodeId: string, preflightId: string) =>
  request<DeployView>("POST", `/api/deploy/runs/${enc(runId)}/install`, { node_id: nodeId, preflight_id: preflightId });
/** Verify one verify-only step (`nodeId`) or every one not done (`"all"`): read-only, one server at a time. */
export const deployVerify = (runId: string, target: { nodeId: string } | "all") =>
  request<DeployView>("POST", `/api/deploy/runs/${enc(runId)}/verify`, target === "all" ? { all: true } : { node_id: target.nodeId });
export const deployReplan = (runId: string) => request<DeployView>("POST", `/api/deploy/runs/${enc(runId)}/replan`, {});
export const deployCancel = (runId: string) => request<DeployView>("POST", `/api/deploy/runs/${enc(runId)}/cancel`, {});
/** Skips the current blocked / unreachable step for this run (it stays pending; nodes that depend on it wait). */
export const deploySkip = (runId: string, nodeId: string) => request<DeployView>("POST", `/api/deploy/runs/${enc(runId)}/skip`, { node_id: nodeId });
/** Returns to a skipped step (reopens a run that ended partial). */
export const deployUnskip = (runId: string, nodeId: string) => request<DeployView>("POST", `/api/deploy/runs/${enc(runId)}/unskip`, { node_id: nodeId });

/** Both ends' uplink MTU of every tunnel leg, from the latest preflights, and the suggested tunnel MTUs. Read-only. */
export const uplinkMTU = () => request<UplinkMTUView>("GET", "/api/mtu/uplinks");
/**
 * Writes exactly the shown suggestions into the links' MTU field (compare-and-set on `from`).
 * Changes the stored topology only: nothing is deployed until the deploy page's own confirmation.
 */
export const adoptUplinkMTU = (changes: MTUChange[]) =>
  request<MTUAdoptResult>("POST", "/api/mtu/adopt", { changes: changes.map(({ link_id, field, from, to }) => ({ link_id, field, from, to })) });

/** Read-only preflight of a remote node's server over the pinned SSH channel. */
export const provisionPreflight = (nodeId: string) =>
  request<{ preflight: PreflightRecord }>("POST", "/api/provision/preflight", { node_id: nodeId });

// --------------------------------------------------------------- servers ---

export const listServers = () => request<{ servers: ServerView[] }>("GET", "/api/servers");
export const getServer = (id: string) => request<{ server: ServerView }>("GET", `/api/servers/${enc(id)}`);
export const createServer = (input: ServerInput) => request<{ server: ServerView }>("POST", "/api/servers", input);
export const updateServer = (id: string, patch: ServerPatch) =>
  request<{ server: ServerView }>("PATCH", `/api/servers/${enc(id)}`, patch);
export const deleteServer = (id: string) => request<{ deleted: string }>("DELETE", `/api/servers/${enc(id)}`);
export const discoverHostKey = (id: string) =>
  request<{ discovery: HostKeyDiscovery; server: ServerView }>("POST", `/api/servers/${enc(id)}/host-key/discover`, {});
/** `fingerprint` must be exactly the discovered (or mismatching) value. */
export const trustHostKey = (id: string, fingerprint: string) =>
  request<{ server: ServerView }>("POST", `/api/servers/${enc(id)}/host-key/trust`, { fingerprint });
export const forgetHostKey = (id: string) => request<{ server: ServerView }>("DELETE", `/api/servers/${enc(id)}/host-key`);
export const testServer = (id: string) =>
  request<{ test: ConnectionTest; server: ServerView; login_help?: LoginHelp; path_note?: TunnelPathNote }>("POST", `/api/servers/${enc(id)}/test`, {});
/** The derived tunnel management addresses of the server's node (nothing is contacted). */
export const getTunnelCandidates = (id: string) => request<TunnelCandidates>("GET", `/api/servers/${enc(id)}/tunnel-candidates`);
/**
 * Connection test over a tunnel address before it is saved: pinned host key
 * required, the server's credential, the same rate limits; not recorded.
 */
export const testTunnelCandidate = (id: string, address: string, port?: number) =>
  request<{ test: ConnectionTest; candidate: true; server: ServerView; path_note?: TunnelPathNote }>("POST", `/api/servers/${enc(id)}/test`, {
    channel: { mode: "tunnel", address, ...(port ? { port } : {}) },
  });

// ------------------------------------------------------- SSH credentials ---

export const listCredentials = () => request<{ credentials: SSHCredentialView[] }>("GET", "/api/ssh-credentials");
export const getCredential = (id: string) =>
  request<{ credential: SSHCredentialView }>("GET", `/api/ssh-credentials/${enc(id)}`);
export const createCredential = (input: SSHCredentialCreate) =>
  request<{ credential: SSHCredentialView }>("POST", "/api/ssh-credentials", input);
export const updateCredential = (id: string, patch: SSHCredentialPatch) =>
  request<{ credential: SSHCredentialView }>("PATCH", `/api/ssh-credentials/${enc(id)}`, patch);
/** Same ID, same kind, new secret. */
export const rotateCredential = (id: string, secret: SSHSecretInput) =>
  request<{ credential: SSHCredentialView }>("PUT", `/api/ssh-credentials/${enc(id)}/secret`, secret);
export const deleteCredential = (id: string) => request<{ deleted: string }>("DELETE", `/api/ssh-credentials/${enc(id)}`);

// ----------------------------------------------------- SOCKS credentials ---

/** Username and password of external SOCKS exits' proxies: write-only, responses carry metadata only. */
export const listSocksCredentials = () =>
  request<{ credentials: SOCKSCredentialView[]; version_tracking?: SOCKSVersionTracking }>("GET", "/api/socks-credentials");
export const createSocksCredential = (input: SOCKSCredentialCreate) =>
  request<{ credential: SOCKSCredentialView }>("POST", "/api/socks-credentials", input);
export const updateSocksCredential = (id: string, patch: SOCKSCredentialPatch) =>
  request<{ credential: SOCKSCredentialView }>("PATCH", `/api/socks-credentials/${enc(id)}`, patch);
/** Same ID, new username and password; the carrier must be re-provisioned to use them. */
export const rotateSocksCredential = (id: string, secret: SOCKSSecretInput) =>
  request<SOCKSRotateResult>("PUT", `/api/socks-credentials/${enc(id)}/secret`, secret);
/** 409 in_use (in_use_by: the external exits) while an external exit names it. */
export const deleteSocksCredential = (id: string) => request<{ deleted: string }>("DELETE", `/api/socks-credentials/${enc(id)}`);

// ------------------------------------------------------------ Cloudflare ---

export const listAccounts = () => request<CloudflareAccountsView>("GET", "/api/cloudflare/accounts");
export const getAccount = (id: string) =>
  request<{ account: CloudflareAccountView }>("GET", `/api/cloudflare/accounts/${enc(id)}`);
export const createAccount = (input: CloudflareAccountInput) =>
  request<{ account: CloudflareAccountView }>("POST", "/api/cloudflare/accounts", input);
export const updateAccount = (id: string, patch: CloudflareAccountPatch) =>
  request<{ account: CloudflareAccountView }>("PATCH", `/api/cloudflare/accounts/${enc(id)}`, patch);
export const rotateAccountToken = (id: string, apiToken: string) =>
  request<{ account: CloudflareAccountView }>("PUT", `/api/cloudflare/accounts/${enc(id)}/token`, { api_token: apiToken });
export const deleteAccount = (id: string) => request<{ deleted: string }>("DELETE", `/api/cloudflare/accounts/${enc(id)}`);
export const checkAccount = (id: string) =>
  request<{ check: PermissionCheck; account: CloudflareAccountView }>("POST", `/api/cloudflare/accounts/${enc(id)}/check`, {});
/** "" clears the selection. */
export const setMeshAccount = (account: string) =>
  request<{ mesh_account: string | null }>("PUT", "/api/cloudflare/mesh-account", { account });
export const getCloudflareRequirements = () => request<CloudflareRequirements>("GET", "/api/cloudflare/requirements");

// ------------------------------------------------------------------ Mesh ---

export const getMesh = () => request<MeshStatus>("GET", "/api/mesh");
/** Fixed read-only detection of host-level Mesh nodes over the pinned SSH channel. */
export const meshDetect = (node_id?: string) =>
  request<{ detections: HostMeshDetection[] }>("POST", "/api/mesh/detect", node_id ? { node_id } : {});
export const meshDeploy = (body: MeshRunBody = {}) => request<MeshRunResult>("POST", "/api/mesh/deploy", body);
/** Takes nothing: servers, credentials, host keys and the account come from the journal. */
export const meshWithdraw = (link_id?: string) => request<MeshRunResult>("POST", "/api/mesh/withdraw", link_id ? { link_id } : {});

/** Legacy single-account endpoints (act on the Mesh account). Prefer the account API. */
export const putMeshCredentials = (accountId: string, apiToken: string) =>
  request<{ credentials: { account_id?: string; token_set: boolean } }>("PUT", "/api/mesh/credentials", {
    account_id: accountId,
    api_token: apiToken,
  });
export const deleteMeshCredentials = () => request<{ credentials: null }>("DELETE", "/api/mesh/credentials");

// ----------------------------------------------------------------- lists ---

export const getLists = () => request<ListsView>("GET", "/api/lists");
export const setListsPolicy = (policy: ListsPolicy) => request<ListsView>("PUT", "/api/lists/policy", { policy });
/** 202 with the started job; 409 update_running; 503 host_unavailable. */
export const updateLists = (body: { lists?: ListKind[]; policy?: ListsPolicy } = {}) =>
  request<{ job: ListsJob }>("POST", "/api/lists/update", body);
export const getListsJob = (signal?: AbortSignal) => request<{ job: ListsJob | null }>("GET", "/api/lists/job", undefined, signal);
export const getListsStatus = () => request<{ status: ListsHostStatus }>("GET", "/api/lists/status");

// --------------------------------------------------------- region groups ---

export const listGroups = () => request<RegionGroupsView>("GET", "/api/region-groups");
export const getGroup = (id: string) =>
  request<{ group: RegionGroupView; thresholds: RegionGroupsView["thresholds"] }>("GET", `/api/region-groups/${enc(id)}`);
export const createGroup = (input: RegionGroupInput) =>
  request<{ group: RegionGroupView } & ApplyRequired>("POST", "/api/region-groups", input);
export const updateGroup = (id: string, patch: RegionGroupPatch) =>
  request<{ group: RegionGroupView } & ApplyRequired>("PATCH", `/api/region-groups/${enc(id)}`, patch);
export const deleteGroup = (id: string) =>
  request<{ deleted: string } & ApplyRequired>("DELETE", `/api/region-groups/${enc(id)}`);
export const setDefaultGroup = (group: string) =>
  request<{ default_group: string; group: RegionGroupView } & ApplyRequired>("PUT", "/api/region-groups/default", { group });
/** Reads the hub's region-group state once over the managed-server SSH channel (fixed command). */
/** Which hub carries the gateway's traffic now (cheap; overview page). */
/** Cumulative throughput counters (poll and diff; see TrafficChart). */
export const getRulesAutoApply = (signal?: AbortSignal) => request<RulesAutoApplyView>("GET", "/api/rules/auto-apply", undefined, signal);
export const getTraffic = (signal?: AbortSignal) => request<TrafficView>("GET", "/api/traffic", undefined, signal);
export const getUpstream = () => request<Carrying>("GET", "/api/upstream");
export const refreshGroupRuntime = () => request<RegionGroupsView>("POST", "/api/region-groups/runtime/refresh");
export const postGroupHealth = (observations: { id: string; up: boolean }[]) =>
  request<{ groups: RegionGroupView[]; flipped: string[] }>("POST", "/api/region-groups/health", { observations });

// --------------------------------------------------------- remote access ---

export const getRemoteAccess = () => request<RemoteAccessView>("GET", "/api/remote-access");
export const putRemoteAccess = (patch: RemoteSettingsPatch) =>
  request<RemoteAccessView>("PUT", "/api/remote-access", patch);
export const listRemoteDevices = () =>
  request<{ devices: RemoteDeviceView[]; runtime: RemoteRuntimeView }>("GET", "/api/remote-access/devices");
export const getRemoteDevice = (id: string) =>
  request<{ device: RemoteDeviceView; runtime: RemoteRuntimeView }>("GET", `/api/remote-access/devices/${enc(id)}`);
/** The response holds the one-time configuration: component state only. */
export const createRemoteDevice = (input: RemoteDeviceInput) =>
  request<RemoteDeviceConfigResult>("POST", "/api/remote-access/devices", input);
/** A device change: installed at once when it only changes the peers. */
export type RemoteChange = ApplyRequired & { fast_apply?: RemoteFastApply };
/** A rules / service-group / rule-set / import save: the automatic install's outcome (R1). */
export type RulesChange = ApplyRequired & { fast_apply?: RulesFastApply };
export const updateRemoteDevice = (id: string, patch: RemoteDevicePatch) =>
  request<{ device: RemoteDeviceView } & RemoteChange>("PATCH", `/api/remote-access/devices/${enc(id)}`, patch);
export const deleteRemoteDevice = (id: string) =>
  request<{ deleted: string } & RemoteChange>("DELETE", `/api/remote-access/devices/${enc(id)}`);
/** New keys; the old public key stops working after the next install. */
export const regenerateRemoteDevice = (id: string, opts: { preshared_key?: boolean } = {}) =>
  request<RemoteDeviceConfigResult>("POST", `/api/remote-access/devices/${enc(id)}/regenerate`, opts);

// ---------------------------------------------------------------- unlock ---

export const getUnlock = () => request<UnlockView>("GET", "/api/unlock");
export const reportUnlock = (body: unknown) =>
  request<{ pending_apply: boolean; decisions: Record<string, string> }>("POST", "/api/unlock/report", body);
export const getUnlockCatalog = () => request<ProbeCatalogView>("GET", "/api/unlock/catalog");
export const runUnlock = (sel: ProbeSelection = {}) => request<{ job: ProbeJob }>("POST", "/api/unlock/run", sel);
export const getUnlockMatrix = (signal?: AbortSignal) => request<UnlockMatrixView>("GET", "/api/unlock/matrix", undefined, signal);
/** 手动: the operator's pick, with the exit identity the matrix showed. */
/** 手动: a group (the rules follow it; exit "") or an exit (the rules pin it), with the identity the matrix showed. */
export interface ManualPick {
  manual: true;
  identity: string;
  group?: string;
}
/** confirm: rules → the recommended exit's group, which prefers it; group / exit: the manual picks. */
export type AdoptKind = "confirm" | "group" | "exit";
/** 确认 (the recommendation) or 手动 (opts): same endpoint, same checks and save. */
export const adoptUnlock = (service: string, exit: string, opts?: ManualPick) =>
  request<{ updated: number; kind?: AdoptKind; group: string; exit: string; manual?: boolean; rules?: string[] } & RulesChange>("POST", "/api/unlock/adopt", {
    service,
    exit,
    ...opts,
  });
/** What saving would move, without saving: the service's rules and how many other rules share the group. */
export const previewAdoptUnlock = (service: string, exit: string, opts?: ManualPick) =>
  request<{ preview: true; kind?: AdoptKind; group: string; exit: string; service_rules: string[]; other_rules: number }>("POST", "/api/unlock/adopt", {
    service,
    exit,
    ...opts,
    preview: true,
  });
export const getUnlockJobs = () => request<ProbeJobsView>("GET", "/api/unlock/jobs");
export const getUnlockJob = (id: string) =>
  request<{ job: ProbeJob; running: boolean }>("GET", `/api/unlock/jobs/${enc(id)}`);
export const cancelUnlockJob = (id: string) =>
  request<{ cancelled: string }>("POST", `/api/unlock/jobs/${enc(id)}/cancel`);
export function getUnlockResults(
  filter: { service?: string; exit?: string; group?: string; family?: string; include_removed?: string } = {},
) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(filter)) if (v) q.set(k, v);
  const qs = q.toString();
  return request<{
    results: ProbeResultRow[];
    validation: string;
    validation_text: string;
    removed_exits?: { exit_id: string; results: number }[];
  }>(
    "GET",
    `/api/unlock/results${qs ? `?${qs}` : ""}`,
  );
}

/** Deletes stored probe results of exits no longer in the topology (admission records are kept). */
export const pruneUnlockResults = () => request<{ removed: number; exits: string[] }>("POST", "/api/unlock/results/prune", {});

// -------------------------------------------------------------- withdraw ---

export const getDeployments = () => request<DeploymentsView>("GET", "/api/deployments");
/** Read-only plan on the deployment's bound server. */
export const withdrawPlan = (nodeId: string, mode: WithdrawMode = "manifest") =>
  request<{ plan: WithdrawPlan; already_withdrawn?: boolean }>("POST", "/api/provision/withdraw/plan", { node_id: nodeId, mode });
/** Runs a reviewed plan; confirm is the node id typed by the operator. */
export const withdrawRun = (nodeId: string, planId: string, confirm: string) =>
  request<WithdrawRunResult>("POST", "/api/provision/withdraw", { node_id: nodeId, plan_id: planId, confirm });
export const withdrawAbandon = (nodeId: string, confirm: string) =>
  request<{ deployment: DeploymentView; changed: boolean }>("POST", "/api/provision/withdraw/abandon", { node_id: nodeId, confirm });
export const forgetDeployment = (nodeId: string) => request<{ deleted: string }>("DELETE", `/api/provision/state/${enc(nodeId)}`);
export const hostWithdraw = (confirm: string, releaseGuard = false) =>
  request<HostWithdrawResult>("POST", "/api/host/withdraw", releaseGuard ? { confirm, release_guard: true } : { confirm });

// ------------------------------------------------------------------- WSS ---

/** WSS carriers: per-listener certificate (fingerprint, validity), per-link
 * path ("set" only), rotation stages. No secret is ever returned. */
export const getWSS = () => request<WSSView>("GET", "/api/wss");
export const wssRegeneratePath = (linkId: string) =>
  request<{ listener: WSSListenerView; committed: boolean }>("POST", `/api/wss/links/${enc(linkId)}/regenerate-path`, {});
export const wssRegenerateCert = (nodeId: string) =>
  request<{ listener: WSSListenerView; committed: boolean }>("POST", `/api/wss/listeners/${enc(nodeId)}/regenerate-cert`, {});
export const wssCancel = (nodeId: string) =>
  request<{ listener: WSSListenerView; committed: boolean }>("POST", `/api/wss/listeners/${enc(nodeId)}/cancel`, {});

// ------------------------------------------------------------------ leak ---

export const getLeakcheck = () => request<{ items: LeakItem[] }>("GET", "/api/leakcheck");

// ------------------------------------------------------------ acceptance ---
// The 验收 page. Request bodies carry ids of installed resources only (a relay
// node id, exit ids, probe catalog ids) and a bounded duration; the server
// resolves everything else. A drill needs the token of prepareAcceptance.

export const getAcceptance = () => request<AcceptanceView>("GET", "/api/acceptance");
export const getAcceptanceSummary = () => request<AcceptanceSummary>("GET", "/api/acceptance/summary");
export const prepareAcceptance = (id: string, body: { target?: string; block_seconds?: number } = {}) =>
  request<AcceptanceConfirmation>("POST", `/api/acceptance/items/${enc(id)}/prepare`, body);
export const runAcceptance = (id: string, body: AcceptanceRunBody = {}) => request<{ job: AcceptanceJob }>("POST", `/api/acceptance/items/${enc(id)}/run`, body);
export const cancelAcceptance = (id: string) => request<{ cancelled?: string; cancelling?: string; note?: string }>("POST", `/api/acceptance/items/${enc(id)}/cancel`, {});
export const signoffAcceptance = (id: string, outcome: "pass" | "fail", note: string) =>
  request<{ result: AcceptanceResult }>("POST", `/api/acceptance/items/${enc(id)}/signoff`, { outcome, note });
export const retryAcceptanceDrill = (id: string) => request<{ drill: AcceptanceDrill }>("POST", "/api/acceptance/drill/retry", { id });
export const releaseAcceptanceDrill = (id: string, confirm: string) => request<{ drill: AcceptanceDrill }>("POST", "/api/acceptance/drill/release", { id, confirm });

// ---------------------------------------------------- ordered rules ---

export const listRuleSets = () => request<{ rule_sets: RuleSetView[]; formats: string[] }>("GET", "/api/rule-sets");
export const createRuleSet = (input: Partial<RuleSet> & { auth?: RuleSetAuthInput }) => request<RuleSetView & RulesChange>("POST", "/api/rule-sets", input);
export const setRuleSetAuth = (id: string, auth: RuleSetAuthInput) => request<RuleSetView>("PUT", `/api/rule-sets/${enc(id)}/auth`, auth);
export const clearRuleSetAuth = (id: string) => request<RuleSetView>("DELETE", `/api/rule-sets/${enc(id)}/auth`);
export const updateRuleSetDef = (id: string, patch: Partial<RuleSet>) => request<RuleSetView & RulesChange>("PATCH", `/api/rule-sets/${enc(id)}`, patch);
export const deleteRuleSet = (id: string) => request<{ deleted: string } & RulesChange>("DELETE", `/api/rule-sets/${enc(id)}`);
export const fetchRuleSet = (id: string) => request<RuleSetView>("POST", `/api/rule-sets/${enc(id)}/update`, {});
export const updateAllRuleSets = () => request<{ job: RuleSetBulkJob }>("POST", "/api/rule-sets/update-all", {});
export const getRuleSetsUpdateAll = (signal?: AbortSignal) => request<{ job: RuleSetBulkJob | null }>("GET", "/api/rule-sets/update-all", undefined, signal);
export const activateHeldRuleSet = (id: string) => request<RuleSetView>("POST", `/api/rule-sets/${enc(id)}/activate-held`, { accept: true });
export const retargetRules = (mihomoGroup: string, target: string) =>
  request<{ updated: number } & RulesChange>("POST", "/api/rules/retarget", { mihomo_group: mihomoGroup, target });
export const importPreview = (body: ImportRequest) => request<ImportPreview>("POST", "/api/rules/import/preview", body);
export const importConfirm = (body: ImportRequest) =>
  request<{ imported: number; rule_sets: number; default_group: string; digest: string } & RulesChange>("POST", "/api/rules/import/confirm", body);
export const testRule = (name: string, address: string, sourceMAC = "") =>
  request<RuleTestResult>("POST", "/api/rules/test", sourceMAC ? { name, address, source_mac: sourceMAC } : { name, address });
export const getSniff = () => request<SniffView>("GET", "/api/sniff");
export const putSniff = (s: SniffSettings) => request<{ setting: SniffView["setting"] }>("PUT", "/api/sniff", s);
/** Has the forwarder run its path self-check now; answers the view with the new result. */
export const postSniffSelfCheck = () => request<SniffView>("POST", "/api/sniff/selfcheck", {});
/** One page of the gateway's connection journal (newest first). */
export function getSniffJournal(query: SniffJournalQuery = {}) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) if (v !== undefined && v !== "" && v !== 0) q.set(k, String(v));
  const qs = q.toString();
  return request<SniffJournalView>("GET", `/api/sniff/journal${qs ? `?${qs}` : ""}`);
}
/** The per-device summary of the journal and the operator's device labels. */
export const getSniffDevices = () => request<SniffJournalView>("GET", "/api/sniff/devices");
export const putSniffDeviceLabel = (address: string, label: string) =>
  request<{ label: SniffDeviceLabel }>("PUT", `/api/sniff/devices/${enc(address)}/label`, { label });
export const deleteSniffDeviceLabel = (address: string) => request<unknown>("DELETE", `/api/sniff/devices/${enc(address)}/label`);
/** Clears the journal on the gateway (the dedicated fixed action; asks for confirmation in the UI first). */
export const clearSniffJournal = () => request<{ cleared: unknown }>("POST", "/api/sniff/journal/clear", { confirm: true });

// ------------------------------------------------ DNS query journal (解析日志) ---
/** Encodes the set fields of a query as a query string (without the "?"). */
function queryOf(query: object): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) if (v !== undefined && v !== "" && v !== 0) q.set(k, String(v));
  return q.toString();
}
/** The switch (planned and installed), the capability gate, the reader's state, scope and bounds. */
export const getDNSLog = () => request<DNSLogView>("GET", "/api/dns-log");
/** Sets the switch; enabling must be acknowledged in the UI first (it stores the names devices ask for). Takes effect with the next gateway install. */
export const putDNSLog = (enabled: boolean) => request<DNSLogView>("PUT", "/api/dns-log", enabled ? { enabled, acknowledge: true } : { enabled });
/** One page of the gateway's query journal (newest first). */
export function getDNSLogJournal(query: DNSLogQuery = {}) {
  const qs = queryOf(query);
  return request<DNSLogJournalView>("GET", `/api/dns-log/journal${qs ? `?${qs}` : ""}`);
}
/** The per-device summary and the device labels (shared with the connection journal). */
export function getDNSLogDevices(range: { from?: string; to?: string } = {}) {
  const qs = queryOf(range);
  return request<DNSLogJournalView>("GET", `/api/dns-log/devices${qs ? `?${qs}` : ""}`);
}
/**
 * Clears the query journal on the gateway (ask for confirmation in the UI
 * first). It resolves only when everything went. A clear that left
 * something rejects with an ApiError whose code is DNS_CLEAR_INCOMPLETE
 * (read what is left with dnsClearLeft); one that did nothing, or cannot be
 * confirmed, rejects with another error. Neither is ever a success.
 */
export const clearDNSLog = () => request<{ complete: true; cleared: unknown }>("POST", "/api/dns-log/clear", { confirm: true });

export const DNS_CLEAR_INCOMPLETE = "dns_log_clear_incomplete";

/** What an incomplete clear left and why (null: e is not that error). */
export function dnsClearLeft(e: unknown): { residual: DNSLogClearResidual; errors: DNSLogClearError[] } | null {
  if (!(e instanceof ApiError) || e.code !== DNS_CLEAR_INCOMPLETE) return null;
  const b = e.body as { residual?: Partial<DNSLogClearResidual> | null; errors?: DNSLogClearError[] | null };
  const r = b.residual ?? {};
  return {
    residual: {
      segments: r.segments ?? 0,
      records: r.records ?? 0,
      bytes: r.bytes ?? 0,
      raw_files: r.raw_files ?? 0,
      raw_bytes: r.raw_bytes ?? 0,
      // An answer without counts says nothing about what is left.
      unknown: r.unknown ?? !b.residual,
    },
    errors: Array.isArray(b.errors) ? b.errors : [],
  };
}
/** The connections of the same device around a query. */
export function getDNSLogRelated(query: LogRelatedQuery) {
  const qs = queryOf(query);
  return request<LogRelatedView<SniffJournalRecord>>("GET", `/api/dns-log/related${qs ? `?${qs}` : ""}`);
}
/** The queries of the same device around a connection. */
export function getSniffJournalRelated(query: LogRelatedQuery) {
  const qs = queryOf(query);
  return request<LogRelatedView<DNSLogRecord>>("GET", `/api/sniff/journal/related${qs ? `?${qs}` : ""}`);
}

// ------------------------------------------------------ link journal (链路日志) ---
/** Whether the collector is installed and running, its sources, the bounds and the scope (what is observed, with what evidence, what is not in scope). */
export const getLinkLog = () => request<LinkLogView>("GET", "/api/link-log");
/** The state now: which path carries, what is abnormal or unknown and for how long, with the evidence. */
export const getLinkLogCurrent = () => request<LinkLogAnswer>("GET", "/api/link-log/current");
/** One page of the timeline of state changes (newest first). */
export function getLinkLogEvents(query: LinkLogQuery = {}) {
  const qs = queryOf(query);
  return request<LinkLogAnswer>("GET", `/api/link-log/events${qs ? `?${qs}` : ""}`);
}
/** Clears the link journal on the gateway (ask for confirmation in the UI first). */
export const clearLinkLog = () => request<{ cleared: unknown }>("POST", "/api/link-log/clear", { confirm: true });
export const ruleAnalysis = () => request<{ rules: RuleAnalysis[]; notes?: string[] | null; shared_address: string; keyword_state?: "off" | "on" | "pending"; keyword_note?: string; upgrade_notes?: string[] }>("GET", "/api/rules/analysis");

// ------------------------------------------------- resolution (DNS) view ---

/** The read-only resolution view (compiled plan, planned vs installed, measured results). */
export const getDNS = () => request<DNSView>("GET", "/api/dns");
/** One node's generated SmartDNS config; account values are never part of it. */
export const getDNSConfig = (node: string) => request<DNSConfigText>("GET", `/api/dns/config?node=${enc(node)}`);
/** Saves the exits' resolver upstream into the topology (takes effect only after preflight and install). */
/**
 * Saves the exits' resolver upstream. Only what the body names changes: no
 * `global` key keeps the global setting (null clears it); exits not listed
 * keep their override (null: follow the global setting; {protocol:"builtin"}:
 * keep the built-in resolvers). `changed_exits` are the exits whose effective
 * upstream changed (each needs preflight → install).
 */
export const putDNSUpstream = (body: { global?: ExitDNSUpstream | null; exits?: Record<string, ExitDNSUpstream | null> }) =>
  request<{ global_upstream?: ExitDNSUpstream | null; exits?: DNSExitRow[]; changed_exits?: string[]; note: string }>("PUT", "/api/dns/upstream", body);
/** The fixed check: the gateway asks the exit's tunnel resolver one fixed name. */
export const postDNSCheck = (exitID: string) => request<{ check: DNSCheckResult; upstream: string }>("POST", "/api/dns/check", { exit_id: exitID });
/** DNS account identifiers: write-only values, responses carry metadata. */
export const listDNSAccounts = () => request<{ accounts: DNSAccountView[] }>("GET", "/api/dns-accounts");
export const createDNSAccount = (input: { name: string; notes?: string; account: string }) =>
  request<{ account: DNSAccountView }>("POST", "/api/dns-accounts", input);
export const rotateDNSAccount = (id: string, account: string) => request<{ account: DNSAccountView }>("PUT", `/api/dns-accounts/${enc(id)}/secret`, { account });
export const deleteDNSAccount = (id: string) => request<{ deleted: string }>("DELETE", `/api/dns-accounts/${enc(id)}`);

/**
 * The build id of the files the panel serves now (version.json, written by
 * `vite build`; static, no panel token, Cache-Control: no-cache). Null when
 * there is none (dev server, demo build) or it cannot be read.
 */
export async function fetchBuildVersion(signal?: AbortSignal): Promise<string | null> {
  try {
    const res = await fetch("version.json", { cache: "no-store", signal });
    if (!res.ok) return null;
    const body = (await res.json()) as { build?: unknown };
    return typeof body.build === "string" && body.build ? body.build : null;
  } catch {
    return null;
  }
}
