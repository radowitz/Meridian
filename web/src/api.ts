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
  ApiErrorBody,
  ApplyResult,
  CloudflareAccountInput,
  CloudflareAccountPatch,
  CloudflareAccountView,
  CloudflareAccountsView,
  CloudflareRequirements,
  DiffResult,
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
  LoginHelp,
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
  RemoteRuntimeView,
  RemoteSettingsPatch,
  RollbackMode,
  SSHCredentialCreate,
  SSHCredentialPatch,
  SSHCredentialView,
  SSHSecretInput,
  ServerInput,
  ServerPatch,
  ServerView,
  ConnectionTest,
  Topology,
  TopologySaveResult,
  UnlockView,
  DeploymentsView,
  HostWithdrawResult,
  WithdrawMode,
  WithdrawPlan,
  WithdrawRunResult,
  DeploymentView,
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
export const getTopology = () => request<Topology>("GET", "/api/topology");

export function putTopology(topo: Topology, draft: boolean) {
  return request<TopologySaveResult>("PUT", draft ? "/api/topology?draft=1" : "/api/topology", topo);
}

export const validate = (topo?: Topology) =>
  request<{ issues: Issue[]; paths: PathReport[] }>("POST", "/api/validate", topo ?? {});

export const compile = (topo?: Topology) => request<Record<string, unknown>>("POST", "/api/compile", topo ?? {});

/** Without a topology the stored document is compiled and compared. */
export const diff = (topo?: Topology) => request<DiffResult>("POST", "/api/diff", topo ?? {});

/** `preflightId`: the reviewed install pre-check (required for the first install to the gateway). */
export const apply = (dryRun: boolean, install: boolean, preflightId?: string) =>
  request<ApplyResult>("POST", "/api/apply", { dry_run: dryRun, install, ...(preflightId ? { preflight_id: preflightId } : {}) });

/** Read-only install pre-check of the gateway through meridian-host. */
export const hostPreflight = () => request<{ preflight: PreflightRecord }>("POST", "/api/host/preflight", {});

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
  request<{ test: ConnectionTest; server: ServerView; login_help?: LoginHelp }>("POST", `/api/servers/${enc(id)}/test`, {});

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
export const meshDeploy = (body: MeshRunBody = {}) => request<MeshRunResult>("POST", "/api/mesh/deploy", body);
/** Takes nothing: servers, credentials, host keys and the account come from the journal. */
export const meshWithdraw = () => request<MeshRunResult>("POST", "/api/mesh/withdraw", {});

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
export const getListsJob = () => request<{ job: ListsJob | null }>("GET", "/api/lists/job");
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
export const updateRemoteDevice = (id: string, patch: RemoteDevicePatch) =>
  request<{ device: RemoteDeviceView } & ApplyRequired>("PATCH", `/api/remote-access/devices/${enc(id)}`, patch);
export const deleteRemoteDevice = (id: string) =>
  request<{ deleted: string } & ApplyRequired>("DELETE", `/api/remote-access/devices/${enc(id)}`);
/** New keys; the old public key stops working after the next install. */
export const regenerateRemoteDevice = (id: string, opts: { preshared_key?: boolean } = {}) =>
  request<RemoteDeviceConfigResult>("POST", `/api/remote-access/devices/${enc(id)}/regenerate`, opts);

// ---------------------------------------------------------------- unlock ---

export const getUnlock = () => request<UnlockView>("GET", "/api/unlock");
export const reportUnlock = (body: unknown) =>
  request<{ pending_apply: boolean; decisions: Record<string, string> }>("POST", "/api/unlock/report", body);
export const getUnlockCatalog = () => request<ProbeCatalogView>("GET", "/api/unlock/catalog");
export const runUnlock = (sel: ProbeSelection = {}) => request<{ job: ProbeJob }>("POST", "/api/unlock/run", sel);
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

// ------------------------------------------------------------------ leak ---

export const getLeakcheck = () => request<{ items: LeakItem[] }>("GET", "/api/leakcheck");
