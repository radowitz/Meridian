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

export function apply(dryRun: boolean, install: boolean) {
  return fetch("/api/apply", {
    method: "POST",
    headers: headers(true),
    body: JSON.stringify({ dry_run: dryRun, install }),
  }).then((r) =>
    parse<{ dry_run: boolean; install: boolean; wrote?: string[]; order: string[]; diff: string }>(r),
  );
}

export function rollback() {
  return fetch("/api/rollback", { method: "POST", headers: headers(true), body: "{}" }).then((r) =>
    parse<{ status: string }>(r),
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
  history: { at: string; kind: string; service: string; exit_id: string; ok: boolean; note?: string }[];
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

export function runUnlock() {
  return fetch("/api/unlock/run", { method: "POST", headers: headers(true), body: "{}" }).then((r) =>
    parse<Record<string, unknown>>(r),
  );
}

export interface LeakItem {
  id: string;
  status: string;
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
