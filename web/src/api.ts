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

export function provision(nodeId: string) {
  return fetch("/api/provision", {
    method: "POST",
    headers: headers(true),
    body: JSON.stringify({ node_id: nodeId, dry_run: true }),
  }).then((r) => parse<{ dry_run: boolean; script: string; node_id: string }>(r));
}
