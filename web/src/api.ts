import type { Issue, PathReport, Topology } from "./types";

async function parse<T>(res: Response): Promise<T> {
  const body = await res.json();
  if (!res.ok) {
    const message = body.error || `请求失败 ${res.status}`;
    const err = new Error(message) as Error & { issues?: Issue[]; body?: unknown };
    err.issues = body.issues;
    err.body = body;
    throw err;
  }
  return body as T;
}

export function getTopology() {
  return fetch("/api/topology").then((r) => parse<Topology>(r));
}

export function putTopology(topo: Topology, draft: boolean) {
  const url = draft ? "/api/topology?draft=1" : "/api/topology";
  return fetch(url, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(topo),
  }).then((r) =>
    parse<{ topology: Topology; issues: Issue[]; paths: PathReport[]; draft: boolean }>(r),
  );
}

export function validate(topo: Topology) {
  return fetch("/api/validate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(topo),
  }).then((r) => parse<{ issues: Issue[]; paths: PathReport[] }>(r));
}

export function diff(topo: Topology) {
  return fetch("/api/diff", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(topo),
  }).then((r) => parse<{ diff: string; order: string[]; issues: Issue[] }>(r));
}

export function apply(dryRun: boolean, install: boolean) {
  return fetch("/api/apply", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ dry_run: dryRun, install }),
  }).then((r) =>
    parse<{ dry_run: boolean; install: boolean; wrote?: string[]; order: string[]; diff: string }>(r),
  );
}

export function rollback() {
  return fetch("/api/rollback", { method: "POST", body: "{}" }).then((r) => parse<{ status: string }>(r));
}

export function provision(nodeId: string) {
  return fetch("/api/provision", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ node_id: nodeId, dry_run: true }),
  }).then((r) => parse<{ dry_run: boolean; script: string; node_id: string }>(r));
}
