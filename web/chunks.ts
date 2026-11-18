// The production build's chunking rule (used by vite.config.ts; see
// web/README.md「首屏与拆包」). Third-party code is placed by where the
// module graph reaches it from — not by a hand-kept list of packages or
// antd components:
//
// - vendor-react: React, ReactDOM and the scheduler. Changes only with a
//   React upgrade, so it stays cached across panel deployments.
// - vendor-shell: every other package module the entry reaches through
//   static imports (main.tsx → App → shell, login gate, ui_base.tsx). It is
//   needed before the first paint.
// - vendor-pages: package modules reached only through lazy pages, by at
//   least SHARED_BY of them (tables, selects, dialogs, form widgets …).
//   Loaded with the first page that needs them, then cached.
// - anything else (used by one or two pages, e.g. the topology graph
//   library) is left to Rollup and travels with those pages.
//
// "Reaches" follows what a module really imports: `import { Button } from
// "antd"` reaches antd's button module, not every component antd's index
// re-exports (otherwise the entry would "reach" all of antd through that
// index and nothing could be split). Application code is left to Rollup's
// own splitting; CSS is never moved by this rule.

import type { GetModuleInfo, ModuleInfo } from "rollup";

/** A package module reached by this many lazy pages or more goes to vendor-pages. */
export const SHARED_BY = 3;

const REACT = /\/node_modules\/(react|react-dom|scheduler)\//;

type Meta = { getModuleInfo: GetModuleInfo; getModuleIds: () => IterableIterator<string> };

let plan: { ids: Set<string>; placement: Map<string, string> } | null = null;

export function vendorChunk(id: string, meta: Meta): string | undefined {
  if (!id.includes("/node_modules/") || !/\.[cm]?[jt]sx?$/.test(id)) return undefined;
  if (REACT.test(id)) return "vendor-react";
  // One plan per build (the module set identifies the build in watch mode).
  if (!plan || !plan.ids.has(id)) plan = makePlan(meta);
  return plan.placement.get(id);
}

function makePlan({ getModuleInfo, getModuleIds }: Meta) {
  const ids = new Set(getModuleIds());
  const deps = new Map<string, string[]>();
  const depsOf = (id: string) => {
    let d = deps.get(id);
    if (!d) deps.set(id, (d = effectiveDeps(id, getModuleInfo)));
    return d;
  };
  const closure = (root: string) => {
    const seen = new Set<string>();
    const stack = [root];
    while (stack.length > 0) {
      const cur = stack.pop()!;
      if (seen.has(cur)) continue;
      seen.add(cur);
      stack.push(...depsOf(cur));
    }
    return seen;
  };
  const shell = new Set<string>();
  const pages = new Map<string, number>();
  for (const id of ids) {
    const info = getModuleInfo(id);
    if (info?.isEntry) for (const m of closure(id)) shell.add(m);
  }
  for (const id of ids) {
    const info = getModuleInfo(id);
    if (!info || info.dynamicImporters.length === 0) continue;
    for (const m of closure(id)) pages.set(m, (pages.get(m) ?? 0) + 1);
  }
  const placement = new Map<string, string>();
  for (const id of ids) {
    if (!id.includes("/node_modules/") || REACT.test(id)) continue;
    if (shell.has(id)) placement.set(id, "vendor-shell");
    else if ((pages.get(id) ?? 0) >= SHARED_BY) placement.set(id, "vendor-pages");
  }
  return { ids, placement };
}

// ------------------------------------------------- what a module imports ---

type Node = { type: string; source?: { value?: unknown } | null; [k: string]: unknown };
type Spec = { type: string; imported?: { name?: string; value?: string }; local?: { name?: string }; exported?: { name?: string; value?: string } };
type Body = Node[];

const nameOf = (n: { name?: string; value?: string } | undefined) => n?.name ?? n?.value ?? "";
const isFrom = (n: Node) => (n.type === "ImportDeclaration" || n.type === "ExportNamedDeclaration" || n.type === "ExportAllDeclaration") && typeof n.source?.value === "string";
const bodyOf = (info: ModuleInfo | null) => (info?.ast as unknown as { body: Body } | null)?.body ?? null;

/**
 * Lines a module's import / export-from declarations up with Rollup's
 * resolved ids (Rollup lists importedIds in order of each source's first
 * appearance). Null when they do not line up; callers then keep everything.
 */
function resolver(info: ModuleInfo, body: Body): ((n: Node) => string) | null {
  const order: string[] = [];
  for (const n of body) if (isFrom(n) && !order.includes(n.source!.value as string)) order.push(n.source!.value as string);
  if (order.length !== info.importedIds.length) return null;
  return (n) => info.importedIds[order.indexOf(n.source!.value as string)];
}

/**
 * The static dependencies of a module, with named imports followed through
 * re-exports to the module that defines the name. A namespace import, a
 * bare `import "x"` or an `export * from "x"` keeps the whole module.
 */
function effectiveDeps(id: string, getModuleInfo: GetModuleInfo): string[] {
  const info = getModuleInfo(id);
  const body = bodyOf(info);
  const target = info && body ? resolver(info, body) : null;
  if (!info || !body || !target) return info ? [...info.importedIds] : [];
  const out = new Set<string>();
  for (const n of body) {
    if (!isFrom(n)) continue;
    const t = target(n);
    const specs = (n.specifiers as Spec[] | undefined) ?? [];
    let names: string[] | null;
    if (n.type === "ExportAllDeclaration") names = null;
    else if (n.type === "ExportNamedDeclaration") names = specs.map((s) => nameOf(s.local));
    else if (specs.length === 0 || specs.some((s) => s.type === "ImportNamespaceSpecifier")) names = null;
    else names = specs.map((s) => (s.type === "ImportDefaultSpecifier" ? "default" : nameOf(s.imported)));
    if (names === null) out.add(t);
    else for (const name of names) for (const m of definingModules(t, name, getModuleInfo, new Set()) ?? [t]) out.add(m);
  }
  return [...out];
}

/**
 * The module that defines `name` as exported by `id`, following re-exports
 * (`export { default as Button } from "./button"`, `export * from "./icons"`).
 * Null when `id` does not export the name.
 */
function definingModules(id: string, name: string, getModuleInfo: GetModuleInfo, seen: Set<string>): string[] | null {
  if (seen.has(id)) return null;
  seen.add(id);
  const info = getModuleInfo(id);
  const body = bodyOf(info);
  const target = info && body ? resolver(info, body) : null;
  if (!info || !body || !target) return [id];
  for (const n of body) {
    if (n.type !== "ExportNamedDeclaration" || !isFrom(n)) continue;
    for (const s of (n.specifiers as Spec[]) ?? []) {
      if (nameOf(s.exported) === name) return definingModules(target(n), nameOf(s.local), getModuleInfo, seen) ?? [target(n)];
    }
  }
  if (declaresLocally(body, name)) return [id];
  for (const n of body) {
    if (n.type !== "ExportAllDeclaration" || !isFrom(n) || n.exported) continue;
    const hit = definingModules(target(n), name, getModuleInfo, seen);
    if (hit) return hit;
  }
  return null;
}

/** Whether the module itself declares the export `name` (not by re-exporting it). */
function declaresLocally(body: Body, name: string): boolean {
  for (const n of body) {
    if (n.type === "ExportDefaultDeclaration" && name === "default") return true;
    if (n.type !== "ExportNamedDeclaration" || isFrom(n)) continue;
    const decl = n.declaration as { id?: { name?: string }; declarations?: { id?: { name?: string } }[] } | null;
    if (decl?.id?.name === name) return true;
    if (decl?.declarations?.some((d) => d.id?.name === name)) return true;
    if (((n.specifiers as Spec[]) ?? []).some((s) => nameOf(s.exported) === name)) return true;
  }
  return false;
}
