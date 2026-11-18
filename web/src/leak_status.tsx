// 防泄露 as one line for the overview: "防泄露 正常" or "防泄露 异常（原因）".
// Clicking opens the existing leak-check items (GET /api/leakcheck) in a
// drawer. The panel only reads compiled configuration here; nothing in it
// proves the absence of a leak.

import { Drawer } from "antd";
import { useState } from "react";
import * as api from "./api";
import { useStatus } from "./state";
import type { LeakItem } from "./types";
import { StatusTag, useApi, type StatusKind } from "./ui";

/**
 * Status per scope. Only the automated group can show a "configuration
 * contains" result; integration and human items never render as passed.
 */
export function leakStatus(it: LeakItem): { kind: StatusKind; label: string } {
  const scope = it.scope || "automated";
  if (scope === "integration") return { kind: "neutral", label: "未执行" };
  if (scope === "human") return { kind: "signoff", label: "待人工签收" };
  if (scope === "limitation") return { kind: "attention", label: "已知限制" };
  switch (it.status) {
    case "pass":
      return { kind: "unverified", label: "配置包含" };
    case "fail":
      return { kind: "failed", label: "配置缺失" };
    case "skip":
      return { kind: "neutral", label: "不适用" };
    case "known_limitation":
      return { kind: "attention", label: "已知限制" };
    default:
      return { kind: "neutral", label: "未执行" };
  }
}

/** The overall state: failing automated items make it 异常 with their titles as the reason. */
export function useLeakStatus() {
  const { install } = useStatus();
  const state = useApi(() => api.getLeakcheck(), [install.kind]);
  const items = state.data?.items ?? [];
  const failed = items.filter((it) => (it.scope || "automated") === "automated" && it.status === "fail");
  return { state, items, ok: !!state.data && failed.length === 0, reason: failed.map((f) => f.title).join("、") };
}

/** Endpoint-access policy (LAN → tunnel endpoints), one line; absent field → nothing. */
function EndpointAccessLine({ leak }: { leak?: unknown }) {
  const { status } = useStatus();
  const pick = (o: unknown) => (o && typeof o === "object" ? (o as Record<string, unknown>).endpoint_access : undefined);
  const v = pick(leak) ?? pick(status);
  const text = endpointAccessText(v);
  if (!text) return null;
  return (
    <p className="endpoint-access" data-testid="leak-endpoint-access" title={endpointAccessTitle(v)}>
      局域网到隧道端点：{text}
    </p>
  );
}

export function LeakStatusLine() {
  const { state, items, ok, reason } = useLeakStatus();
  const [open, setOpen] = useState(false);
  if (!state.data) return null;
  return (
    <>
      <button type="button" className="ov-fact leak-status-line" data-testid="leak-status-line" data-ok={ok} onClick={() => setOpen(true)}>
        <span className="ov-label">防泄露</span> <StatusTag kind={ok ? "ok" : "failed"}>{ok ? "正常" : `异常（${reason}）`}</StatusTag>
      </button>
      <Drawer open={open} onClose={() => setOpen(false)} title="防泄露" width={480} destroyOnHidden>
        <EndpointAccessLine leak={state.data} />
        <ul className="leak-status-list" data-testid="leak-status-items">
          {items.map((it) => {
            const s = leakStatus(it);
            return (
              <li key={it.id} data-testid={`leak-item-${it.id}`}>
                <StatusTag kind={s.kind}>{s.label}</StatusTag> {it.title}
                {it.detail ? <div className="muted">{it.detail}</div> : null}
              </li>
            );
          })}
        </ul>
      </Drawer>
    </>
  );
}

/** Blocked endpoints' reasons ({items[]} shape), for a title; undefined when none. */
export function endpointAccessTitle(v: unknown): string | undefined {
  if (!v || typeof v !== "object") return undefined;
  const items = (v as Record<string, unknown>).items;
  if (!Array.isArray(items)) return undefined;
  const lines = items
    .filter((i) => i && typeof i === "object" && (i as Record<string, unknown>).class === "blocked")
    .map((i) => {
      const r = i as Record<string, unknown>;
      return `${r.node_name || r.node_id || ""} ${r.addr ?? ""}：${r.reason ?? ""}`.trim();
    });
  return lines.length ? lines.join("\n") : undefined;
}

/** Accepts a string, {summary}, {direct,tunnel,blocked,items} or {domestic,overseas}; anything else → null. */
export function endpointAccessText(v: unknown): string | null {
  if (typeof v === "string") return v.trim() || null;
  if (v && typeof v === "object") {
    const o = v as Record<string, unknown>;
    if (typeof o.summary === "string" && o.summary) return o.summary;
    if (typeof o.direct === "number" && typeof o.tunnel === "number") {
      const blocked = typeof o.blocked === "number" ? o.blocked : 0;
      if (o.direct + o.tunnel + blocked === 0) return null;
      return `国内直连 ${o.direct} · 境外经默认出口 ${o.tunnel}` + (blocked > 0 ? ` · 拦截 ${blocked}` : "");
    }
    if (o.domestic != null || o.overseas != null) return "国内直连 · 境外经默认出口";
  }
  return null;
}
