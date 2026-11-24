// The gateway install after a relay's links were deleted (and an earlier
// relay provisioning was compensated): synthetic responses modelled on that
// scenario. The deploy page must render every step without throwing.

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { fakeApi, panelStatus, renderAt } from "./testing";
import { CLEAN, OK_AGENT, confirmModal, exitNode, topology } from "./pages_fixtures";
import type { PreflightRecord } from "./types";
import { ErrorBoundary } from "./ErrorBoundary";
import { PreflightReport, normalizePreflight } from "./Preflight";

const REMOVED = [
  "/etc/meridian/wss/client-gw-relay.env",
  "/etc/meridian/wss/client-gw-relay.trust.pem",
  "/etc/systemd/system/wstunnel-client-gw-relay.service",
  "/etc/wireguard/m22.conf",
  "/etc/wireguard/m22w.conf",
];

function gatewayRec(over: Partial<PreflightRecord> = {}): PreflightRecord {
  return CLEAN({
    id: "pf-gw",
    kind: "gateway",
    node_id: "gw",
    node_name: "网关",
    role: "gateway",
    target: undefined,
    first_install: false,
    ownership: "same",
    findings: [
      { severity: "warning", code: "previous_run_leftovers", resource: "relay", message: "上一次下发留下了没有撤掉的东西。" },
      { severity: "info", code: "host_summary", message: "主机：Debian 13。" },
    ],
    counts: { blocking: 0, warning: 1, info: 1 },
    changes: [
      { kind: "file", action: "change", resource: "/etc/meridian/link-journal.json" },
      ...REMOVED.map((p) => ({ kind: "file", action: "remove", resource: p })),
      { kind: "unit", action: "remove", resource: "wstunnel-client-gw-relay.service" },
    ],
    file_changes: {
      basis: "installed_manifest",
      added: [],
      changed: ["/etc/meridian/link-journal.json"],
      removed: REMOVED,
      unchanged: ["/etc/meridian/meridian.nft"],
      not_compared: [],
      summary: "文件：1 个内容变化、5 个不再生成；1 个与已安装的内容相同。",
    },
    ...over,
  });
}

function scenario(rec: () => unknown) {
  return fakeApi({
    "GET /api/topology": () => ({
      topology: topology({
        nodes: [exitNode("gw", "网关", { role: "gateway", region: "cn" }), exitNode("ix", "IX", { role: "hub" }), exitNode("relay", "中继", { role: "relay" })],
        links: [],
      }),
      version: "v1",
    }),
    "GET /api/status": () =>
      panelStatus({
        ...OK_AGENT,
        installOver: { state: "changed", installed_version: 3, applied: true, applied_matches: false },
        nodes: [
          { node_id: "gw", node_name: "网关", role: "gateway", state: "changed", pending: true },
          { node_id: "ix", node_name: "IX", role: "hub", state: "changed", pending: true },
          { node_id: "relay", node_name: "中继", role: "relay", state: "not_installed", pending: true },
        ],
      }),
    "GET /api/host": () => ({
      installed: { version: 3, files: 10, interfaces: ["m22"], units: ["meridian.service"], nft_tables: ["inet meridian"], route_tables: [100], dns: true },
      pending: null,
      agent: { ok: true },
    }),
    "POST /api/host/preflight": () => ({ preflight: rec() }),
    "POST /api/apply": () => ({ dry_run: false, install: true, order: [], diff: "", host: { transaction: "t", committed: true, steps: [] } }),
  });
}

async function preflightAndInstall() {
  renderAt("#/deploy", { foldsOpen: true });
  await userEvent.click(await screen.findByTestId("host-preflight-run"));
  return screen.findByTestId("host-preflight");
}

describe("gateway install after a relay's links were deleted", () => {
  it("shows the preflight with removed files and the leftovers warning, and installs", async () => {
    const api = scenario(() => gatewayRec());
    const report = await preflightAndInstall();
    expect(report).toHaveTextContent("5 个不再生成");
    expect(report.querySelector('[data-code="previous_run_leftovers"]')).not.toBeNull();
    await waitFor(() => expect(screen.getByRole("button", { name: /安装到网关/ })).toBeEnabled());
    await userEvent.click(screen.getByRole("button", { name: /安装到网关/ }));
    await confirmModal("安装");
    await waitFor(() => expect(api.find("POST /api/apply")).toHaveLength(1));
    expect(await screen.findByTestId("txn-result")).toBeInTheDocument();
  });
});

describe("lists missing from a preflight answer", () => {
  // Before the fix each of these threw while rendering (TypeError: ... reading
  // 'length' / 'map' / 'join', "rec.changes is not iterable") and the deploy
  // page was replaced by the error page.
  const holes: [string, (r: Record<string, unknown>) => void][] = [
    ["file_changes.not_compared", (r) => ((r.file_changes as Record<string, unknown>).not_compared = null)],
    ["file_changes.removed", (r) => delete (r.file_changes as Record<string, unknown>).removed],
    ["changes", (r) => (r.changes = null)],
    ["findings", (r) => (r.findings = null)],
    ["not_checked", (r) => delete r.not_checked],
    ["footprint.listens", (r) => ((r.footprint as Record<string, unknown>).listens = null)],
    ["counts", (r) => delete r.counts],
  ];
  for (const [name, hole] of holes) {
    it(`renders the report without ${name}`, () => {
      const r = JSON.parse(JSON.stringify(gatewayRec())) as Record<string, unknown>;
      hole(r);
      render(<PreflightReport rec={r as unknown as PreflightRecord} />);
      expect(screen.getByTestId("preflight-report")).toBeInTheDocument();
    });
  }

  it("derives the counts from the findings when they are missing", () => {
    const r = JSON.parse(JSON.stringify(gatewayRec())) as Record<string, unknown>;
    delete r.counts;
    expect(normalizePreflight(r as unknown as PreflightRecord).counts).toEqual({ blocking: 0, warning: 1, info: 1 });
  });

  it("the gateway preflight with a null list shows on the deploy page and install stays possible", async () => {
    scenario(() => {
      const r = JSON.parse(JSON.stringify(gatewayRec())) as Record<string, unknown>;
      (r.file_changes as Record<string, unknown>).not_compared = null;
      r.changes = null;
      return r;
    });
    const report = await preflightAndInstall();
    expect(report).toHaveTextContent("5 个不再生成");
    expect(screen.queryByText("这个页面出错了")).toBeNull();
    await waitFor(() => expect(screen.getByRole("button", { name: /安装到网关/ })).toBeEnabled());
  });
});

describe("region error boundary", () => {
  it("shows one line with the error and retries", async () => {
    let fail = true;
    function Maybe() {
      if (fail) throw new Error("坏数据");
      return <span>好了</span>;
    }
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    render(
      <div>
        <ErrorBoundary>
          <Maybe />
        </ErrorBoundary>
        <span>旁边的内容</span>
      </div>,
    );
    const line = screen.getByTestId("region-error");
    expect(line).toHaveTextContent("这部分出错了");
    expect(line).toHaveTextContent("坏数据");
    expect(screen.getByText("旁边的内容")).toBeInTheDocument();
    fail = false;
    await userEvent.click(within(line).getByRole("button", { name: /重\s*试/ }));
    expect(screen.getByText("好了")).toBeInTheDocument();
    spy.mockRestore();
  });

  it("a region that throws on the deploy page leaves the navigation and the other regions working", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const api = scenario(() => gatewayRec());
    // A WSS answer with a listener missing its lists: the WSS card throws.
    api.on("GET /api/wss", () => ({ listeners: [{ node_id: "relay", server_name: "relay" }], validity_days: 365, rotate_before: 30, verification: "", interruption: "", order: "" }));
    renderAt("#/deploy", { foldsOpen: true });
    const line = await screen.findByTestId("region-error");
    expect(line).toHaveTextContent("这部分出错了");
    expect(screen.queryByText("这个页面出错了")).toBeNull();
    expect(screen.getByTestId("host-preflight-run")).toBeInTheDocument();
    expect(screen.getAllByRole("menuitem").length).toBeGreaterThan(0);
    spy.mockRestore();
  });
});
