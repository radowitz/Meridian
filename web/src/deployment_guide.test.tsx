// The ordered deployment guide against the in-memory fake API. Each test
// renders the guide alone (not the whole app) and stays small: the web
// suite is slow on purpose-built machines too.

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App as AntApp } from "antd";
import { describe, expect, it } from "vitest";
import { DeploymentGuide } from "./DeploymentGuide";
import { fakeApi, reply } from "./testing";
import type { DeployRun, DeployStep, DeployView } from "./types";

const NOW = "2026-11-14T10:00:00Z";
const LIMITS = {
  proves: ["网关：安装事务已提交，健康检查通过"],
  does_not_prove: ["隧道真的握手、流量真的经出口出去（端到端连通）"],
  independent: ["远程接入（开关与设备）是独立资源：保存拓扑、本引导的任何一步都不会打开、关闭或修改它"],
};

function step(id: string, over: Partial<DeployStep> = {}): DeployStep {
  return {
    node_id: id,
    node_name: id,
    role: id === "gw" ? "gateway" : "exit",
    kind: id === "gw" ? "gateway" : "remote",
    reason: id === "gw" ? "网关最后" : "出口：先于枢纽",
    plan_state: "changed",
    phase: "pending",
    attempts: 0,
    position: 1,
    current: false,
    in_flight: false,
    confirmation_valid: false,
    can_preflight: false,
    can_install: false,
    ...over,
  };
}

function run(steps: DeployStep[], over: Partial<DeployRun> = {}): DeployRun {
  return {
    id: "deploy-1",
    state: "active",
    created_at: NOW,
    updated_at: NOW,
    topology_version: "v1",
    steps: steps.map((s, i) => ({ ...s, position: i + 1 })),
    skipped: [],
    stale: false,
    ...over,
  };
}

function view(r: DeployRun | null, over: Partial<DeployView> = {}): DeployView {
  return { limits: LIMITS, run: r, plan: { topology_version: "v1", steps: [], skipped: [] }, topology_version: "v1", ...over };
}

function show() {
  return render(
    <AntApp>
      <DeploymentGuide />
    </AntApp>,
  );
}

describe("deployment guide", () => {
  it("shows the plan with reasons and skipped nodes, and starts the plan that was shown", async () => {
    const api = fakeApi({
      "GET /api/deploy": () =>
        view(null, {
          plan: {
            topology_version: "v1",
            steps: [step("tw2", { reason: "挂在中继出口 dc1 后面" }), step("dc1"), step("gw", { reason: "网关最后" })],
            skipped: [
              { node_id: "my1", node_name: "马来西亚", role: "exit", kind: "external", why: "外部 SOCKS 出口：面板不登录、不装机" },
              { node_id: "us", node_name: "美国", role: "exit", kind: "in_sync", why: "没有变化" },
            ],
          },
        }),
      "POST /api/deploy/runs": () => view(run([step("tw2", { current: true, can_preflight: true }), step("dc1"), step("gw")])),
    });
    show();
    const plan = await screen.findByTestId("deploy-plan");
    const rows = within(plan).getAllByRole("row").slice(1);
    expect(rows.map((r) => r.getAttribute("data-testid"))).toEqual(["plan-step-tw2", "plan-step-dc1", "plan-step-gw"]);
    expect(plan).toHaveTextContent("挂在中继出口 dc1 后面");
    expect(screen.getByTestId("deploy-limits")).toHaveTextContent("不是端到端验证");
    expect(screen.getByTestId("deploy-remote-access-note")).toHaveTextContent("远程接入");
    await userEvent.click(within(plan).getByText(/跳过的节点/));
    expect(await screen.findByTestId("deploy-skip-my1")).toHaveTextContent("不装机");
    await userEvent.click(screen.getByTestId("deploy-start"));
    await waitFor(() => expect(api.find("POST /api/deploy/runs")).toHaveLength(1));
    expect(api.find("POST /api/deploy/runs")[0].body).toEqual({ topology_version: "v1" });
    expect(await screen.findByTestId("deploy-run")).toBeInTheDocument();
  });

  it("confirms one node with exactly its reviewed preflight", async () => {
    const rec = {
      id: "pf-1",
      kind: "remote",
      node_id: "tw2",
      node_name: "tw2",
      role: "exit",
      deployment: "dep",
      bundle: "b".repeat(64),
      first_install: true,
      at: NOW,
      expires_at: "2999-01-01T00:00:00Z",
      host: { mem_total_kb: 1, mem_avail_kb: 1, complete: true },
      footprint: { files: [], interfaces: [], listens: [], route_tables: [], nft_tables: [], units: [], packages: [], binaries: [] },
      not_checked: [],
      ownership: "none",
      blocking: false,
      findings: [],
      changes: [{ kind: "file", action: "create", resource: "/etc/wireguard/m01.conf" }],
      counts: { blocking: 0, warning: 0, info: 0 },
    };
    const reviewing = run([step("tw2", { current: true, phase: "review", preflight_id: "pf-1", can_preflight: true, can_install: true, confirmation_valid: true }), step("gw")], {
      current: "tw2",
      preflight: rec as unknown as DeployRun["preflight"],
    });
    const api = fakeApi({
      "GET /api/deploy": () => view(reviewing),
      "POST /api/deploy/runs/:id/install": () =>
        view(run([step("tw2", { phase: "done", outcome: "installed", health: { source: "remote_script", committed: true, verify: "verified" } }), step("gw", { current: true, can_preflight: true })], { current: "gw" })),
    });
    show();
    expect(await screen.findByTestId("deploy-review")).toBeInTheDocument();
    await userEvent.click(screen.getByTestId("deploy-install"));
    const dialog = await waitFor(() => {
      const el = document.querySelector<HTMLElement>(".ant-modal-confirm");
      if (!el) throw new Error("no confirm dialog");
      return el;
    });
    expect(dialog).toHaveTextContent("只确认这一台");
    await userEvent.click(within(dialog).getByRole("button", { name: /^确\s*认$/ }));
    await waitFor(() => expect(api.find("POST /api/deploy/runs/deploy-1/install")).toHaveLength(1));
    expect(api.find("POST /api/deploy/runs/deploy-1/install")[0].body).toEqual({ node_id: "tw2", preflight_id: "pf-1" });
    const health = await screen.findByTestId("deploy-health-tw2");
    expect(health).toHaveTextContent("端到端未验证");
  });

  it("stops at a failed node and offers only the re-check", async () => {
    fakeApi({
      "GET /api/deploy": () =>
        view(
          run([step("dc1", { phase: "failed", outcome: "compensated", current: true, can_preflight: true }), step("gw")], {
            state: "stopped",
            current: "dc1",
            stop_reason: "dc1：装机失败，已补偿（服务器回到这次下发之前）",
          }),
        ),
    });
    show();
    expect(await screen.findByTestId("deploy-stopped")).toHaveTextContent("已补偿");
    expect(screen.getByTestId("deploy-phase-dc1")).toHaveAttribute("data-phase", "failed");
    expect(screen.getByTestId("deploy-preflight")).toHaveTextContent("重新核对");
    expect(screen.getByTestId("deploy-retry-note")).toHaveTextContent("不会重做");
    expect(screen.queryByTestId("deploy-install")).toBeNull();
  });

  it("says why a plan is stale and re-plans on request", async () => {
    const api = fakeApi({
      "GET /api/deploy": () =>
        view(run([step("dc1", { current: true })], { stale: true, stale_reason: "计划之后拓扑被保存过", affected: ["dc1"], current: "dc1" })),
      "POST /api/deploy/runs/:id/replan": () => view(run([step("dc1", { current: true, can_preflight: true, invalidated: "重新计划时发现预检之后这个节点要下发的内容变了：预检作废" })], { current: "dc1" })),
    });
    show();
    const stale = await screen.findByTestId("deploy-stale");
    expect(stale).toHaveTextContent("受影响的节点：dc1");
    expect(screen.getByTestId("deploy-preflight")).toBeDisabled();
    await userEvent.click(within(stale).getByTestId("deploy-replan"));
    await waitFor(() => expect(api.find("POST /api/deploy/runs/deploy-1/replan")).toHaveLength(1));
    expect(await screen.findByTestId("deploy-invalidated")).toHaveTextContent("预检作废");
  });

  it("waits out a server's rate limit instead of retrying", async () => {
    const api = fakeApi({
      "GET /api/deploy": () =>
        view(run([step("dc1", { current: true, code: "ssh_rate_limited", outcome: "not_started", not_executed: true, wait_seconds: 45, retry_at: "2999-01-01T00:00:00Z" })], { current: "dc1" })),
      "POST /api/deploy/runs/:id/preflight": () => reply(409, { code: "deploy_wait", error: "限速", retry_after: 45 }),
    });
    show();
    expect(await screen.findByTestId("deploy-wait")).toHaveTextContent("秒后可以重试");
    expect(screen.getByTestId("deploy-preflight")).toBeDisabled();
    expect(api.find("POST /api/deploy/runs/deploy-1/preflight")).toHaveLength(0);
  });
});
