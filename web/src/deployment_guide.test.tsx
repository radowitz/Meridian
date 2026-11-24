// The ordered deployment guide against the in-memory fake API. Each test
// renders the guide alone (not the whole app) and stays small: the web
// suite is slow on purpose-built machines too.

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App as AntApp } from "antd";
import { describe, expect, it } from "vitest";
import { DeploymentGuide } from "./DeploymentGuide";
import { fakeApi, phoneWidth, reply } from "./testing";
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
            steps: [step("twnat", { reason: "挂在中继出口 dc1 后面" }), step("dc1"), step("gw", { reason: "网关最后" })],
            skipped: [
              { node_id: "myext", node_name: "马来西亚", role: "exit", kind: "external", why: "外部 SOCKS 出口：面板不登录、不下发" },
              { node_id: "us", node_name: "美国", role: "exit", kind: "in_sync", why: "没有变化" },
            ],
          },
        }),
      "POST /api/deploy/runs": () => view(run([step("twnat", { current: true, can_preflight: true }), step("dc1"), step("gw")])),
    });
    show();
    const plan = await screen.findByTestId("deploy-plan");
    const rows = within(plan).getAllByRole("row").slice(1);
    expect(rows.map((r) => r.getAttribute("data-testid"))).toEqual(["plan-step-twnat", "plan-step-dc1", "plan-step-gw"]);
    expect(plan).toHaveTextContent("挂在中继出口 dc1 后面");
    expect(screen.queryByTestId("deploy-limits")).toBeNull();
    expect(screen.getByTestId("deploy-remote-access-note")).toHaveTextContent("远程接入");
    await userEvent.click(within(plan).getByText(/跳过的节点/));
    expect(await screen.findByTestId("deploy-skip-myext")).toHaveTextContent("不下发");
    await userEvent.click(screen.getByTestId("deploy-start"));
    await waitFor(() => expect(api.find("POST /api/deploy/runs")).toHaveLength(1));
    expect(api.find("POST /api/deploy/runs")[0].body).toEqual({ topology_version: "v1" });
    expect(await screen.findByTestId("deploy-run")).toBeInTheDocument();
  });

  it("confirms one node with exactly its reviewed preflight", async () => {
    const rec = {
      id: "pf-1",
      kind: "remote",
      node_id: "twnat",
      node_name: "twnat",
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
    const reviewing = run([step("twnat", { current: true, phase: "review", preflight_id: "pf-1", can_preflight: true, can_install: true, confirmation_valid: true }), step("gw")], {
      current: "twnat",
      preflight: rec as unknown as DeployRun["preflight"],
    });
    const api = fakeApi({
      "GET /api/deploy": () => view(reviewing),
      "POST /api/deploy/runs/:id/install": () =>
        view(run([step("twnat", { phase: "done", outcome: "installed", health: { source: "remote_script", committed: true, verify: "verified" } }), step("gw", { current: true, can_preflight: true })], { current: "gw" })),
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
    expect(api.find("POST /api/deploy/runs/deploy-1/install")[0].body).toEqual({ node_id: "twnat", preflight_id: "pf-1" });
    const health = await screen.findByTestId("deploy-health-twnat");
    expect(health).toHaveTextContent("端到端未验证");
  });

  it("stops at a failed node and offers only the re-check", async () => {
    fakeApi({
      "GET /api/deploy": () =>
        view(
          run([step("dc1", { phase: "failed", outcome: "compensated", current: true, can_preflight: true }), step("gw")], {
            state: "stopped",
            current: "dc1",
            stop_reason: "dc1：下发失败，已补偿（服务器回到这次下发之前）",
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

  it("does not claim a health check for adopted nodes when a run finishes", async () => {
    fakeApi({
      "GET /api/deploy": () =>
        view(
          run(
            [
              step("dc1", { phase: "done", outcome: "installed", completion: "installed", health: { source: "remote_script", committed: true, verify: "verified" } }),
              step("dc2", { phase: "done", outcome: "adopted", evidence: "host_record", completion: "adopted", health: { source: "host_record", committed: true } }),
              step("gw", { phase: "done", outcome: "installed", completion: "installed", health: { source: "gateway_transaction", committed: true } }),
            ],
            { state: "done" },
          ),
        ),
    });
    show();
    const done = await screen.findByTestId("deploy-done");
    expect(done).toHaveTextContent("2 个节点在这次运行中安装并通过健康检查");
    expect(done).not.toHaveTextContent("全部 3 个节点");
    expect(screen.getByTestId("deploy-done-adopted")).toHaveTextContent("未检查健康");
    expect(screen.getByTestId("deploy-done-adopted")).toHaveTextContent("dc2");
    expect(screen.getByTestId("deploy-phase-dc2")).toHaveTextContent("未重新检查健康");
    expect(screen.getByTestId("deploy-phase-dc1")).toHaveTextContent("健康检查通过");
    expect(screen.getByTestId("deploy-health-dc2")).toHaveTextContent("健康未重新检查");
  });

  it("keeps the full statement when every node was installed and checked", async () => {
    fakeApi({
      "GET /api/deploy": () =>
        view(run([step("dc1", { phase: "done", outcome: "installed", completion: "installed" }), step("gw", { phase: "done", outcome: "installed", completion: "installed" })], { state: "done" })),
    });
    show();
    expect(await screen.findByTestId("deploy-done")).toHaveTextContent("全部 2 个节点都在这次运行中安装：服务已启动、健康检查通过");
    expect(screen.queryByTestId("deploy-done-adopted")).toBeNull();
  });

  it("offers to skip a blocked node, names the nodes that will still wait, and posts the skip", async () => {
    const blocked = run(
      [
        step("dc2", { current: true, phase: "blocked", can_preflight: true, can_skip: true, skip_holds: ["hkb", "gw"], message: "预检有 1 个阻断项" }),
        step("jp-a"),
        step("hkb", { role: "hub" }),
        step("gw"),
      ],
      { current: "dc2" },
    );
    const api = fakeApi({
      "GET /api/deploy": () => view(blocked),
      "POST /api/deploy/runs/:id/skip": () =>
        view(
          run(
            [
              step("dc2", { phase: "blocked", skip: { kind: "blocked", reason: "预检阻断：连不上外部 SOCKS 出口", at: NOW }, can_unskip: true }),
              step("jp-a", { current: true, can_preflight: true }),
              step("hkb", { role: "hub", waiting_for: ["dc2"] }),
              step("gw", { waiting_for: ["dc2"] }),
            ],
            { current: "jp-a" },
          ),
        ),
    });
    show();
    const offer = await screen.findByTestId("deploy-skip-offer");
    expect(within(offer).getByTestId("deploy-skip-holds")).toHaveTextContent("hkb、gw");
    await userEvent.click(within(offer).getByTestId("deploy-skip"));
    const dialog = await screen.findByTestId("deploy-skip-confirm");
    expect(dialog).toHaveTextContent("保持「待处理」");
    expect(dialog).toHaveTextContent("会继续等待的节点：hkb、gw");
    const modal = dialog.closest<HTMLElement>(".ant-modal-confirm")!;
    await userEvent.click(within(modal).getByRole("button", { name: /跳过这一台/ }));
    await waitFor(() => expect(api.find("POST /api/deploy/runs/deploy-1/skip")).toHaveLength(1));
    expect(api.find("POST /api/deploy/runs/deploy-1/skip")[0].body).toEqual({ node_id: "dc2" });
    expect(await screen.findByTestId("deploy-skipped-dc2")).toHaveTextContent("连不上外部 SOCKS 出口");
    expect(screen.getByTestId("deploy-phase-dc2")).toHaveAttribute("data-skipped", "true");
    expect(screen.getByTestId("deploy-waiting-hkb")).toHaveTextContent("等 dc2");
    expect(screen.getByTestId("deploy-waiting-gw")).toHaveTextContent("等 dc2");
    expect(screen.getByTestId("deploy-phase-gw")).toHaveAttribute("data-waiting", "true");
  });

  it("does not offer a skip for an unknown outcome", async () => {
    fakeApi({
      "GET /api/deploy": () =>
        view(run([step("dc1", { phase: "unknown", outcome: "unknown", current: true, can_preflight: true }), step("gw")], { state: "stopped", current: "dc1", stop_reason: "dc1：结果不明" })),
    });
    show();
    expect(await screen.findByTestId("deploy-stopped")).toBeInTheDocument();
    expect(screen.queryByTestId("deploy-skip-offer")).toBeNull();
    expect(screen.queryByTestId("deploy-skip")).toBeNull();
  });

  it("ends partial with the skipped nodes listed, and returns to one", async () => {
    const api = fakeApi({
      "GET /api/deploy": () =>
        view(
          run(
            [
              step("dc2", { phase: "blocked", skip: { kind: "blocked", reason: "预检阻断：连不上外部 SOCKS 出口", at: NOW }, can_unskip: true }),
              step("jp-a", { phase: "done", outcome: "installed", completion: "installed" }),
              step("gw", { waiting_for: ["dc2"] }),
            ],
            {
              state: "partial",
              summary: {
                all_checked: false,
                installed: ["jp-a"],
                adopted: [],
                in_sync: [],
                skipped_nodes: [{ node_id: "dc2", node_name: "dc2", kind: "blocked", reason: "预检阻断：连不上外部 SOCKS 出口" }],
                waiting_nodes: [{ node_id: "gw", node_name: "gw", waits_for: ["dc2"] }],
                text: "没有全部完成",
              },
            },
          ),
        ),
      "POST /api/deploy/runs/:id/unskip": () => view(run([step("dc2", { current: true, can_preflight: true }), step("jp-a", { phase: "done", completion: "installed" }), step("gw")], { current: "dc2" })),
    });
    show();
    const partial = await screen.findByTestId("deploy-partial");
    expect(partial).toHaveTextContent("没有全部完成");
    expect(screen.getByTestId("deploy-partial-skipped")).toHaveTextContent("dc2（预检有阻断项）");
    expect(screen.getByTestId("deploy-partial-waiting")).toHaveTextContent("gw（等 dc2）");
    expect(screen.queryByTestId("deploy-done")).toBeNull();
    expect(screen.getByTestId("deploy-run-state")).toHaveAttribute("data-state", "partial");
    await userEvent.click(screen.getByTestId("deploy-unskip-dc2"));
    await waitFor(() => expect(api.find("POST /api/deploy/runs/deploy-1/unskip")).toHaveLength(1));
    expect(api.find("POST /api/deploy/runs/deploy-1/unskip")[0].body).toEqual({ node_id: "dc2" });
    expect(await screen.findByTestId("deploy-current")).toHaveTextContent("dc2");
  });

  it("at phone width: stacked cards with the skip offer, skipped and waiting rows", async () => {
    phoneWidth();
    fakeApi({
      "GET /api/deploy": () =>
        view(
          run(
            [
              step("dc2", { phase: "pending", outcome: "not_started", code: "unreachable", message: "无法连接 203.0.113.42:22：connection refused", skip: { kind: "unreachable", reason: "连不上或登录不了服务器（没有执行任何操作）：无法连接 203.0.113.42:22：connection refused".repeat(2), at: NOW }, can_unskip: true }),
              step("jp-a", { current: true, phase: "blocked", can_preflight: true, can_skip: true, skip_holds: ["hkb", "gw"] }),
              step("hkb", { role: "hub", node_name: "备用枢纽 · 一个比较长的节点名字用来测试换行", waiting_for: ["dc2"] }),
              step("gw", { waiting_for: ["dc2"] }),
            ],
            { current: "jp-a" },
          ),
        ),
    });
    show();
    const offer = await screen.findByTestId("deploy-skip-offer");
    const cards = [...document.querySelectorAll<HTMLElement>('li.data-card[data-testid^="deploy-step-"]')];
    expect(cards).toHaveLength(4);
    for (const c of cards) expect(c.closest(".data-table-wrap")).toHaveAttribute("data-stacked", "true");
    const run_ = screen.getByTestId("deploy-run");
    expect(run_.querySelector("table")).toBeNull();
    expect(within(cards[0]).getByTestId("deploy-unskip-dc2")).toBeInTheDocument();
    expect(within(cards[0]).getByTestId("deploy-skipped-dc2").style.overflowWrap).toBe("anywhere");
    expect(within(cards[2]).getByTestId("deploy-waiting-hkb")).toHaveTextContent("等 dc2");
    expect(offer.style.overflowWrap).toBe("anywhere");
    expect(within(offer).getByTestId("deploy-skip")).toBeEnabled();
  });
});
