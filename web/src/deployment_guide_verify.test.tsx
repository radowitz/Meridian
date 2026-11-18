// Verify-only steps of the deployment guide: their own group, outside the
// install order, with per-row and "verify all" actions and clear states.
// Small renders on purpose (web/README.md「前端测试耗时」).

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App as AntApp } from "antd";
import { describe, expect, it, vi } from "vitest";
import { VerifyGroup } from "./DeployVerifyGroup";
import { DeploymentGuide } from "./DeploymentGuide";
import { fakeApi } from "./testing";
import type { DeployRun, DeployStep, DeployView } from "./types";

const NOW = "2026-11-14T10:00:00Z";

function step(id: string, over: Partial<DeployStep> = {}): DeployStep {
  return {
    node_id: id,
    node_name: id,
    role: id === "gw" ? "gateway" : "exit",
    kind: id === "gw" ? "gateway" : "remote",
    reason: id === "gw" ? "网关最后" : "只需核对：面板的记录已与这份内容一致",
    plan_state: id === "gw" ? "changed" : "in_sync",
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

const verified = step("jp-a", {
  verify_only: true,
  phase: "done",
  completion: "adopted",
  verify_state: "verified",
  health: { source: "host_record", committed: true, detail: "服务器上的安装记录已经是这份内容" },
});
const unreachable = step("dc1", {
  verify_only: true,
  verify_state: "unreachable",
  outcome: "not_started",
  not_executed: true,
  code: "unreachable",
  message: "无法连接 203.0.113.41:22：connection refused",
  path_note: "这个地址依赖主链路，而网关现在经备用枢纽承载：主链路可能不通。面板不会自动改走其它管理通道。",
  can_verify: true,
});
const waiting = step("sg1", { verify_only: true, verify_state: "waiting", outcome: "not_started", code: "ssh_rate_limited", wait_seconds: 42 });
const pending = step("us2", { verify_only: true, verify_state: "pending", can_verify: true });

describe("deployment guide: verify-only steps", () => {
  it("shows each state, one alert, and verifies one row or all", async () => {
    const onVerify = vi.fn();
    const onVerifyAll = vi.fn();
    render(<VerifyGroup steps={[verified, unreachable, waiting, pending]} busy={false} onVerify={onVerify} onVerifyAll={onVerifyAll} />);
    const group = screen.getByTestId("deploy-verify-group");
    expect(within(group).getByTestId("deploy-verify-state-jp-a")).toHaveAttribute("data-verify", "verified");
    expect(within(group).getByTestId("deploy-verify-state-jp-a")).toHaveTextContent("未重新检查健康");
    expect(within(group).getByTestId("deploy-verify-state-dc1")).toHaveAttribute("data-verify", "unreachable");
    expect(within(group).getByTestId("deploy-verify-dc1")).toHaveTextContent("connection refused");
    expect(within(group).getByTestId("verify-path-note-dc1")).toHaveTextContent("网关现在经备用枢纽承载");
    expect(within(group).getByTestId("deploy-verify-state-sg1")).toHaveAttribute("data-verify", "waiting");
    expect(within(group).getByTestId("verify-wait-left")).toHaveTextContent("面板不会连接这台服务器");
    // One alert for the whole group.
    expect(within(group).getAllByRole("alert")).toHaveLength(1);
    expect(within(group).getByTestId("deploy-verify-alert")).toHaveTextContent("1 台连不上、1 台在限速等待");
    // A done step has no action; a waiting one cannot be verified now.
    expect(within(group).queryByTestId("deploy-verify-one-jp-a")).toBeNull();
    expect(within(group).getByTestId("deploy-verify-one-sg1")).toBeDisabled();
    await userEvent.click(within(group).getByTestId("deploy-verify-one-us2"));
    expect(onVerify).toHaveBeenCalledWith(expect.objectContaining({ node_id: "us2" }));
    await userEvent.click(within(group).getByTestId("deploy-verify-all"));
    expect(onVerifyAll).toHaveBeenCalledTimes(1);
  });

  it("is disabled while the run cannot act", () => {
    render(<VerifyGroup steps={[pending]} busy={false} disabled onVerify={() => undefined} onVerifyAll={() => undefined} />);
    expect(screen.getByTestId("deploy-verify-all")).toBeDisabled();
    expect(screen.getByTestId("deploy-verify-one-us2")).toBeDisabled();
  });

  it("keeps verify-only steps out of the ordered table and sends the batch", async () => {
    const r: DeployRun = {
      id: "deploy-1",
      state: "active",
      created_at: NOW,
      updated_at: NOW,
      topology_version: "v1",
      steps: [step("gw", { current: true, can_preflight: true, position: 1 }), { ...pending, position: 2 }, { ...unreachable, position: 3 }],
      skipped: [],
      stale: false,
      current: "gw",
    };
    const view: DeployView = { limits: { proves: [], does_not_prove: [], independent: ["x"] }, run: r, topology_version: "v1" };
    const api = fakeApi({ "GET /api/deploy": () => view, "POST /api/deploy/runs/:id/verify": () => view });
    render(
      <AntApp>
        <DeploymentGuide />
      </AntApp>,
    );
    const runView = await screen.findByTestId("deploy-run");
    expect(within(runView).getByTestId("deploy-step-gw")).toBeInTheDocument();
    expect(within(runView).queryByTestId("deploy-step-us2")).toBeNull();
    expect(within(screen.getByTestId("deploy-verify-group")).getByTestId("deploy-verify-us2")).toBeInTheDocument();
    await userEvent.click(screen.getByTestId("deploy-verify-all"));
    await waitFor(() => expect(api.find("POST /api/deploy/runs/deploy-1/verify")).toHaveLength(1));
    expect(api.find("POST /api/deploy/runs/deploy-1/verify")[0].body).toEqual({ all: true });
  });

  it("marks a step whose verify found a different record as an install step", async () => {
    const r: DeployRun = {
      id: "deploy-1",
      state: "active",
      created_at: NOW,
      updated_at: NOW,
      topology_version: "v1",
      steps: [
        step("sg1", { current: true, phase: "review", verify_diff: "服务器上记录的内容摘要与计划的不同", verify_state: "differs", position: 1 }),
        step("gw", { position: 2 }),
      ],
      skipped: [],
      stale: false,
      current: "sg1",
    };
    fakeApi({ "GET /api/deploy": () => ({ limits: { proves: [], does_not_prove: [], independent: ["x"] }, run: r, topology_version: "v1" }) });
    render(
      <AntApp>
        <DeploymentGuide />
      </AntApp>,
    );
    expect(await screen.findByTestId("deploy-verify-diff-sg1")).toHaveTextContent("内容摘要与计划的不同");
    expect(screen.queryByTestId("deploy-verify-group")).toBeNull();
  });
});
