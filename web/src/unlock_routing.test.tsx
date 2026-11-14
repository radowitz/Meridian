// The unlock routing panel on its own (no page render): measured evidence
// and the inferred exit in use are labelled apart, the warning for "no
// candidate has evidence" is shown, and switching a service group to
// automatic sends only select (no rule is created).

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App as AntApp } from "antd";
import { afterEach, describe, expect, it, vi } from "vitest";
import { fakeApi } from "./testing";
import type { UnlockOwner } from "./types";
import { RoutingPanel } from "./UnlockRouting";

afterEach(() => vi.restoreAllMocks());

const owner: UnlockOwner = {
  key: "service-group:svc-video",
  name: "Video",
  kind: "service_group",
  service_group: "svc-video",
  group: "us",
  group_name: "美国",
  region: "us",
  mode: "pinned",
  pin_reason: "服务组是固定选择",
  probes: ["peacock"],
  candidates: [
    { exit_id: "us", name: "美国出口", region: "us", evidence: "failed", seen_at: "2026-11-14T00:00:00Z", active: true, default: true },
    { exit_id: "us-2", name: "美国出口（备）", region: "us", evidence: "expired", seen_at: "2026-11-13T00:00:00Z", active: false, default: false },
  ],
  default: "us",
  active: "us",
  inferred: true,
  demoted: false,
  unavailable: true,
  sched_fails: 2,
  switched_at: "2026-11-14T00:00:00Z",
  switch_reason: "all_failed",
  rules: 1,
  warnings: ["没有任何候选有有效的解锁证据：留在默认出口 美国出口，不会随机换地区"],
};

describe("unlock routing panel", () => {
  it("separates measured evidence from the inferred exit and switches a service group to auto", async () => {
    const api = fakeApi({ "PATCH /api/service-groups/:id": () => ({ service_group: { id: "svc-video", name: "Video", select: "auto" } }) });
    const changed = vi.fn();
    render(
      <AntApp>
        <RoutingPanel owners={[owner]} catalog={[{ service: "peacock", name: "Peacock", reachability: false, basis: "" }]} pending onChanged={changed} />
      </AntApp>,
    );
    const card = screen.getByTestId("owner-service-group:svc-video");
    expect(within(card).getByText("实测不可用")).toBeTruthy();
    expect(within(card).getByText("结果已过期")).toBeTruthy();
    expect(within(card).getByText("推算在用")).toBeTruthy();
    expect(within(card).getByTestId("owner-warning").textContent).toContain("留在默认出口");
    expect(screen.getByTestId("unlock-routing").textContent).toContain("没有在真实平台和真实网关上验证");
    await userEvent.click(within(card).getByRole("button", { name: /改为自动/ }));
    await waitFor(() => expect(api.find("PATCH /api/service-groups/svc-video")).toHaveLength(1));
    expect(api.find("PATCH /api/service-groups/svc-video")[0].body).toEqual({ select: "auto" });
    await waitFor(() => expect(changed).toHaveBeenCalled());
  });
});
