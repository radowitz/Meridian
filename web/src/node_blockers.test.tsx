// Managed nodes without a link are listed on the deploy page whatever the
// plan says, each with a way to the topology.
import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { NodeBlockers } from "./DeploymentGuide";
import type { PreflightFinding } from "./types";

const f = (id: string, end: string): PreflightFinding => ({
  severity: "blocking",
  code: "node_has_no_link",
  message: `这个节点还没有链路：先在拓扑页把它连到${end}`,
  resource: id,
});

describe("deploy page: nodes without a link", () => {
  it("lists relay, exit and hub blockers with a topology link", () => {
    render(<NodeBlockers blockers={[f("relay", "网关"), f("us9", "枢纽"), f("hk9", "中继或 IX")]} />);
    const box = screen.getByTestId("node-blockers");
    for (const id of ["relay", "us9", "hk9"]) expect(within(box).getByText(id)).toBeTruthy();
    expect(within(box).getAllByText("去拓扑")).toHaveLength(3);
    expect(within(box).getAllByRole("link")[0].getAttribute("href")).toContain("topology");
  });

  it("renders nothing without blockers or with malformed entries", () => {
    const { container } = render(<NodeBlockers blockers={undefined} />);
    expect(container.textContent).toBe("");
    const r = render(<NodeBlockers blockers={[null as unknown as PreflightFinding]} />);
    expect(r.container.textContent).toBe("");
  });
});

describe("deploy guide with an invalid plan", () => {
  it("still shows the blockers next to the plan error", async () => {
    const { fakeApi } = await import("./testing");
    const { DeploymentGuide } = await import("./DeploymentGuide");
    const { App: AntApp } = await import("antd");
    fakeApi({
      "GET /api/deploy": () => ({
        limits: { proves: [], does_not_prove: [], independent: [] },
        run: null,
        plan_error: "拓扑无效：节点 relay 没有链路",
        plan_error_code: "invalid_topology",
        node_blockers: [f("relay", "网关")],
      }),
    });
    render(
      <AntApp>
        <DeploymentGuide />
      </AntApp>,
    );
    const box = await screen.findByTestId("node-blockers");
    expect(within(box).getByText("relay")).toBeTruthy();
    expect(box.textContent).toContain("先在拓扑页把它连到网关");
  });
});
