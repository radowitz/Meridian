// Management channels, failures before execution and the per-node install
// state, against the in-memory fake API. Small tests on purpose: the deploy
// page suite in pages.test.tsx is already slow.

import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";
import { fakeApi, panelStatus, renderAt } from "./testing";
import { ApiError } from "./api";
import { ApiErrorAlert, clearCooldowns } from "./ui";
import type { Node, ServerView, Topology } from "./types";

const NOW = "2026-11-14T10:00:00Z";

function server(over: Partial<ServerView> = {}): ServerView {
  return {
    id: "srv-hub",
    name: "香港枢纽机",
    address: "198.51.100.20",
    port: 22,
    user: "root",
    auth: "key",
    credential: null,
    host_key: { state: "trusted", fingerprint: "SHA256:hub" },
    created_at: NOW,
    updated_at: NOW,
    operable: true,
    ready: true,
    missing: [],
    in_use_by: [],
    node: null,
    ...over,
  };
}

function node(id: string, name: string, over: Partial<Node> = {}): Node {
  return {
    id,
    name,
    role: "exit",
    region: "hk",
    managed: true,
    path_v4: true,
    path_v6: true,
    egress_v4: true,
    egress_v6: true,
    nat_dial_out: false,
    residential: false,
    ix_bound: false,
    ...over,
  };
}

afterEach(() => clearCooldowns());

describe("servers: management channel", () => {
  it("edits the channel to a jump through a relay and sends exactly that, labelled unverified", async () => {
    const relay = server({ id: "srv-relay", name: "国内中继机", address: "203.0.113.5", node: { kind: "node", id: "relay", name: "国内中继" } });
    let hub = server();
    const api = fakeApi({
      "GET /api/servers": () => ({ servers: [relay, hub] }),
      "GET /api/servers/:id": (req) => ({ server: req.params.id === relay.id ? relay : hub }),
      "PATCH /api/servers/:id": (req) => {
        hub = { ...hub, channel: (req.body as { channel: ServerView["channel"] }).channel };
        return { server: hub };
      },
    });
    renderAt("#/servers/srv-hub");
    await userEvent.click(await screen.findByRole("button", { name: /编\s*辑/ }));
    const drawer = await waitFor(() => {
      const el = [...document.querySelectorAll<HTMLElement>(".ant-drawer")].find((d) => d.textContent?.includes("编辑 香港枢纽机"));
      if (!el) throw new Error("no edit drawer");
      return el;
    });
    expect(drawer).toHaveTextContent("不会自动改走直连");
    expect(drawer).toHaveTextContent("还没有在真实主机上验证过");
    await userEvent.click(within(drawer).getByText("经中继跳转"));
    const sel = await within(drawer).findByRole("combobox", { name: "中继服务器" });
    fireEvent.mouseDown(sel);
    const opt = await waitFor(() => {
      const hit = [...document.querySelectorAll<HTMLElement>(".ant-select-item-option")].find((e) => e.textContent?.includes("国内中继机"));
      if (!hit) throw new Error("no relay option");
      return hit;
    });
    // The server itself is not offered as its own relay.
    expect([...document.querySelectorAll(".ant-select-item-option")].some((e) => e.textContent?.includes("香港枢纽机"))).toBe(false);
    fireEvent.click(opt);
    await userEvent.click(within(drawer).getByRole("button", { name: /保\s*存/ }));
    await waitFor(() => expect(api.find("PATCH /api/servers/srv-hub")).toHaveLength(1));
    expect(api.find("PATCH /api/servers/srv-hub")[0].body).toEqual({ channel: { mode: "jump", via_server_id: "srv-relay" } });
    await waitFor(() => expect(document.body).toHaveTextContent("经中继 国内中继机 跳转到 198.51.100.20:22"));
    expect(document.body).toHaveTextContent("未经实机验证");
  });

  it("says plainly that nothing ran and a retry is safe after a handshake timeout", async () => {
    let sv = server({ ready: false, missing: ["connection_test"], credential_id: "cred-k", credential: { id: "cred-k", name: "运维密钥", kind: "private_key" } });
    const failed = {
      at: NOW,
      ok: false,
      code: "ssh_handshake_timeout",
      error: "香港枢纽机 的 SSH 握手（密钥交换或登录）超时",
      not_executed: true,
      safe_to_retry: true,
      duration_ms: 20000,
    };
    fakeApi({
      "GET /api/servers": () => ({ servers: [sv] }),
      "GET /api/servers/:id": () => ({ server: sv }),
      "POST /api/servers/:id/test": () => {
        sv = { ...sv, last_test: failed };
        return { test: failed, server: sv };
      },
    });
    renderAt("#/servers/srv-hub");
    const flow = await screen.findByTestId("server-flow");
    await userEvent.click(within(flow).getByRole("button", { name: /测\s*试\s*连\s*接/ }));
    const note = await within(flow).findByTestId("exec-note");
    expect(note).toHaveTextContent("没有执行任何操作，可以安全重试");
    expect(flow).toHaveTextContent("SSH 握手超时");
  });

  it("says nothing ran but no safe retry for a refused login, and nothing at all when execution may have started", () => {
    const auth = new ApiError(502, { error: "登录被拒绝", code: "auth_failed", not_executed: true });
    const { unmount } = render(<ApiErrorAlert error={auth} />);
    expect(screen.getByTestId("exec-note")).toHaveTextContent("没有执行任何操作。");
    expect(screen.getByTestId("exec-note")).not.toHaveTextContent("可以安全重试");
    unmount();
    render(<ApiErrorAlert error={new ApiError(502, { error: "远程执行超时，结果不明", code: "run_timeout" })} />);
    expect(screen.queryByTestId("exec-note")).toBeNull();
  });
});

describe("deploy: per-node install state", () => {
  it("shows each remote node against its own install, not the gateway's", async () => {
    const t: Topology = {
      settings: { draft: false } as Topology["settings"],
      nodes: [node("gw", "家宽网关", { role: "gateway", region: "cn" }), node("hk-2", "香港二号", { server_id: "srv-hub", public_key: "PUB=" }), node("us", "美国", { region: "us", server_id: "srv-us", public_key: "PUB2=" })],
      links: [],
      rules: [],
    } as Topology;
    fakeApi({
      "GET /api/topology": () => t,
      "GET /api/servers": () => ({ servers: [server(), server({ id: "srv-us", name: "美国机", address: "198.51.100.40" })] }),
      "GET /api/status": () =>
        panelStatus({
          installOver: { state: "in_sync", installed_version: 3, applied: true, applied_matches: false },
          nodes: [
            { node_id: "gw", node_name: "家宽网关", role: "gateway", state: "in_sync", pending: false },
            {
              node_id: "hk-2",
              node_name: "香港二号",
              role: "exit",
              state: "in_sync",
              pending: false,
              verify: { at: NOW, state: "verified", source: "post_install" },
            },
            {
              node_id: "us",
              node_name: "美国",
              role: "exit",
              state: "changed",
              pending: true,
              reason: "这个节点要下发的文件与它上一次成功安装的不同",
              last_outcome: "compensated",
              evidence: "host_journal",
            },
          ],
          pending_nodes: 1,
        }),
    });
    renderAt("#/deploy");
    const hk = await screen.findByTestId("node-state-hk-2");
    expect(hk).toHaveTextContent("已是最新");
    expect(screen.getByTestId("node-state-us")).toHaveTextContent("有待下发的变更");
  });
});
