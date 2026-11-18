// Tunnel management address candidates in the server form: usable ones
// selectable with their link and dependency, unusable and unknown ones
// visible but not selectable with the reason, manual entry noted as
// unverified, the connection test before saving with the carrying-state
// note. Small renders (no page, no app shell).

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App as AntApp } from "antd";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CandidateList, TunnelCandidatePicker } from "./TunnelCandidates";
import { fakeApi, reply } from "./testing";
import type { MgmtCandidate, TunnelCandidates } from "./types";
import { clearCooldowns } from "./ui";

afterEach(() => clearCooldowns());

function cand(address: string, over: Partial<MgmtCandidate> = {}): MgmtCandidate {
  return {
    node_id: "dc1",
    address,
    family: address.includes(":") ? "ipv6" : "ipv4",
    link_id: "ix-dc1",
    link_name: "IX 到香港机房 1",
    iface: "m05",
    mode: "udp",
    peer_id: "ix",
    peer_name: "IX（主枢纽）",
    status: "usable",
    depends: "main",
    works: [{ state: "udp", source: "fd66:0:0:2::1", iface: "m01", hops: [], reply_hops: [], static: false, kind: "main" }],
    ...over,
  };
}

function data(over: Partial<TunnelCandidates> = {}): TunnelCandidates {
  return {
    server_id: "srv-dc1",
    nodes: [
      {
        node_id: "dc1",
        node_name: "香港机房 1",
        role: "exit",
        states: [
          { id: "udp", label: "主链路，网关到中继走 UDP 腿", tier: "main", iface: "m01" },
          { id: "backup", label: "备用枢纽承载（网关直连备用枢纽的 WSS）", tier: "backup", iface: "m02" },
        ],
        candidates: [
          cand("fd66:0:0:6::2"),
          cand("fd66:0:0:4::2", {
            link_id: "hkb-dc1",
            link_name: "备用枢纽到香港机房 1",
            peer_id: "hkb",
            peer_name: "备用枢纽",
            depends: "backup_hub",
            works: [{ state: "backup", source: "fd66:0:0:3::1", iface: "m02", hops: [], reply_hops: [], static: false, kind: "backup_hub" }],
          }),
          cand("10.66.6.2", {
            status: "unreachable",
            depends: undefined,
            works: [],
            reason: "回程：dc1 在链路 ix-dc1 上对 ix 的 AllowedIPs 不包含目的地址 10.66.2.1",
          }),
          cand("10.66.9.9", { status: "unknown", depends: undefined, works: [], reason: "去程：隧道对端 x 不是受管节点" }),
        ],
        notes: ["按安装时的首选链路推导"],
      },
    ],
    carrying: { known: true, state: "udp", label: "主链路，网关到中继走 UDP 腿", tier: "main" },
    ...over,
  };
}

describe("servers: tunnel address candidates", () => {
  it("offers usable candidates with link and dependency; unusable ones are visible, not selectable, with the reason", async () => {
    const onPick = vi.fn();
    render(<CandidateList data={data()} address="" onPick={onPick} />);
    const main = screen.getByTestId("tunnel-candidate-fd66:0:0:6::2");
    expect(main).toHaveTextContent("依赖主链路");
    expect(main).toHaveTextContent("IX 到香港机房 1");
    expect(main).toHaveTextContent("对端 IX（主枢纽）");
    expect(screen.getByTestId("tunnel-candidate-fd66:0:0:4::2")).toHaveTextContent("依赖备用枢纽");
    // The backup-hub address does not work while the main path carries.
    expect(screen.getByTestId("tunnel-candidate-fd66:0:0:4::2")).toHaveTextContent("当前承载状态下不通");
    const unusable = screen.getByTestId("tunnel-candidates-unusable");
    expect(within(unusable).getByTestId("tunnel-candidate-reason-10.66.6.2")).toHaveTextContent("AllowedIPs 不包含目的地址");
    expect(within(unusable).getByTestId("tunnel-candidate-10.66.9.9")).toHaveTextContent("无法判断");
    for (const r of within(unusable).getAllByRole("radio")) expect(r).toBeDisabled();
    await userEvent.click(screen.getByTestId("tunnel-pick-fd66:0:0:6::2"));
    expect(onPick).toHaveBeenCalledWith("fd66:0:0:6::2");
    expect(screen.getByTestId("tunnel-carrying")).toHaveTextContent("主链路");
  });

  it("notes a manual address as unverified, and an unknown carrying state", () => {
    render(
      <CandidateList
        data={data({ carrying: { known: false, message: "读不到网关当前的承载路径：没有配置 host agent" } })}
        address="10.66.77.7"
        onPick={() => undefined}
      />,
    );
    expect(screen.getByTestId("tunnel-manual-note")).toHaveTextContent("未经推导");
    expect(screen.getByTestId("tunnel-carrying")).toHaveTextContent("读不到网关当前的承载路径");
  });

  it("tests a candidate before saving and shows the carrying-state note on failure", async () => {
    const api = fakeApi({
      "GET /api/servers/:id/tunnel-candidates": () => data(),
      "POST /api/servers/:id/test": () => ({
        candidate: true,
        test: { at: "", ok: false, code: "unreachable", error: "无法连接 [fd66:0:0:6::2]:22", not_executed: true, duration_ms: 0 },
        path_note: { text: "这个地址依赖主链路（网关经中继到主枢纽），而网关现在经备用枢纽承载。面板不会自动改走其它管理通道。", derived: true },
      }),
    });
    render(
      <AntApp>
        <TunnelCandidatePicker serverId="srv-dc1" address="fd66:0:0:6::2" port={22} onPick={() => undefined} />
      </AntApp>,
    );
    await screen.findByTestId("tunnel-candidates");
    await userEvent.click(screen.getByTestId("tunnel-test"));
    await waitFor(() => expect(api.find("POST /api/servers/srv-dc1/test")).toHaveLength(1));
    expect(api.find("POST /api/servers/srv-dc1/test")[0].body).toEqual({ channel: { mode: "tunnel", address: "fd66:0:0:6::2", port: 22 } });
    expect(await screen.findByTestId("tunnel-test-result")).toHaveAttribute("data-ok", "false");
    expect(screen.getByTestId("tunnel-test-path-note")).toHaveTextContent("网关现在经备用枢纽承载");
  });

  it("refuses a test while the host key is not pinned, pointing to the existing confirmation flow", async () => {
    fakeApi({
      "GET /api/servers/:id/tunnel-candidates": () => data(),
      "POST /api/servers/:id/test": () => reply(409, { code: "host_key_untrusted", error: "服务器 dc1 的主机指纹还没有确认" }),
    });
    render(
      <AntApp>
        <TunnelCandidatePicker serverId="srv-dc1" address="fd66:0:0:6::2" onPick={() => undefined} />
      </AntApp>,
    );
    await screen.findByTestId("tunnel-candidates");
    await userEvent.click(screen.getByTestId("tunnel-test"));
    expect(await screen.findByText(/先按原有流程获取并核对指纹/)).toBeInTheDocument();
  });

  it("a new server has no candidates yet", () => {
    render(<TunnelCandidatePicker address="" onPick={() => undefined} />);
    expect(screen.getByTestId("tunnel-candidates-new")).toHaveTextContent("手工填写（未经推导）");
  });
});
