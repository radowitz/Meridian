// SOCKS credential versions in the panel: what a carrier's state says
// before and after a rotation, what a carrier installed before versions
// were recorded says (in sync, with the caveat), and the credentials
// section's notices. Small renders: the state tag and the SOCKS section.

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App as AntApp } from "antd";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SocksSection } from "./CredentialsPage";
import { NodeInstallTag } from "./DeployPage";
import {
  SOCKS_UNRECORDED_LABEL,
  SOCKS_UNRECORDED_TEXT,
  socksRotatedMessage,
  socksStateLines,
  socksTrackingProblem,
  socksUnrecorded,
  socksVersionsText,
} from "./status_words";
import { fakeApi, phoneWidth } from "./testing";
import type { NodeInstallState, SOCKSCredentialView } from "./types";

afterEach(() => vi.restoreAllMocks());

const NOW = "2026-11-15T00:00:00Z";
const CRED = "socks-0123456789ab";
const USER = "rotated-user-4711";
const PASS = "rotated-pass-0815";

function carrier(over: Partial<NodeInstallState> = {}): NodeInstallState {
  return { node_id: "dc2", node_name: "承载节点", role: "exit", state: "in_sync", pending: false, ...over };
}

function cred(over: Partial<SOCKSCredentialView> = {}): SOCKSCredentialView {
  return {
    id: CRED,
    name: "示例代理",
    secret_set: true,
    created_at: NOW,
    updated_at: NOW,
    used_by: [{ kind: "node", id: "myext", name: "外部出口" }],
    version: 1,
    tracked: true,
    carriers: ["dc2"],
    ...over,
  };
}

describe("carrier state and SOCKS credential versions", () => {
  it("a carrier installed before versions were recorded stays in sync and says what cannot be proven", () => {
    const note = `这个节点承载的外部 SOCKS 出口使用的凭据 ${CRED} 在面板开始记录凭据版本之前就已存在，这个节点安装时没有记录用的是哪一版：面板不能证明节点上的用户名和密码就是现在保存的`;
    const st = carrier({ socks_unrecorded: [CRED], note });
    render(<NodeInstallTag st={st} />);
    const tag = screen.getByTestId("node-state-dc2");
    expect(tag).toHaveTextContent("已是最新");
    expect(tag).toHaveTextContent(SOCKS_UNRECORDED_LABEL);
    expect(tag).not.toHaveTextContent("有待下发的变更");
    expect(socksStateLines(st)).toEqual([note]);
    // Without a sentence from the backend the panel's own is used.
    expect(socksStateLines(carrier({ socks_unrecorded: [CRED] }))).toEqual([SOCKS_UNRECORDED_TEXT]);
    expect(SOCKS_UNRECORDED_TEXT).toContain("不能证明");
    expect(SOCKS_UNRECORDED_TEXT).toContain("升级本身不把它算作待下发");
  });

  it("after a rotation the carrier is pending with the reason; after the reinstall it is in sync again", async () => {
    const reason = `外部 SOCKS 凭据已轮换（${CRED} 已安装版本 1，现在是版本 2）：承载节点仍在用旧的用户名和密码，重新预检并安装后才用新的`;
    const pending = carrier({ state: "changed", pending: true, reason, socks_versions: { [CRED]: 2 }, installed_socks_versions: { [CRED]: 1 } });
    const { unmount } = render(<NodeInstallTag st={pending} />);
    const tag = screen.getByTestId("node-state-dc2");
    expect(tag).toHaveTextContent("有待下发的变更");
    expect(tag).not.toHaveTextContent(SOCKS_UNRECORDED_LABEL);
    expect(socksStateLines(pending)).toEqual([`外部 SOCKS 凭据：现在是 ${CRED} 版本 2；已安装 ${CRED} 版本 1`]);
    await userEvent.hover(tag);
    const tip = await screen.findByRole("tooltip");
    expect(tip).toHaveTextContent("外部 SOCKS 凭据已轮换");
    expect(tip).toHaveTextContent("已安装版本 1，现在是版本 2");
    unmount();

    const done = carrier({ socks_versions: { [CRED]: 2 }, installed_socks_versions: { [CRED]: 2 } });
    render(<NodeInstallTag st={done} />);
    const again = screen.getByTestId("node-state-dc2");
    expect(again).toHaveTextContent("已是最新");
    expect(again).not.toHaveTextContent(SOCKS_UNRECORDED_LABEL);
    expect(socksStateLines(done)).toEqual([`外部 SOCKS 凭据：已安装 ${CRED} 版本 2`]);
  });

  it("a carrier of a credential rotated after the upgrade, installed before: pending, the installed version unknown", () => {
    const st = carrier({ state: "changed", pending: true, socks_versions: { [CRED]: 2 }, socks_unrecorded: [CRED] });
    render(<NodeInstallTag st={st} />);
    expect(screen.getByTestId("node-state-dc2")).toHaveTextContent("有待下发的变更");
    expect(screen.getByTestId("node-state-dc2")).not.toHaveTextContent(SOCKS_UNRECORDED_LABEL);
    expect(socksStateLines(st)).toEqual([`外部 SOCKS 凭据：现在是 ${CRED} 版本 2；已安装的版本没有记录`]);
  });

  it("a node that carries no external exit says nothing about SOCKS", () => {
    expect(socksStateLines(carrier())).toEqual([]);
    expect(socksVersionsText(undefined)).toBe("");
    expect(socksVersionsText({ "socks-b": 2, "socks-a": 1 })).toBe("socks-a 版本 1、socks-b 版本 2");
  });
});

describe("SOCKS credentials section", () => {
  function mount() {
    return render(
      <AntApp>
        <SocksSection focus={false} openCreate={false} />
      </AntApp>,
    );
  }

  it("names the credentials from before versions were recorded and what that means, at phone width too", async () => {
    phoneWidth();
    fakeApi({
      "GET /api/socks-credentials": () => ({
        credentials: [cred({ tracked: false, version: 3 }), cred({ id: "socks-ba9876543210", name: "新建的代理", carriers: ["dc1"] }), cred({ id: "socks-000000000001", name: "没人用", tracked: false, carriers: [], used_by: [] })],
        version_tracking: { ready: true, since: NOW },
      }),
    });
    mount();
    const notice = await screen.findByTestId("socks-unrecorded");
    expect(notice).toHaveTextContent("示例代理");
    expect(notice).not.toHaveTextContent("新建的代理");
    expect(notice).not.toHaveTextContent("没人用");
    expect(notice).toHaveTextContent("不能证明");
    expect(notice).toHaveTextContent("升级本身不把这些承载节点算作待下发");
    expect(screen.queryByTestId("socks-tracking-problem")).toBeNull();
    expect(await screen.findByTestId(`socks-version-${CRED}`)).toHaveTextContent("版本 3（记录版本之前已有，未轮换过）");
    expect(screen.getByTestId("socks-version-socks-ba9876543210")).toHaveTextContent("版本 1");
    expect(screen.getByTestId("socks-version-socks-ba9876543210")).not.toHaveTextContent("未轮换过");
  });

  it("says so when the baseline could not be written", async () => {
    fakeApi({
      "GET /api/socks-credentials": () => ({ credentials: [cred()], version_tracking: { ready: false, error: "写入凭据索引失败" } }),
    });
    mount();
    const warn = await screen.findByTestId("socks-tracking-problem");
    expect(warn).toHaveTextContent("写入凭据索引失败");
    expect(warn).toHaveTextContent("轮换不会让承载节点显示待下发");
    expect(socksTrackingProblem(undefined)).toBe("");
    expect(socksTrackingProblem({ ready: true })).toBe("");
  });

  it("a rotation names the carriers that now wait for an install, and never shows the material", async () => {
    let list = [cred({ tracked: false, version: 1 })];
    const note = "已轮换（版本 2）：承载节点 dc2 在重新预检并安装之前仍在用旧的用户名和密码；之前的预检已失效";
    const api = fakeApi({
      "GET /api/socks-credentials": () => ({ credentials: list, version_tracking: { ready: true, since: NOW } }),
      "PUT /api/socks-credentials/:id/secret": () => {
        list = [cred({ tracked: true, version: 2, rotated_at: NOW })];
        return { credential: list[0], pending: ["dc2"], note };
      },
    });
    mount();
    await screen.findByTestId("socks-unrecorded");
    const row = await screen.findByTestId(`socks-row-${CRED}`);
    await userEvent.click(within(row).getByRole("button", { name: "示例代理 的更多操作" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "轮换" }));
    const drawer = await screen.findByRole("dialog");
    expect(drawer).toHaveTextContent("轮换后承载节点显示「有待下发的变更」并写明原因，之前做的预检作废");
    expect(within(drawer).getByTestId("socks-rotate-carriers")).toHaveTextContent("dc2");
    await userEvent.type(within(drawer).getByLabelText("SOCKS 用户名"), USER);
    await userEvent.type(within(drawer).getByLabelText("SOCKS 密码"), PASS);
    await userEvent.click(within(drawer).getByRole("button", { name: /轮\s*换/ }));
    await waitFor(() => expect(api.find(`PUT /api/socks-credentials/${CRED}/secret`)).toHaveLength(1));
    expect(await screen.findByText(note)).toBeInTheDocument();
    // Rotated: tracked from now on, the caveat is gone.
    await waitFor(() => expect(screen.queryByTestId("socks-unrecorded")).toBeNull());
    expect(await screen.findByTestId(`socks-version-${CRED}`)).toHaveTextContent("版本 2");
    expect(document.body.textContent).not.toContain(USER);
    expect(document.body.textContent).not.toContain(PASS);
  });

  it("words of a rotation's answer", () => {
    expect(socksRotatedMessage({ credential: cred(), pending: ["dc1", "dc2"] })).toContain("承载节点 dc1、dc2 待下发");
    expect(socksRotatedMessage({ credential: cred(), pending: [] })).toBe("已轮换；承载节点重新装机后生效");
    expect(socksRotatedMessage({ credential: cred(), note: "服务器给的说明" })).toBe("服务器给的说明");
    expect(socksUnrecorded([cred(), cred({ tracked: false }), cred({ tracked: false, carriers: [] })])).toHaveLength(1);
  });
});
