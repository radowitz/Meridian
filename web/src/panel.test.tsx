// Interaction tests against the in-memory fake API (testing.tsx).
// Covered here: secrets are sent once and never kept, the server host-key
// flow and its mismatch state, refused deletes with referrers, the honest
// Cloudflare permission check, list source policy and fallback reporting,
// the pending-install indicator, and Mesh never looking verified.

import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { fakeApi, panelStatus, renderAt, reply, webStorageDump } from "./testing";
import type { CloudflareAccountView, ListsJob, ListsView, SSHCredentialView, ServerView } from "./types";

const NOW = "2026-11-12T10:00:00Z";
const FP_OLD = "SHA256:oldOLDoldOLDoldOLDoldOLDoldOLDoldOLDold000";
const FP_NEW = "SHA256:newNEWnewNEWnewNEWnewNEWnewNEWnewNEWnew111";

function server(over: Partial<ServerView> = {}): ServerView {
  return {
    id: "srv-1",
    name: "香港枢纽",
    address: "192.0.2.10",
    port: 22,
    user: "root",
    auth: "key",
    credential_id: "key-1",
    credential: { id: "key-1", name: "主密钥", kind: "private_key" },
    host_key: { state: "unknown" },
    created_at: NOW,
    updated_at: NOW,
    last_test: null,
    operable: false,
    ready: false,
    missing: ["host_key", "connection_test"],
    in_use_by: [],
    node: null,
    ...over,
  };
}

function credential(over: Partial<SSHCredentialView> = {}): SSHCredentialView {
  return {
    id: "key-1",
    name: "主密钥",
    kind: "private_key",
    key_type: "ssh-ed25519",
    public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITESTPUBLICKEYONLY test",
    fingerprint: "SHA256:pubPUBpubPUBpubPUBpubPUBpubPUBpubPUBpub222",
    secret_set: true,
    created_at: NOW,
    updated_at: NOW,
    in_use_by: [],
    ...over,
  };
}

function account(over: Partial<CloudflareAccountView> = {}): CloudflareAccountView {
  return {
    id: "cf-1",
    name: "个人账户",
    account_id: "0123456789abcdef0123456789abcdef",
    token_set: true,
    created_at: NOW,
    updated_at: NOW,
    used_for_mesh: false,
    bound_deployment: null,
    in_use_by: [],
    ...over,
  };
}

async function confirmModal(okText: string) {
  const box = await waitFor(() => {
    const el = document.querySelector<HTMLElement>(".ant-modal-confirm");
    if (!el) throw new Error("no confirm dialog");
    return el;
  });
  await userEvent.click(within(box).getByRole("button", { name: btn(okText) }));
}

/** antd puts a space between two CJK characters in buttons ("删 除"). */
function btn(text: string) {
  return new RegExp(`^\\s*${text.split("").join("\\s*")}\\s*$`);
}

// ------------------------------------------------------------- secrets ---

describe("secrets", () => {
  it("sends an imported private key and passphrase once, clears the fields and keeps nothing in web storage", async () => {
    const KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nTESTKEYMATERIAL-do-not-keep\n-----END OPENSSH PRIVATE KEY-----";
    const PASS = "test-passphrase-4711";
    let creds: SSHCredentialView[] = [];
    const api = fakeApi({
      "GET /api/ssh-credentials": () => ({ credentials: creds }),
      "POST /api/ssh-credentials": (req) => {
        const b = req.body as { passphrase?: string };
        if (b.passphrase !== PASS) return reply(422, { error: "私钥口令不正确", code: "passphrase_invalid", field: "passphrase" });
        const c = credential({ id: "key-9", name: "导入的密钥", has_passphrase: true });
        creds = [c];
        return reply(201, { credential: c });
      },
    });
    renderAt("#/keys");
    await userEvent.click(await screen.findByRole("button", { name: /新建密钥/ }));
    const drawer = await screen.findByRole("dialog");
    await userEvent.click(within(drawer).getByText("导入私钥"));
    await userEvent.type(within(drawer).getByLabelText("名称"), "导入的密钥");
    fireEvent.change(within(drawer).getByLabelText("私钥"), { target: { value: KEY } });
    await userEvent.type(within(drawer).getByLabelText("私钥口令"), "wrong-pass");

    // First attempt: refused. The secrets are cleared all the same.
    await userEvent.click(within(drawer).getByRole("button", { name: btn("创建") }));
    await screen.findByText("私钥口令不正确");
    expect(within(drawer).getByLabelText("私钥")).toHaveValue("");
    expect(within(drawer).getByLabelText("私钥口令")).toHaveValue("");

    // Second attempt with the right passphrase.
    fireEvent.change(within(drawer).getByLabelText("私钥"), { target: { value: KEY } });
    await userEvent.type(within(drawer).getByLabelText("私钥口令"), PASS);
    await userEvent.click(within(drawer).getByRole("button", { name: btn("创建") }));
    await screen.findByText("密钥已创建");
    expect(screen.getByTestId("public-key-handoff")).toHaveTextContent("authorized_keys");

    const posts = api.find("POST /api/ssh-credentials");
    expect(posts).toHaveLength(2);
    expect(posts[1].body).toMatchObject({ kind: "private_key", private_key: KEY, passphrase: PASS, name: "导入的密钥" });
    // The passphrase went out in exactly one request; nothing else carried it.
    expect(api.calls.filter((c) => c.raw?.includes(PASS))).toHaveLength(1);
    expect(api.calls.filter((c) => c.raw?.includes("TESTKEYMATERIAL"))).toHaveLength(2);
    // Not in web storage, not in the URL, not on the page.
    const stored = webStorageDump();
    expect(stored).not.toContain(PASS);
    expect(stored).not.toContain("TESTKEYMATERIAL");
    expect(window.location.href).not.toContain("TESTKEYMATERIAL");
    expect(document.body.textContent).not.toContain(PASS);
    expect(document.body.textContent).not.toContain("TESTKEYMATERIAL");
    // The only thing in sessionStorage may be the panel token, nothing else.
    for (let i = 0; i < sessionStorage.length; i++) expect(sessionStorage.key(i)).toBe("meridian.token");
  });

  it("shows a set API token as 已设置 · 替换, never prefilled, and sends a replacement once", async () => {
    const TOKEN = "cf_test_token_replacement_123456";
    const api = fakeApi({
      "GET /api/cloudflare/accounts": () => ({ accounts: [account()], mesh_account: null }),
      "PUT /api/cloudflare/accounts/:id/token": () => ({ account: account({ rotated_at: NOW }) }),
    });
    renderAt("#/cloudflare");
    await userEvent.click(await screen.findByRole("button", { name: /的更多操作/ }));
    await userEvent.click(await waitFor(() => {
      const el = [...document.querySelectorAll<HTMLElement>(".ant-dropdown-menu-item")].find((e) => e.textContent?.includes("编辑"));
      if (!el) throw new Error("no menu");
      return el;
    }));
    const drawer = await screen.findByRole("dialog");
    expect(within(drawer).getByText("已设置")).toBeInTheDocument();
    expect(within(drawer).queryByLabelText("API token")).toBeNull();
    await userEvent.click(within(drawer).getByRole("button", { name: btn("替换") }));
    const input = within(drawer).getByLabelText("API token");
    expect(input).toHaveValue("");
    expect(input).toHaveAttribute("autocomplete", "new-password");
    await userEvent.type(input, TOKEN);
    await userEvent.click(within(drawer).getByRole("button", { name: btn("保存") }));
    await waitFor(() => expect(api.find("PUT /api/cloudflare/accounts/cf-1/token")).toHaveLength(1));
    expect(api.find("PUT /api/cloudflare/accounts/cf-1/token")[0].body).toEqual({ api_token: TOKEN });
    expect(api.calls.filter((c) => c.raw?.includes(TOKEN))).toHaveLength(1);
    expect(webStorageDump()).not.toContain(TOKEN);
    expect(document.body.textContent).not.toContain(TOKEN);
  });
});

// ------------------------------------------------------------- servers ---

describe("servers", () => {
  it("walks discover → trust exactly the discovered value → connection test", async () => {
    let sv = server();
    const api = fakeApi({
      "GET /api/servers": () => ({ servers: [sv] }),
      "GET /api/servers/:id": () => ({ server: sv }),
      "GET /api/ssh-credentials": () => ({ credentials: [credential({ in_use_by: [{ kind: "server", id: "srv-1", name: "香港枢纽" }] })] }),
      "POST /api/servers/:id/host-key/discover": () => {
        sv = server({ host_key: { state: "discovered", seen_fingerprint: FP_NEW, seen_key_type: "ssh-ed25519", seen_at: NOW } });
        return { discovery: { key_type: "ssh-ed25519", fingerprint: FP_NEW, matches_pinned: false }, server: sv };
      },
      "POST /api/servers/:id/host-key/trust": () => {
        sv = server({ host_key: { state: "trusted", fingerprint: FP_NEW, key_type: "ssh-ed25519", pinned_at: NOW, source: "operator" }, operable: true, missing: ["connection_test"] });
        return { server: sv };
      },
      "POST /api/servers/:id/test": () => {
        const test = { at: NOW, ok: true, auth_method: "key" as const, os: "Debian GNU/Linux 13", kernel: "6.12.0-test", arch: "x86_64", duration_ms: 812 };
        sv = { ...sv, last_test: test, ready: true, missing: [] };
        return { test, server: sv };
      },
    });
    renderAt("#/servers/srv-1");
    const flow = await screen.findByTestId("server-flow");
    expect(within(flow).getByRole("button", { name: btn("测试连接") })).toBeDisabled();

    await userEvent.click(within(flow).getByRole("button", { name: btn("获取指纹") }));
    await within(flow).findByText(FP_NEW);
    expect(within(flow).getByText(/ssh-keygen -lf/)).toBeInTheDocument();

    await userEvent.click(within(flow).getByRole("button", { name: /核对一致/ }));
    await confirmModal("确认并固定");
    await waitFor(() => expect(api.find("POST /api/servers/srv-1/host-key/trust")).toHaveLength(1));
    expect(api.find("POST /api/servers/srv-1/host-key/trust")[0].body).toEqual({ fingerprint: FP_NEW });

    const testBtn = await within(flow).findByRole("button", { name: btn("测试连接") });
    await waitFor(() => expect(testBtn).toBeEnabled());
    await userEvent.click(testBtn);
    await within(flow).findByText("Debian GNU/Linux 13");
    expect(within(flow).getByText("x86_64")).toBeInTheDocument();
  });

  it("blocks on a host-key mismatch and offers trust-new or clear, each with its consequence", async () => {
    let sv = server({
      host_key: {
        state: "mismatch",
        fingerprint: FP_OLD,
        key_type: "ssh-ed25519",
        pinned_at: NOW,
        seen_fingerprint: FP_NEW,
        seen_key_type: "ssh-ed25519",
        seen_at: NOW,
      },
      operable: false,
      missing: ["host_key", "connection_test"],
    });
    const api = fakeApi({
      "GET /api/servers": () => ({ servers: [sv] }),
      "GET /api/ssh-credentials": () => ({ credentials: [credential()] }),
      "POST /api/servers/:id/host-key/trust": (req) => {
        sv = server({ host_key: { state: "trusted", fingerprint: (req.body as { fingerprint: string }).fingerprint, pinned_at: NOW } });
        return { server: sv };
      },
    });
    renderAt("#/servers/srv-1");
    const alert = await screen.findByTestId("host-key-mismatch");
    expect(alert).toHaveTextContent("所有连接都被拒绝");
    expect(within(alert).getByText(FP_OLD)).toBeInTheDocument();
    expect(within(alert).getByText(FP_NEW)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: btn("测试连接") })).toBeDisabled();
    expect(within(alert).getByRole("button", { name: /清除固定并重新获取/ })).toBeInTheDocument();

    await userEvent.click(within(alert).getByRole("button", { name: /信任新指纹/ }));
    await waitFor(() => expect(document.querySelector(".ant-modal-confirm")).toHaveTextContent("旧指纹作废"));
    await confirmModal("确认并固定");
    await waitFor(() => expect(api.find("POST /api/servers/srv-1/host-key/trust")).toHaveLength(1));
    expect(api.find("POST /api/servers/srv-1/host-key/trust")[0].body).toEqual({ fingerprint: FP_NEW });
    await waitFor(() => expect(screen.queryByTestId("host-key-mismatch")).toBeNull());
  });

  it("lists the referrers as links when a delete is refused", async () => {
    fakeApi({
      "GET /api/servers": () => ({ servers: [server({ in_use_by: [{ kind: "node", id: "hk", name: "香港枢纽节点" }] })] }),
      "GET /api/ssh-credentials": () => ({ credentials: [credential()] }),
      "DELETE /api/servers/:id": () =>
        reply(409, {
          error: "服务器 香港枢纽 仍被引用（拓扑节点或未撤回完的 Mesh 部署），先解除引用",
          code: "in_use",
          in_use_by: [
            { kind: "node", id: "hk", name: "香港枢纽节点" },
            { kind: "mesh_deployment", id: "run-1", name: "Mesh 部署（published）" },
          ],
        }),
    });
    renderAt("#/servers");
    const row = await screen.findByTestId("server-row-srv-1");
    await userEvent.click(within(row).getByRole("button", { name: /的更多操作/ }));
    await userEvent.click(await waitFor(() => {
      const el = [...document.querySelectorAll<HTMLElement>(".ant-dropdown-menu-item")].find((e) => e.textContent?.includes("删除"));
      if (!el) throw new Error("no menu");
      return el;
    }));
    await confirmModal("删除");
    const refused = await screen.findByTestId("refused-dialog");
    expect(refused).toHaveTextContent("先解除引用");
    expect(within(refused).getByRole("link", { name: "香港枢纽节点" })).toHaveAttribute("href", "#/topology/hk");
    expect(within(refused).getByRole("link", { name: "Mesh 部署（published）" })).toHaveAttribute("href", "#/cloudflare?section=mesh");
  });
});

// ---------------------------------------------------------- cloudflare ---

describe("cloudflare", () => {
  it("presents a passing check as readable with write access unconfirmed, and a denied one as missing permissions", async () => {
    let acct = account();
    fakeApi({
      "GET /api/cloudflare/accounts": () => ({ accounts: [acct], mesh_account: null }),
      "POST /api/cloudflare/accounts/:id/check": () => {
        acct = account({
          permission_check: {
            checked_at: NOW,
            ok: true,
            token_status: "active",
            token_kind: "account",
            confirmed: ["可以读取这个账户的路由（Networks Read 或 Write）"],
            unconfirmed: ["Cloudflare One Connectors Write：只读检查无法区分 Read 与 Write"],
            checks: [
              { name: "token_verify", endpoint: "GET /accounts/{account_id}/tokens/verify", status: "pass" },
              { name: "read_mesh_nodes", endpoint: "GET /accounts/{account_id}/warp_connector", status: "pass" },
            ],
            detail: "token 有效，能读取 Mesh 节点和路由；写权限未能用只读检查证明（见 unconfirmed）。",
          },
        });
        return { check: acct.permission_check, account: acct };
      },
    });
    renderAt("#/cloudflare");
    await userEvent.click(await screen.findByRole("button", { name: /检查权限/ }));
    const view = await screen.findByTestId("permission-check");
    expect(view).toHaveTextContent("写权限未确认");
    expect(view).toHaveTextContent("Connectors Write：只读检查无法区分");
    expect(view.querySelector('[data-status="unverified"]')).not.toBeNull();
    // A pass is never shown in the plain "ok" colour.
    expect(view.querySelector('.status-tag[data-status="ok"]')?.textContent).toBe("通过");
    expect(screen.queryAllByText(/^正常$/)).toHaveLength(0);
  });

  it("shows denied checks and missing permissions", async () => {
    fakeApi({
      "GET /api/cloudflare/accounts": () => ({
        accounts: [
          account({
            permission_check: {
              checked_at: NOW,
              ok: false,
              missing: ["Cloudflare One Networks Write"],
              checks: [
                { name: "token_verify", endpoint: "GET /accounts/{account_id}/tokens/verify", status: "pass" },
                { name: "read_routes", endpoint: "GET /accounts/{account_id}/teamnet/routes", status: "denied", detail: "403 Authentication error" },
              ],
              detail: "Cloudflare 拒绝了部分检查：read_routes=denied。",
            },
          }),
        ],
        mesh_account: null,
      }),
    });
    renderAt("#/cloudflare");
    expect(await screen.findByText("缺少权限")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /展开行|Expand row/ }));
    const view = await screen.findByTestId("permission-check");
    expect(view).toHaveTextContent("被拒绝");
    expect(view).toHaveTextContent("Cloudflare One Networks Write");
    expect(view).toHaveTextContent("写权限未确认");
  });

  it("never calls a published Mesh usable", async () => {
    fakeApi({
      "GET /api/cloudflare/accounts": () => ({ accounts: [account({ used_for_mesh: true })], mesh_account: "cf-1" }),
      "GET /api/mesh": () => ({
        dataplane: "unverified",
        dataplane_note: "Mesh 数据面：未验证。路由发布成功不等于 Mesh 可用。",
        fault_injection: false,
        stages: ["plan", "routes"],
        mesh_account: { id: "cf-1", name: "个人账户", account_id: "0123456789abcdef0123456789abcdef", source: "selected", permission_check: null },
        plan_servers: [{ node_id: "hk", name: "香港枢纽", role: "hub", server_id: "srv-1", server_name: "香港枢纽", ready: true, missing: [] }],
        plan: { addressing: null, nodes: [{ id: "hk", name: "香港枢纽", role: "hub" }], routes: [], return_v4: [], return_v6: [], issues: [] },
        journal: {
          run_id: "run-1",
          state: "published",
          account_id: "0123456789abcdef0123456789abcdef",
          hosts: [{ node_id: "hk", role: "hub", server_id: "srv-1", credential_id: "key-1", ssh_host: "192.0.2.10", ssh_port: 22, ssh_user: "root", host_key: FP_OLD }],
          started: NOW,
          updated: NOW,
          stages: [
            { name: "plan", status: "done" },
            { name: "routes", status: "done" },
          ],
          nodes: [],
          routes: [],
          remotes: [],
          targets: [],
          dataplane: "unverified",
        },
      }),
    });
    renderAt("#/cloudflare");
    expect(await screen.findAllByText("路由已发布 · 数据面未验证")).not.toHaveLength(0);
    expect(screen.getAllByText("未验证").length).toBeGreaterThan(0);
    expect(document.body.textContent).not.toMatch(/Mesh\s*可用(?!；|。)/);
    expect(screen.getByText(FP_OLD)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: btn("撤回") })).toBeInTheDocument();
  });
});

// --------------------------------------------------------------- lists ---

function listsView(over: Partial<ListsView> = {}): ListsView {
  return {
    policy: "automatic",
    saved: false,
    policies: ["domestic", "overseas", "automatic"],
    order: ["domestic", "overseas"],
    sources: [
      { name: "domestic", geosite_base: "https://cdn.jsdelivr.net/gh/v2fly/domain-list-community@master/data", chnroute_base: "https://cdn.jsdelivr.net/gh/x" },
      { name: "overseas", geosite_base: "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data", chnroute_base: "https://raw.githubusercontent.com/x" },
    ],
    lists: { geosite: ["cn", "netflix"], keywords: [], chnroute: ["chnroute4", "chnroute6"] },
    host_available: true,
    job: null,
    ...over,
  };
}

describe("lists", () => {
  it("changes the source policy and reports a fallback and a kept previous version", async () => {
    let view = listsView();
    const done: ListsJob = {
      id: "lists-1",
      state: "done",
      policy: "automatic",
      lists: ["geosite", "chnroute"],
      started_at: NOW,
      finished_at: NOW,
      report: {
        policy: "automatic",
        sources: ["domestic", "overseas"],
        started_at: NOW,
        finished_at: NOW,
        ok: false,
        partial: true,
        dns_changed: true,
        dns_restart: "ok",
        lists: [
          {
            list: "geosite:netflix",
            kind: "geosite",
            updated: true,
            kept: false,
            source: "overseas",
            count: 120,
            files: 3,
            dropped: { regexp: 2 },
            current: { source: "overseas", url: "https://raw.githubusercontent.com/x/netflix", updated_at: NOW, count: 120, files: 3 },
            attempts: [
              { source: "domestic", url: "https://cdn.jsdelivr.net/x/netflix", ok: false, error: "HTTP 503", duration_ms: 900 },
              { source: "overseas", url: "https://raw.githubusercontent.com/x/netflix", ok: true, duration_ms: 1500 },
            ],
          },
          {
            list: "chnroute4",
            kind: "chnroute",
            updated: false,
            kept: true,
            current: { source: "domestic", url: "https://cdn.jsdelivr.net/x/china.txt", updated_at: "2026-11-01T00:00:00Z", count: 8000 },
            attempts: [
              { source: "domestic", url: "https://cdn.jsdelivr.net/x/china.txt", ok: false, error: "条数骤减", duration_ms: 400 },
              { source: "overseas", url: "https://raw.githubusercontent.com/x/china.txt", ok: false, error: "timeout", duration_ms: 60000 },
            ],
            error: "两个源都失败",
          },
        ],
      },
    };
    let jobReads = 0;
    const api = fakeApi({
      // The agent answers right now (GET /api/status), so an update can run.
      "GET /api/status": () => panelStatus({ agent: { configured: true, ok: true }, lists_available: true }),
      "GET /api/lists": () => view,
      "PUT /api/lists/policy": (req) => {
        view = listsView({ policy: (req.body as { policy: "domestic" }).policy, saved: true });
        return view;
      },
      "POST /api/lists/update": () =>
        reply(202, { job: { id: "lists-1", state: "running", policy: "domestic", lists: ["geosite", "chnroute"], started_at: NOW } }),
      "GET /api/lists/job": () => {
        jobReads++;
        return { job: jobReads > 1 ? done : null };
      },
    });
    renderAt("#/lists");
    expect(await screen.findByText(/没有定时任务/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("radio", { name: /^国内源/ }));
    await waitFor(() => expect(api.find("PUT /api/lists/policy")).toHaveLength(1));
    expect(api.find("PUT /api/lists/policy")[0].body).toEqual({ policy: "domestic" });
    await waitFor(() => expect(screen.getByRole("radio", { name: /^国内源/ })).toHaveAttribute("aria-checked", "true"));

    await userEvent.click(screen.getByRole("button", { name: /立即更新/ }));
    await waitFor(() => expect(api.find("POST /api/lists/update")).toHaveLength(1));
    expect(await screen.findByText("更新中")).toBeInTheDocument();
    const job = await screen.findByTestId("lists-job", {}, { timeout: 8000 });
    await within(job).findByText("部分更新", {}, { timeout: 8000 });
    expect(within(job).getByText("已更新（换源后）")).toBeInTheDocument();
    expect(within(job).getByText("失败，保留上一版")).toBeInTheDocument();
    expect(within(job).getByText(/1 个名单下载或校验失败，网关上继续使用上一版/)).toBeInTheDocument();
    expect(within(job).getByText("HTTP 503")).toBeInTheDocument();
  });

  it("explains that updates need the host agent", async () => {
    fakeApi({ "GET /api/lists": () => listsView({ host_available: false }) });
    renderAt("#/lists");
    expect(await screen.findByText("宿主执行通道不可用，现在不能更新名单")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /立即更新/ })).toBeDisabled();
  });

  it("does not offer an update when the lists action is configured but the agent does not answer", async () => {
    fakeApi({
      "GET /api/lists": () => listsView({ host_available: true }),
      "GET /api/status": () => panelStatus({ agent: { configured: true, ok: false, error: "dial unix: connection refused" }, lists_available: false }),
    });
    renderAt("#/lists");
    expect(await screen.findByText("宿主执行通道不可用，现在不能更新名单")).toBeInTheDocument();
    expect(screen.getByText("dial unix: connection refused")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /立即更新/ })).toBeDisabled();
  });
});

// ------------------------------------------------------ pending install ---

describe("pending install indicator (GET /api/status)", () => {
  const changed = (applied_matches: boolean) =>
    panelStatus({ agent: { configured: true, ok: true }, installOver: { state: "changed", installed_version: 3, applied: true, applied_matches } });

  it("appears when the stored topology differs from what is installed and links to deploy", async () => {
    const api = fakeApi({ "GET /api/status": () => changed(false) });
    renderAt("#/servers");
    const ind = await screen.findByTestId("pending-install");
    expect(ind).toHaveTextContent("有改动尚未安装");
    expect(screen.getByTestId("global-status")).toHaveTextContent("v3");
    await userEvent.click(within(ind).getByRole("button", { name: /安装/ }));
    await waitFor(() => expect(window.location.hash).toBe("#/deploy"));
    // The shell no longer polls the heavy endpoints.
    expect(api.find("GET /api/mesh")).toHaveLength(0);
    expect(api.find("GET /api/unlock/jobs")).toHaveLength(0);
    expect(api.find("GET /api/status").length).toBeGreaterThan(0);
  });

  it("says 已应用，尚未安装 when the change was applied to the data directory but not installed", async () => {
    // /api/diff compares with the applied snapshot and says "no change"; the
    // status endpoint compares with the installed manifest and does not.
    fakeApi({ "GET /api/status": () => changed(true) });
    renderAt("#/servers");
    const ind = await screen.findByTestId("pending-install");
    expect(ind).toHaveTextContent("已应用，尚未安装");
  });

  it("is absent when the installed version is in sync", async () => {
    fakeApi({
      "GET /api/status": () => panelStatus({ agent: { configured: true, ok: true }, installOver: { state: "in_sync", installed_version: 3, applied: true, applied_matches: true } }),
    });
    renderAt("#/servers");
    await screen.findByText("宿主通道正常");
    await act(async () => {
      await new Promise((r) => setTimeout(r, 50));
    });
    expect(screen.queryByTestId("pending-install")).toBeNull();
  });

  it("says 尚未安装到网关 when nothing was ever installed", async () => {
    fakeApi();
    renderAt("#/");
    const ind = (await screen.findAllByTestId("pending-install"))[0];
    expect(ind).toHaveTextContent("尚未安装到网关");
  });

  it("says 拓扑无法编译 when the stored draft does not compile", async () => {
    fakeApi({ "GET /api/status": () => panelStatus({ installOver: { state: "invalid", error: "拓扑校验未通过" } }) });
    renderAt("#/servers");
    expect(await screen.findByTestId("pending-install")).toHaveTextContent("拓扑无法编译");
  });

  it("shows running jobs from the status endpoint", async () => {
    fakeApi({
      "GET /api/status": () =>
        panelStatus({ jobs: { lists: { state: "running", running: true }, unlock: { state: "done", running: false }, mesh: { state: "compensating", running: true } } }),
    });
    renderAt("#/servers");
    const bar = await screen.findByTestId("global-status");
    await within(bar).findByText("名单更新中");
    expect(bar).toHaveTextContent("Mesh 部署进行中");
    expect(bar).not.toHaveTextContent("解锁探测中");
  });
});

describe("error table", () => {
  it("names a login method the server does not offer differently from a rejected credential", async () => {
    const { errorTitle } = await import("./ui");
    const { ApiError } = await import("./api");
    expect(errorTitle(new ApiError(502, { error: "x", code: "auth_method_unavailable" }))).toBe("服务器不接受这种登录方式");
    expect(errorTitle(new ApiError(502, { error: "x", code: "auth_failed" }))).toMatch(/拒绝/);
    for (const c of ["legacy_install_refused", "transaction_pending", "peer_keys_missing", "nothing_to_rollback", "rollback_mode_required", "activation_failed_compensated", "activation_failed_uncompensated"])
      expect(errorTitle(new ApiError(409, { error: "x", code: c }))).not.toBe("操作没有完成");
  });
});
