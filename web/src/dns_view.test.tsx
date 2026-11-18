// The resolution view (the body of the 解析设置 page, #/dns): rows per kind
// of name, transports, the exits' upstream with the account masked,
// measured vs 未验证, the fixed check, the read-only config text, and the
// write-only account value. Without an encrypted upstream the page says so
// first and offers「设置加密上游」; the form explains in place what to enter,
// with one invented example.

import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App as AntApp } from "antd";
import { afterEach, describe, expect, it, vi } from "vitest";
import DNSSettingsPage, { DNSConfigView, upstreamState } from "./DNSView";
import { layoutChecks } from "./demo/testkit";
import { fakeApi, nowrapCellRisks, phoneWidth, tableBudgets } from "./testing";
import type { DNSView } from "./types";

afterEach(() => vi.restoreAllMocks());

const AT = "2026-11-14T00:00:00Z";
const MASK = "‹账户标识已隐藏›";
const SECRET = "acct9z8y7x";

function view(over: Partial<DNSView> = {}): DNSView {
  return {
    paths: [
      { scope: "domestic", label: "国内名字", answered_by: "网关 SmartDNS 的 domestic 组", egress: "网关自己的上联（家宽）",
        upstreams: [{ address: "192.0.2.53:853", transport: "dot", verify: "不按主机名校验" }, { address: "192.0.2.53:53", transport: "plain" }],
        switches: [{ name: "domestic_dot", label: "国内解析器", value: "192.0.2.53" }] },
      { scope: "exit", id: "jp-a", label: "出口 jp-a 的规则名字", answered_by: "出口 jp-a 上的 SmartDNS", egress: "出口 jp-a 自己的上联",
        upstreams: [{ address: "198.51.100.153:853", transport: "dot", verify: `主机名必须是 ${MASK}.dns.example.net` }] },
      { scope: "gateway", label: "网关主机自己的程序", answered_by: "主机系统的解析器：不由 Meridian 管理", egress: "网关自己的上联" },
    ],
    exits: [{ id: "jp-a", name: "日本", source: "global", description: `DoT 198.51.100.153:853（证书校验 ${MASK}.dns.example.net）`, transport: "dot", resolver: "fd66::54:1", checkable: true }],
    global_upstream: { protocol: "dot", addresses: ["198.51.100.153"], tls_host_name: "{account}.dns.example.net", account_credential: "dnsacct-1" },
    configs: [
      { node: "gw", node_name: "网关", role: "gateway", path: "/etc/smartdns/smartdns.conf", planned_sha256: "ab".repeat(32), installed: "same", basis: "gateway_installed_manifest" },
      { node: "jp-a", node_name: "日本", role: "exit", path: "/etc/smartdns/smartdns.conf", planned_sha256: "cd".repeat(32), installed: "differs", basis: "node_bundle_digest", restricted: true },
    ],
    forwarder: {
      available: true,
      checked_at: AT,
      resolvers: [
        { target: "direct", probe: { server: "192.0.2.53:53", outcome: "answer", reached: true, duration_ms: 21, transport: "udp", timeout_ms: 2000 } },
        { target: "direct", probe: { server: "198.51.100.53:53", outcome: "timeout", reached: false, duration_ms: 500, transport: "udp", timeout_ms: 500, known_silent: true },
          health: { server: "198.51.100.53:53", mark: 100, transport: "udp", last_outcome: "timeout", last_at: AT, last_latency_ms: 500, answered: 0, failed: 9, consecutive_failures: 9, source: "selfcheck" } },
      ],
    },
    checks: [],
    check_available: true,
    check_name: "example.com",
    unverified: ["面板显示的上游来自编译结果"],
    masked: MASK,
    ...over,
  };
}

function mount() {
  return render(
    <AntApp>
      <DNSConfigView />
    </AntApp>,
  );
}

describe("resolution view", () => {
  it("shows each kind of name with its upstream, transport and line, and what is measured", async () => {
    fakeApi({ "GET /api/dns": () => view(), "GET /api/dns-accounts": () => ({ accounts: [] }) });
    mount();
    const dom = await screen.findByTestId("dns-path-domestic");
    expect(within(dom).getAllByText("DoT").length).toBeGreaterThan(0);
    expect(within(dom).getByText("明文")).toBeTruthy();
    expect(within(dom).getByText("网关自己的上联（家宽）")).toBeTruthy();
    // "Planned, not verified" is said once for the section, not repeated per row.
    expect(within(dom).queryByText("计划（未验证）")).toBeNull();
    expect(screen.getByTestId("dns-path-exit-jp-a").textContent).toContain(`${MASK}.dns.example.net`);
    expect(screen.getByTestId("dns-path-gateway").textContent).toContain("不由 Meridian 管理");
    // Planned vs installed.
    expect(screen.getByTestId("dns-config-gw").textContent).toContain("与计划一致");
    expect(screen.getByTestId("dns-config-jp-a").textContent).toContain("与主机上已安装的不同");
    // The forwarder's resolvers, one silent and known as such.
    const rs = screen.getAllByTestId("dns-resolver");
    expect(rs).toHaveLength(2);
    expect(rs[1].textContent).toContain("已知不应答");
    expect(rs[1].textContent).toContain("最多等 500 毫秒");
    // No check yet: unverified.
    expect(screen.getByTestId("dns-exit-jp-a").textContent).toContain("未检查");
  });

  it("runs the fixed check and shows its result; without measurements the forwarder part says 未验证", async () => {
    let checked = false;
    const fa = fakeApi({
      "GET /api/dns": () =>
        view({
          checks: checked ? [{ exit_id: "jp-a", resolver: "fd66::54:1", name: "example.com", qtype: "A", outcome: "answer", answers: 1, duration_ms: 44, checked_at: AT }] : [],
          forwarder: { available: false, code: "sniff_off", message: "嗅探转发服务关闭", resolvers: [] },
        }),
      "GET /api/dns-accounts": () => ({ accounts: [] }),
      "POST /api/dns/check": () => {
        checked = true;
        return { check: {}, upstream: "" };
      },
    });
    mount();
    expect((await screen.findAllByText(/未验证：嗅探转发服务关闭/)).length).toBe(1);
    await openOverrides();
    await userEvent.click(within(screen.getByTestId("dns-exit-jp-a")).getByRole("button", { name: "解析检查" }));
    await waitFor(() => expect(screen.getByTestId("dns-check-jp-a").textContent).toContain("实测：有回答"));
    expect(fa.find("POST /api/dns/check")[0].body).toEqual({ exit_id: "jp-a" });
  });

  it("shows the config text read-only, masked", async () => {
    fakeApi({
      "GET /api/dns": () => view(),
      "GET /api/dns-accounts": () => ({ accounts: [] }),
      "GET /api/dns/config": () => ({ node: "jp-a", path: "/etc/smartdns/smartdns.conf", planned_sha256: "cd", text: `server-tls 198.51.100.153:853 -host-name ${MASK}.dns.example.net\n`, masked: true }),
    });
    mount();
    const row = await screen.findByTestId("dns-config-jp-a");
    await userEvent.click(screen.getByRole("button", { name: "生成的 SmartDNS 配置" }));
    await userEvent.click(within(row).getByRole("button", { name: "查看原文" }));
    const pre = await screen.findByLabelText("jp-a 的 SmartDNS 配置");
    expect(pre.textContent).toContain(`-host-name ${MASK}.dns.example.net`);
    expect(pre.tagName).toBe("PRE");
  });

  it("sends an account value once and never shows it", async () => {
    let accounts: unknown[] = [];
    const fa = fakeApi({
      "GET /api/dns": () => view(),
      "GET /api/dns-accounts": () => ({ accounts }),
      "POST /api/dns-accounts": () => {
        accounts = [{ id: "dnsacct-2", name: "示例", secret_set: true, created_at: AT, updated_at: AT, used_by: [] }];
        return { account: accounts[0] };
      },
    });
    mount();
    const box = await screen.findByTestId("dns-accounts");
    await userEvent.click(screen.getByRole("button", { name: "账户标识" }));
    await userEvent.type(within(box).getByLabelText("账户标识名称"), "示例");
    await userEvent.type(within(box).getByLabelText("账户标识的值"), SECRET);
    await userEvent.click(within(box).getByRole("button", { name: "添加账户标识" }));
    await waitFor(() => expect(within(box).getByText("值已保存，不再显示")).toBeTruthy());
    expect(fa.find("POST /api/dns-accounts")[0].body).toEqual({ name: "示例", account: SECRET });
    expect(document.body.textContent).not.toContain(SECRET);
    expect((within(box).getByLabelText("账户标识的值") as HTMLInputElement).value).toBe("");
  });

  it("saves the global upstream through the upstream endpoint", async () => {
    const fa = fakeApi({
      "GET /api/dns": () => view(),
      "GET /api/dns-accounts": () => ({ accounts: [] }),
      "PUT /api/dns/upstream": () => ({ note: "已保存" }),
    });
    mount();
    const form = await screen.findByTestId("dns-upstream-form");
    await userEvent.click(within(form).getByRole("button", { name: "保存到拓扑" }));
    await waitFor(() => expect(fa.find("PUT /api/dns/upstream")).toHaveLength(1));
    expect(fa.find("PUT /api/dns/upstream")[0].body).toEqual({
      global: { protocol: "dot", addresses: ["198.51.100.153"], tls_host_name: "{account}.dns.example.net", account_credential: "dnsacct-1" },
    });
  });
});

// ------------------------------------------------ rows that must wrap ---

describe("resolution paths: long labels", () => {
  it("a switch whose label is a sentence is a stacked row (label above the value), so it wraps instead of widening the row", async () => {
    const LABEL = "未列名单的名字也问国内解析器（只在回答全是国内地址时采用）";
    fakeApi({
      "GET /api/dns": () =>
        view({
          paths: [
            { scope: "unlisted", label: "没有名单、没有规则命中的名字", answered_by: "默认组 hk 当前成员出口上的 SmartDNS（组解析地址 fd66::53:b，组标记 0x10b）", egress: "经隧道到默认组的出口",
              upstreams: [{ address: "[fd66::53:b]:53", transport: "tunnel" }],
              switches: [{ name: "unlisted_domestic_dns", label: LABEL, value: "关" }, { name: "default_group", label: "默认境外组", value: "hk" }] },
          ],
        }),
      "GET /api/dns-accounts": () => ({ accounts: [] }),
    });
    mount();
    const row = await screen.findByTestId("dns-path-unlisted");
    expect(row).toHaveClass("dns-path");
    const dt = within(row).getByText(LABEL);
    expect(dt.tagName).toBe("DT");
    expect(dt.closest(".fact")).toHaveClass("fact-stacked");
    expect(dt.style.whiteSpace).toBe("");
    // Short labels of the same card stay side by side.
    expect(within(row).getByText("应答方").closest(".fact")).not.toHaveClass("fact-stacked");
    // Every switch row is stacked: its label is prose, whatever its length.
    expect(within(row).getByText("默认境外组").closest(".fact")).toHaveClass("fact-stacked");
    // The other rows of the page carry the class whose rules let their tag rows shrink to the box.
    for (const el of [...document.querySelectorAll("[data-testid^='dns-config-'], [data-testid='dns-resolver']")]) expect(el).toHaveClass("dns-row");
    expect(document.querySelector(".dns-page")).not.toBeNull();
  });
});

// ------------------------------------------ unconfigured: the guidance ---

const PLAIN_EXIT = { id: "jp-a", name: "日本", source: "default" as const, description: "内置公共解析器 192.0.2.1、192.0.2.2（明文 53）", transport: "plain", resolver: "fd66::54:1", checkable: true };

describe("resolution settings page: guidance", () => {
  it("is a page of its own, and without an encrypted upstream says so first with a prominent action", async () => {
    const fa = fakeApi({
      "GET /api/dns": () => view({ exits: [PLAIN_EXIT, { ...PLAIN_EXIT, id: "sg1", name: "新加坡" }], global_upstream: null }),
      "GET /api/dns-accounts": () => ({ accounts: [] }),
    });
    render(
      <AntApp>
        <DNSSettingsPage />
      </AntApp>,
    );
    expect(screen.getByRole("heading", { level: 1, name: "解析设置" })).toBeInTheDocument();
    const st = await screen.findByTestId("dns-upstream-status");
    expect(screen.getByRole("heading", { name: "境外解析上游（例如 NextDNS）" })).toBeVisible();
    expect(within(screen.getByTestId("dns-overseas-path")).getAllByRole("listitem").map((x) => x.textContent)).toEqual(["设备", "网关 SmartDNS", "隧道", "出口 SmartDNS", "境外解析上游"]);
    expect(document.querySelector(".dns-overrides")).not.toHaveAttribute("open");
    // Explanations are not on the page: they wait for the usage guide.
    expect(screen.getByTestId("page-help")).not.toBeVisible();
    expect(screen.getByTestId("dns-overseas-help")).toHaveTextContent(/\S/);
    expect(screen.getByTestId("dns-upstream-form").closest("details")).toBeNull();
    expect(st).toHaveAttribute("data-state", "none");
    expect(st).toHaveTextContent("还没有设置加密上游：境外名字现在由各出口向内置公共解析器明文查询");
    expect(screen.getByTestId("dns-upstream-why")).toHaveTextContent("出口所在网络能看到查询的名字");
    // It is the first thing of the page's content, above every section.
    expect(st.compareDocumentPosition(document.querySelector(".section")!) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    // Nothing to enter is shown until asked: the global form is on "built-in".
    const form = screen.getByTestId("dns-upstream-form");
    expect(within(form).queryByLabelText("上游地址")).toBeNull();
    await userEvent.click(within(st).getByRole("button", { name: "设置加密上游" }));
    const addr = await within(form).findByLabelText("上游地址");
    await waitFor(() => expect(addr).toHaveFocus());
    expect(within(form).getByLabelText("TLS 主机名")).toBeInTheDocument();
    // The explanation is in the usage guide (hidden on the page).
    const help = screen.getByTestId("dns-upstream-help");
    expect(help).not.toBeVisible();
    expect(help).toHaveTextContent("上游地址要自己填");
    expect(help).toHaveTextContent("面板不内置任何服务商的地址");
    expect(help).toHaveTextContent("账户标识单独保存，并且打码");
    expect(help).toHaveTextContent(`只显示「${MASK}」`);
    expect(help).toHaveTextContent("证书主机名用占位符");
    expect(help).toHaveTextContent("{account}");
    // One generic example: an invented provider, example.* names and documentation addresses only.
    const ex = within(help).getByTestId("dns-upstream-example");
    expect(ex).toHaveTextContent("虚构的服务商");
    expect(ex).toHaveTextContent("{account}.dns.example.net");
    expect(ex).toHaveTextContent("198.51.100.53, 2001:db8::53");
    const names = ex.textContent!.match(/[a-z0-9-]+(\.[a-z0-9-]+)+/gi)!.filter((n) => /[a-z]/i.test(n));
    expect(names.length).toBeGreaterThan(0);
    for (const n of names) expect(n, n).toMatch(/(^|\.)example\.(net|com|org)$/);
    for (const ip of ex.textContent!.match(/\b\d+\.\d+\.\d+\.\d+\b/g)!) expect(ip, ip).toMatch(/^(192\.0\.2|198\.51\.100|203\.0\.113)\./);
    // Nothing was saved by opening the form.
    expect(fa.calls.filter((c) => c.method !== "GET")).toEqual([]);
    layoutChecks("#/dns unconfigured");
  });

  it("says which exits still ask in clear text when only some are encrypted, and counts what is not installed yet", async () => {
    fakeApi({
      "GET /api/dns": () =>
        view({
          exits: [view().exits[0], { ...PLAIN_EXIT, id: "tw1", name: "台湾", source: "builtin" }],
          configs: [...view().configs, { node: "tw1", node_name: "台湾", role: "exit", path: "/etc/smartdns/smartdns.conf", planned_sha256: "01".repeat(32), installed: "same", basis: "node_bundle_digest" }],
        }),
      "GET /api/dns-accounts": () => ({ accounts: [] }),
    });
    mount();
    const st = await screen.findByTestId("dns-upstream-status");
    expect(st).toHaveAttribute("data-state", "partial");
    expect(st).toHaveTextContent("1 个出口使用加密上游，1 个仍向内置公共解析器明文查询：台湾");
    // jp-a's installed config differs from the plan.
    expect(st).toHaveTextContent("1 个出口尚未安装这份设置");
    expect(within(st).getByRole("link", { name: "部署页" })).toHaveAttribute("href", "#/deploy");
    expect(within(st).getByRole("button", { name: "设置加密上游" })).toBeInTheDocument();
  });

  it("with every exit on an encrypted upstream there is no warning and no setup button", async () => {
    fakeApi({ "GET /api/dns": () => perExitView({ exits: perExitView().exits.filter((e) => e.transport !== "plain") }), "GET /api/dns-accounts": () => ({ accounts: [] }) });
    mount();
    const st = await screen.findByTestId("dns-upstream-status");
    expect(st).toHaveAttribute("data-state", "all");
    expect(st).toHaveTextContent("已设置加密上游");
    expect(st).not.toHaveClass("ant-alert");
    expect(screen.queryByRole("button", { name: "设置加密上游" })).toBeNull();
    expect(upstreamState({ exits: [], configs: [] }).state).toBe("no_exits");
  });

  it("explains the same fields in an exit's own form", async () => {
    fakeApi({ "GET /api/dns": () => perExitView(), "GET /api/dns-accounts": () => ({ accounts: ACCOUNTS }) });
    mount();
    const ed = await openEditor("tw1", "台湾");
    expect(within(ed).queryByTestId("dns-upstream-help")).toBeNull();
    await userEvent.click(radio(ed, "单独设置"));
    await pick(ed, "协议", "DoH");
    const help = within(ed).getByTestId("dns-upstream-help");
    expect(help).toHaveTextContent("TLS 主机名和 DoH 路径里属于账户的那一段写成 {account}");
    expect(within(help).getByTestId("dns-upstream-example")).toHaveTextContent("/dns-query");
  });
});

// ------------------------------------------------ per-exit upstream ---

const GLOBAL = { protocol: "dot" as const, addresses: ["198.51.100.153"], tls_host_name: "{account}.dns.example.net", account_credential: "dnsacct-1" };
const OWN = { protocol: "doh" as const, addresses: ["203.0.113.53"], tls_host_name: "doh.example.org", path: "/{account}", account_credential: "dnsacct-1" };

/** Four managed exits (global / own / builtin / Mesh-only), the gateway and an external SOCKS exit. */
function perExitView(over: Partial<DNSView> = {}): DNSView {
  return view({
    paths: [
      ...view().paths,
      { scope: "external_exit", id: "ext1", label: "外部 SOCKS 出口 ext1 的规则名字", answered_by: "承载出口 jp-a 上的 SmartDNS", egress: "经该外部出口的 SOCKS 代理", nodes: ["gw", "jp-a"] },
    ],
    exits: [
      { id: "jp-a", name: "日本", source: "global", upstream: GLOBAL, description: `DoT 198.51.100.153:853（证书校验 ${MASK}.dns.example.net）`, transport: "dot", resolver: "fd66::54:1", checkable: true },
      { id: "sg1", name: "新加坡", source: "own", upstream: OWN, description: `DoH https://doh.example.org/${MASK}（连接 203.0.113.53:443，证书校验 doh.example.org）`, transport: "doh", resolver: "fd66::54:2", checkable: true },
      { id: "tw1", name: "台湾", source: "builtin", description: "内置公共解析器 192.0.2.1、192.0.2.2（明文 53）", transport: "plain", resolver: "fd66::54:3", checkable: true },
      { id: "mesh1", name: "只经 Mesh", source: "global", upstream: GLOBAL, description: `DoT 198.51.100.153:853（证书校验 ${MASK}.dns.example.net）`, transport: "dot", checkable: false },
    ],
    global_upstream: GLOBAL,
    configs: [
      { node: "gw", node_name: "网关", role: "gateway", path: "/etc/smartdns/smartdns.conf", planned_sha256: "ab".repeat(32), installed: "same", basis: "gateway_installed_manifest" },
      { node: "jp-a", node_name: "日本", role: "exit", path: "/etc/smartdns/smartdns.conf", planned_sha256: "cd".repeat(32), installed: "same", basis: "node_bundle_digest", restricted: true, account_version: 1, installed_account_version: 1 },
      { node: "sg1", node_name: "新加坡", role: "exit", path: "/etc/smartdns/smartdns.conf", planned_sha256: "ef".repeat(32), installed: "differs", basis: "node_bundle_digest", restricted: true, account_version: 2, installed_account_version: 1, detail: "DNS 账户标识已轮换" },
      { node: "tw1", node_name: "台湾", role: "exit", path: "/etc/smartdns/smartdns.conf", planned_sha256: "01".repeat(32), installed: "not_installed", basis: "node_bundle_digest" },
    ],
    ...over,
  });
}

const ACCOUNTS = [{ id: "dnsacct-1", name: "示例加密解析", secret_set: true, created_at: AT, updated_at: AT, used_by: [], version: 2, exits: ["jp-a", "sg1"] }];

async function openOverrides() {
  await screen.findByTestId("dns-exit-table");
  const details = document.querySelector<HTMLDetailsElement>(".dns-overrides")!;
  if (!details.open) await userEvent.click(within(details).getByText("按出口覆盖与解析检查", { selector: "summary" }));
}

async function openEditor(id: string, name: string) {
  await openOverrides();
  const row = await screen.findByTestId(`dns-exit-${id}`);
  await userEvent.click(within(row).getByRole("button", { name: `设置 ${name} 的解析上游` }));
  return screen.findByTestId(`dns-exit-editor-${id}`);
}

function radio(box: HTMLElement, label: string) {
  return within(box).getByRole("radio", { name: label }) as HTMLInputElement;
}

async function pick(box: HTMLElement, label: string, option: string) {
  fireEvent.mouseDown(within(box).getByRole("combobox", { name: label }));
  const el = await waitFor(() => {
    const hit = [...document.querySelectorAll<HTMLElement>(".ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option")].find((e) => e.textContent?.includes(option));
    if (!hit) throw new Error(`no option ${option}`);
    return hit;
  });
  fireEvent.click(el);
}

describe("per-exit upstream", () => {
  it("shows one row per exit: source, masked upstream, planned vs installed with the account version, and nodes it does not apply to", async () => {
    fakeApi({ "GET /api/dns": () => perExitView(), "GET /api/dns-accounts": () => ({ accounts: ACCOUNTS }) });
    mount();
    await openOverrides();
    const jp = await screen.findByTestId("dns-exit-jp-a");
    expect(jp.textContent).toContain("来源：全局设置");
    expect(jp.textContent).toContain(`${MASK}.dns.example.net`);
    expect(jp.textContent).toContain("计划与已安装一致");
    expect(within(jp).getByTestId("dns-exit-version-jp-a").textContent).toBe("账户标识版本：计划 1 · 已安装 1");
    const sg = screen.getByTestId("dns-exit-sg1");
    expect(sg.textContent).toContain("来源：本出口单独设置");
    expect(sg.textContent).toContain(`https://doh.example.org/${MASK}`);
    expect(sg.textContent).toContain("待下发：与已安装的不同");
    // The version changed by a rotation: planned 2, installed 1.
    expect(within(sg).getByTestId("dns-exit-version-sg1").textContent).toBe("账户标识版本：计划 2 · 已安装 1（不同：重新预检并安装后生效）");
    const tw = screen.getByTestId("dns-exit-tw1");
    expect(tw.textContent).toContain("来源：本出口保持内置");
    expect(tw.textContent).toContain("还没有安装");
    // Mesh-only: no check, with the reason.
    const mesh = screen.getByTestId("dns-exit-mesh1");
    expect(within(mesh).getByRole("button", { name: "解析检查" })).toBeDisabled();
    expect(mesh.textContent).toContain("没有隧道解析器");
    // Not configurable: the gateway and the external SOCKS exit, with reasons and no settings button.
    const gw = screen.getByTestId("dns-exit-gw");
    expect(within(gw).getByTestId("dns-exit-na-gw").textContent).toContain("网关不是出口");
    expect(within(gw).queryByRole("button")).toBeNull();
    const ext = screen.getByTestId("dns-exit-ext1");
    expect(ext.textContent).toContain("不可设置");
    expect(ext.textContent).toContain("外部 SOCKS 出口");
    expect(ext.textContent).toContain("承载出口 jp-a");
    expect(within(ext).queryByRole("button")).toBeNull();
  });

  it("starts each exit in its current mode and switches between the three", async () => {
    fakeApi({ "GET /api/dns": () => perExitView(), "GET /api/dns-accounts": () => ({ accounts: ACCOUNTS }) });
    mount();
    let ed = await openEditor("jp-a", "日本");
    expect(radio(ed, "沿用全局设置").checked).toBe(true);
    expect(within(ed).getByTestId("dns-exit-mode-note").textContent).toContain(`DoT 198.51.100.153:853（证书校验 ${MASK}.dns.example.net）`);
    expect(within(ed).queryByLabelText("上游地址")).toBeNull();
    await userEvent.click(radio(ed, "单独设置"));
    // The custom form starts from the global setting and has every field of the global form.
    expect((within(ed).getByLabelText("上游地址") as HTMLInputElement).value).toBe("198.51.100.153");
    expect((within(ed).getByLabelText("TLS 主机名") as HTMLInputElement).value).toBe("{account}.dns.example.net");
    expect(within(ed).getByLabelText("端口")).toBeTruthy();
    expect(within(ed).getByRole("combobox", { name: "账户标识" })).toBeTruthy();
    expect(within(ed).getByRole("button", { name: "新建账户标识" })).toBeTruthy();
    expect(within(ed).queryByLabelText("DoH 路径")).toBeNull();
    await pick(ed, "协议", "DoH");
    expect(within(ed).getByLabelText("DoH 路径")).toBeTruthy();
    await userEvent.click(radio(ed, "使用内置解析器"));
    expect(within(ed).queryByLabelText("上游地址")).toBeNull();
    expect(within(ed).getByTestId("dns-exit-mode-note").textContent).toContain("内置公共解析器");
    await userEvent.click(radio(ed, "沿用全局设置"));
    expect(within(ed).getByTestId("dns-exit-mode-note").textContent).toContain("跟随全局");
    // Another exit opens in its own mode.
    await userEvent.click(within(ed).getByRole("button", { name: "关闭设置" }));
    ed = await openEditor("sg1", "新加坡");
    expect(radio(ed, "单独设置").checked).toBe(true);
    expect((within(ed).getByLabelText("DoH 路径") as HTMLInputElement).value).toBe("/{account}");
    await userEvent.click(within(ed).getByRole("button", { name: "关闭设置" }));
    ed = await openEditor("tw1", "台湾");
    expect(radio(ed, "使用内置解析器").checked).toBe(true);
  });

  it("saves only the one exit: the exact body has no global and no other exit, then lists what became pending", async () => {
    let topo = perExitView();
    const fa = fakeApi({
      "GET /api/dns": () => topo,
      "GET /api/dns-accounts": () => ({ accounts: ACCOUNTS }),
      "PUT /api/dns/upstream": () => {
        topo = perExitView({ exits: perExitView().exits.map((e) => (e.id === "jp-a" ? { ...e, source: "builtin", upstream: undefined, transport: "plain", description: "内置公共解析器" } : e)) });
        return { note: "已保存到拓扑：要经过预检、确认并安装到各出口后才生效", changed_exits: ["jp-a"], global_upstream: GLOBAL };
      },
    });
    mount();
    const ed = await openEditor("jp-a", "日本");
    await userEvent.click(radio(ed, "使用内置解析器"));
    await userEvent.click(within(ed).getByRole("button", { name: "保存这个出口" }));
    await waitFor(() => expect(fa.find("PUT /api/dns/upstream")).toHaveLength(1));
    const body = fa.find("PUT /api/dns/upstream")[0].body as Record<string, unknown>;
    expect(body).toStrictEqual({ exits: { "jp-a": { protocol: "builtin" } } });
    expect("global" in body).toBe(false);
    const note = await screen.findByTestId("dns-pending");
    expect(note.textContent).toContain("待下发的出口：日本（jp-a）");
    expect(note.textContent).toContain("保存没有安装任何东西");
    // Nothing was installed or preflighted by the save.
    expect(fa.calls.filter((c) => c.method !== "GET" && c.path !== "/api/dns/upstream")).toEqual([]);
    await waitFor(() => expect(screen.getByTestId("dns-exit-jp-a").textContent).toContain("来源：本出口保持内置"));
  });

  it("sends a custom DoH upstream with the same shape as the global form, and null to follow the global setting again", async () => {
    const fa = fakeApi({
      "GET /api/dns": () => perExitView(),
      "GET /api/dns-accounts": () => ({ accounts: ACCOUNTS }),
      "PUT /api/dns/upstream": () => ({ note: "已保存", changed_exits: [] }),
    });
    mount();
    let ed = await openEditor("tw1", "台湾");
    await userEvent.click(radio(ed, "单独设置"));
    await pick(ed, "协议", "DoH");
    const addr = within(ed).getByLabelText("上游地址");
    await userEvent.clear(addr);
    await userEvent.type(addr, "203.0.113.7, 2001:db8::7");
    const host = within(ed).getByLabelText("TLS 主机名");
    await userEvent.clear(host);
    await userEvent.type(host, "dns.example.com");
    await userEvent.type(within(ed).getByLabelText("DoH 路径"), "/dns-query");
    // No {account} any more: clear the credential.
    fireEvent.mouseDown(within(ed).getByRole("combobox", { name: "账户标识" }));
    await userEvent.click(ed.querySelector(".ant-select-clear") as HTMLElement);
    await userEvent.click(within(ed).getByRole("button", { name: "保存这个出口" }));
    await waitFor(() => expect(fa.find("PUT /api/dns/upstream")).toHaveLength(1));
    expect(fa.find("PUT /api/dns/upstream")[0].body).toStrictEqual({
      exits: { tw1: { protocol: "doh", addresses: ["203.0.113.7", "2001:db8::7"], tls_host_name: "dns.example.com", path: "/dns-query" } },
    });
    expect(await screen.findByTestId("dns-pending")).toHaveTextContent("没有出口的生效上游发生变化");
    await userEvent.click(within(ed).getByRole("button", { name: "关闭设置" }));
    ed = await openEditor("sg1", "新加坡");
    await userEvent.click(radio(ed, "沿用全局设置"));
    await userEvent.click(within(ed).getByRole("button", { name: "保存这个出口" }));
    await waitFor(() => expect(fa.find("PUT /api/dns/upstream")).toHaveLength(2));
    expect(fa.find("PUT /api/dns/upstream")[1].body).toStrictEqual({ exits: { sg1: null } });
  });

  it("shows the validation issues of a refused exit setting, like the global form", async () => {
    fakeApi({
      "GET /api/dns": () => perExitView(),
      "GET /api/dns-accounts": () => ({ accounts: ACCOUNTS }),
      "PUT /api/dns/upstream": () => ({
        __status: 422,
        body: { error: "校验未通过，没有保存", issues: [{ code: "exit_dns_invalid", severity: "error", node_id: "jp-a", field: "exit_dns", message: "出口 jp-a 的解析上游：上游地址 10.1.2.3 在 10.0.0.0/8 里：只能是公网地址（不能经隧道、局域网或本机）。" }] },
      }),
    });
    mount();
    const ed = await openEditor("jp-a", "日本");
    await userEvent.click(radio(ed, "单独设置"));
    const addr = within(ed).getByLabelText("上游地址");
    await userEvent.clear(addr);
    await userEvent.type(addr, "10.1.2.3");
    await userEvent.click(within(ed).getByRole("button", { name: "保存这个出口" }));
    const err = await within(ed).findByTestId("dns-save-error");
    expect(err.textContent).toContain("校验未通过，没有保存");
    expect(err.textContent).toContain("只能是公网地址");
    expect(err.textContent).toContain("节点 jp-a");
    expect(screen.queryByTestId("dns-pending")).toBeNull();
    // The same display under the global form.
    const form = screen.getByTestId("dns-upstream-form");
    await userEvent.click(within(form).getByRole("button", { name: "保存到拓扑" }));
    expect((await within(form).findByTestId("dns-save-error")).textContent).toContain("只能是公网地址");
  });

  it("creates an account identifier from the exit form once and selects it, never showing the value", async () => {
    let accounts: unknown[] = ACCOUNTS;
    const fa = fakeApi({
      "GET /api/dns": () => perExitView(),
      "GET /api/dns-accounts": () => ({ accounts }),
      "POST /api/dns-accounts": () => {
        const a = { id: "dnsacct-9", name: "新服务", secret_set: true, created_at: AT, updated_at: AT, used_by: [], version: 1 };
        accounts = [...ACCOUNTS, a];
        return { account: a };
      },
      "PUT /api/dns/upstream": () => ({ note: "已保存", changed_exits: ["tw1"] }),
    });
    mount();
    const ed = await openEditor("tw1", "台湾");
    await userEvent.click(radio(ed, "单独设置"));
    await userEvent.click(within(ed).getByRole("button", { name: "新建账户标识" }));
    const box = within(ed).getByTestId("dns-account-create");
    await userEvent.type(within(box).getByLabelText("新账户标识名称"), "新服务");
    await userEvent.type(within(box).getByLabelText("新账户标识的值"), SECRET);
    expect((within(box).getByLabelText("新账户标识的值") as HTMLInputElement).type).toBe("password");
    await userEvent.click(within(box).getByRole("button", { name: "保存并选用" }));
    await waitFor(() => expect(within(ed).queryByTestId("dns-account-create")).toBeNull());
    expect(fa.find("POST /api/dns-accounts")[0].body).toEqual({ name: "新服务", account: SECRET });
    await userEvent.click(within(ed).getByRole("button", { name: "保存这个出口" }));
    await waitFor(() => expect(fa.find("PUT /api/dns/upstream")).toHaveLength(1));
    const sent = fa.find("PUT /api/dns/upstream")[0].body as { exits: Record<string, { account_credential?: string }> };
    expect(sent.exits.tw1.account_credential).toBe("dnsacct-9");
    expect(fa.find("PUT /api/dns/upstream")[0].raw).not.toContain(SECRET);
    expect(document.body.textContent).not.toContain(SECRET);
  });

  it("runs the read-only check from an exit's row", async () => {
    const fa = fakeApi({
      "GET /api/dns": () => perExitView(),
      "GET /api/dns-accounts": () => ({ accounts: ACCOUNTS }),
      "POST /api/dns/check": () => ({ check: {}, upstream: "" }),
    });
    mount();
    const sg = await screen.findByTestId("dns-exit-sg1");
    await openOverrides();
    await userEvent.click(within(sg).getByRole("button", { name: "解析检查" }));
    await waitFor(() => expect(fa.find("POST /api/dns/check")).toHaveLength(1));
    expect(fa.find("POST /api/dns/check")[0].body).toEqual({ exit_id: "sg1" });
    expect(fa.find("PUT /api/dns/upstream")).toHaveLength(0);
  });

  it("fits its section on a desktop and turns into cards on a phone", async () => {
    // A long exit name, as an operator would write one: it must wrap, not run over the next column.
    const LONG_EXIT = "日本东京 · 一个很长很长的出口名字用来测试换行（示例）";
    const long = () => perExitView({ exits: perExitView().exits.map((e) => (e.id === "jp-a" ? { ...e, name: LONG_EXIT } : e)) });
    fakeApi({ "GET /api/dns": long, "GET /api/dns-accounts": () => ({ accounts: ACCOUNTS }) });
    const { unmount } = render(
      <AntApp>
        <DNSSettingsPage />
      </AntApp>,
    );
    await screen.findByTestId("dns-exit-jp-a");
    const over = tableBudgets().filter((t) => t.width > t.budget);
    expect(over, over.map((t) => `${t.name} in ${t.container}: ${t.width} > ${t.budget}`).join("; ")).toEqual([]);
    // The name cell wraps (a flex column, the name and the id as its own wrapping block): whole name, no cut.
    const nameCell = screen.getByTestId("dns-exit-name-jp-a");
    expect(nameCell).toHaveClass("dns-exit-name");
    expect(nameCell.textContent).toBe(`${LONG_EXIT}jp-a`);
    expect(nameCell.closest("td")).toHaveClass("col-flex");
    expect(nameCell.closest("td")).not.toHaveClass("col-fixed");
    expect(nameCell.querySelector(".ellipsis-text")).toBeNull();
    expect(nameCell.closest(".ant-space")).toBeNull();
    // No nowrap cell of the table holds more text than its declared width (estimate; see testing.tsx).
    expect(nowrapCellRisks()).toEqual([]);
    unmount();

    phoneWidth();
    const { container } = mount();
    await openOverrides();
    const jp = await screen.findByTestId("dns-exit-jp-a");
    expect(jp.tagName).toBe("LI");
    // The card's heading is the whole name, wrapping.
    expect(jp.querySelector(".data-card-title .dns-exit-name")?.textContent).toBe(`${LONG_EXIT}jp-a`);
    expect(jp.querySelector(".data-card-title .ellipsis-text")).toBeNull();
    const wrap = container.querySelector<HTMLElement>("[data-testid='dns-exit-table']")!;
    expect(wrap).toHaveAttribute("data-stacked", "true");
    expect(wrap.querySelector("table")).toBeNull();
    expect(screen.getByTestId("dns-exit-gw").textContent).toContain("不可设置");
    const ed = await openEditor("jp-a", LONG_EXIT);
    await userEvent.click(radio(ed, "单独设置"));
    expect(within(ed).getByLabelText("上游地址")).toBeTruthy();
    expect(container.querySelector(".data-table-wrap[data-overflow='true']")).toBeNull();
    expect(container.querySelector(".ant-table-cell-fix-right")).toBeNull();
    layoutChecks("phone #/dns");
  });
});
