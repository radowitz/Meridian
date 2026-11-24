// Interaction tests of the operational pages against the in-memory fake
// API (split out of the former pages.test.tsx; helpers and fixtures in
// pages_fixtures.tsx).
//
// The deploy page: failed and refused installs, rollback choices, remote
// nodes, install pre-checks, panel-delivered binaries, deployment records
// and withdraw, managed sysctl, SSH rate limiting and the servers page's
// login help.

import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";
import { fakeApi, panelStatus, renderAt, reply, webStorageDump } from "./testing";
import { clearCooldowns } from "./ui";
import type {
  PreflightRecord,
} from "./types";
import {
  NOW,
  btn,
  confirmModal,
  exitNode,
  topology,
  server,
  OK_AGENT,
  PUBKEY,
  preflightRec,
  CLEAN,
  deployment,
  EMPTY_SET,
  deploymentsView,
  withdrawPlanOf,
} from "./pages_fixtures";

describe("deploy", () => {
  const changed = () => panelStatus({ ...OK_AGENT, installOver: { state: "changed", installed_version: 3, applied: true, applied_matches: false } });
  const host = (installed: boolean) => ({
    installed: installed ? { version: 3, files: 10, interfaces: ["m1"], units: ["meridian.service"], nft_tables: ["inet meridian"], route_tables: [100], dns: true } : null,
    pending: null,
    agent: { ok: true },
  });

  it("shows the failing step and that the install was compensated", async () => {
    fakeApi({
      "GET /api/status": changed,
      "GET /api/host": () => host(true),
      "POST /api/diff": () => ({ diff: "===== nodes/gw/etc/meridian/meridian.nft (changed) =====\n table\n-old\n+new\n", order: [], issues: [] }),
      "POST /api/apply": () =>
        reply(500, {
          error: "安装失败，已补偿回到事务前的状态：宿主动作 activate 失败：start meridian.service",
          code: "activation_failed_compensated",
          compensated: true,
          host: {
            transaction: "txn-1",
            kind: "apply",
            from_version: 3,
            to_version: 4,
            diff: { files_changed: ["etc/meridian/meridian.nft"] },
            steps: [
              { name: "daemon-reload", ok: true },
              { name: "start meridian.service", ok: false, detail: "Job for meridian.service failed" },
            ],
            committed: false,
            compensated: true,
          },
        }),
    });
    renderAt("#/deploy");
    expect(await screen.findByTestId("applied-snapshot-diff")).toHaveTextContent("1 个文件");
    await userEvent.click(await screen.findByRole("button", { name: /安装到网关/ }));
    await confirmModal("安装");
    const failed = await screen.findByTestId("txn-failed");
    expect(failed).toHaveTextContent("失败，已补偿回事务前的状态");
    const step = failed.querySelector('[data-step-status="failed"]')!;
    expect(step).toHaveTextContent("start meridian.service");
    expect(step).toHaveTextContent("从这一步开始失败");
    expect(failed).toHaveTextContent("已补偿回安装前");
    expect(screen.queryByText(/已安装：服务已启动/)).toBeNull();
  });

  it("explains refusals by their code: no host agent, missing peer keys, legacy, pending, invalid", async () => {
    const api = fakeApi({
      "GET /api/topology": () => {
        const t = topology();
        return { ...t, nodes: [...t.nodes, exitNode("ix-line", "IX 专线", { managed: false })] };
      },
      "GET /api/status": changed,
      "GET /api/host": () => host(true),
      "POST /api/apply": () => reply(503, { error: "面板没有宿主执行能力：……未写入任何宿主文件", code: "host_unavailable" }),
    });
    renderAt("#/deploy");
    const install = async () => {
      await userEvent.click(await screen.findByRole("button", { name: /安装到网关/ }));
      await confirmModal("安装");
    };
    await install();
    expect(await screen.findByTestId("txn-refused")).toHaveTextContent("没有宿主执行通道，什么都没改");

    api.on("POST /api/apply", () =>
      reply(422, {
        error: "拒绝安装",
        code: "peer_keys_missing",
        peer_key_problems: [{ peer: "hk-hub", problem: "missing" }, { peer: "hk-ix", problem: "placeholder" }, { peer: "ix-line", problem: "missing" }],
      }),
    );
    await install();
    await waitFor(() => expect(screen.getByTestId("txn-refused")).toHaveTextContent("这些对端节点还没有可用的公钥"));
    const refused = screen.getByTestId("txn-refused");
    expect(within(refused).getByRole("link", { name: "主枢纽" })).toHaveAttribute("href", "#/topology/hk-hub");
    // A managed remote node is fixed in 远端节点; anything else in the topology.
    const items = within(screen.getByTestId("peer-key-list")).getAllByRole("listitem");
    expect(items[0]).toHaveTextContent("在下面「远端节点」里生成密钥并下发");
    expect(items[2]).toHaveTextContent("在拓扑里填入它的公钥");
    expect(within(items[2]).getByRole("link", { name: "在拓扑里填入它的公钥" })).toHaveAttribute("href", "#/topology/ix-line");

    // The page decides on the code, not on the message text.
    api.on("POST /api/apply", () => reply(409, { error: "refused (any text)", code: "legacy_install_refused" }));
    await install();
    await waitFor(() => expect(screen.getByTestId("txn-refused")).toHaveTextContent("无法可靠接管"));

    api.on("POST /api/apply", () => reply(409, { error: "pending (any text)", code: "transaction_pending" }));
    await install();
    await waitFor(() => expect(screen.getByTestId("txn-refused")).toHaveTextContent("上一次宿主事务没有完成，先恢复"));
    expect(within(screen.getByTestId("txn-refused")).getByRole("button", { name: btn("恢复") })).toBeInTheDocument();

    api.on("POST /api/apply", () =>
      reply(422, { error: "x", code: "topology_invalid", issues: [{ code: "rule_unreachable", severity: "error", rule_id: "r1", message: "规则 r1 永远匹配不到" }] }),
    );
    await install();
    await waitFor(() => expect(screen.getByTestId("txn-refused")).toHaveTextContent("拓扑校验没有通过"));
    expect(screen.getByTestId("txn-refused")).toHaveTextContent("规则 r1 永远匹配不到");

    // An old message without a code is not guessed at.
    api.on("POST /api/apply", () => reply(409, { error: "宿主上有旧版 Meridian 数据面" }));
    await install();
    await waitFor(() => expect(screen.queryByTestId("txn-refused")).toBeNull());
  });

  it("does not offer a rollback when there is no previous configuration", async () => {
    fakeApi({
      "GET /api/status": () => panelStatus({ ...changed(), previous_available: false }),
      "GET /api/host": () => host(true),
    });
    renderAt("#/deploy");
    expect(await screen.findByTestId("version-current")).toHaveTextContent("当前");
    expect(screen.queryByTestId("version-previous")).toBeNull();
    expect(screen.queryByRole("button", { name: /回滚/ })).toBeNull();
  });

  it("offers 只写入数据目录 only without a host agent, and lists what an applied-only change would install", async () => {
    const appliedOnly = { state: "changed" as const, installed_version: 3, applied: true, applied_matches: true };
    const api = fakeApi({
      "GET /api/status": () => panelStatus({ ...OK_AGENT, installOver: appliedOnly }),
      "GET /api/host": () => host(true),
      "POST /api/diff": () => ({
        diff: "（没有变化）\n",
        order: [],
        issues: [],
        installed: { files_changed: ["etc/nftables.d/meridian.nft"], files_added: ["etc/wireguard/m09.conf"], interfaces_added: ["m09"] },
      }),
    });
    renderAt("#/deploy");
    const list = await screen.findByTestId("installed-diff");
    expect(list).toHaveTextContent("/etc/nftables.d/meridian.nft");
    expect(list).toHaveTextContent("/etc/wireguard/m09.conf");
    expect(list).toHaveTextContent("没有逐行内容");
    expect(list).toHaveTextContent("m09");
    expect(screen.queryByTestId("apply-only")).toBeNull();
    expect(screen.queryByText(/只写入数据目录/)).toBeNull();

    expect(api.find("POST /api/apply")).toHaveLength(0);
  });

  it("offers 只写入数据目录 without a host agent and says what it does there", async () => {
    const api = fakeApi({
      "GET /api/status": () => panelStatus({ installOver: { state: "not_installed", installed_version: null, applied: false, applied_matches: false } }),
      "POST /api/apply": () => ({ dry_run: false, install: false, wrote: ["a", "b"], order: [], diff: "" }),
    });
    renderAt("#/deploy");
    await userEvent.click(await screen.findByTestId("apply-only"));
    const box = await waitFor(() => {
      const el = document.querySelector<HTMLElement>(".ant-modal-confirm");
      if (!el) throw new Error("no confirm dialog");
      return el;
    });
    expect(box).toHaveTextContent("没有宿主执行通道的场合");
    await confirmModal("只写入");
    await waitFor(() => expect(api.find("POST /api/apply")).toHaveLength(1));
    expect(api.find("POST /api/apply")[0].body).toEqual({ dry_run: false, install: false });
    expect(screen.getByRole("button", { name: /安装到网关/ })).toBeDisabled();
  });

  it("lists the current version and rolls the gateway back from the previous row", async () => {
    const api = fakeApi({
      "GET /api/status": changed,
      "GET /api/host": () => host(true),
      "POST /api/rollback": () => ({ status: "rolled_back", mode: "runtime", host: null }),
    });
    renderAt("#/deploy");
    expect(await screen.findByTestId("version-current")).toHaveTextContent("当前");
    const rb = within(screen.getByTestId("version-previous")).getByRole("button", { name: /回滚/ });
    await waitFor(() => expect(rb).toBeEnabled());
    await userEvent.click(rb);
    await confirmModal("回滚");
    await waitFor(() => expect(api.find("POST /api/rollback")).toHaveLength(1));
    expect(api.find("POST /api/rollback")[0].body).toEqual({ install: true });
  });

  it("uses snapshot-only rollback when nothing is installed and blocks install while the topology does not compile", async () => {
    const api = fakeApi({
      "GET /api/status": () =>
        panelStatus({
          ...OK_AGENT,
          installOver: {
            state: "invalid",
            error: "拓扑校验未通过",
            issues: [{ code: "lan_interface_mismatch", severity: "error", node_id: "gw", message: "网关节点的 lan_interface 和 settings 不一致。" }],
          },
        }),
      "GET /api/host": () => host(false),
      "POST /api/rollback": () => ({ status: "rolled_back", mode: "snapshot" }),
    });
    renderAt("#/deploy");
    expect(await screen.findByText("拓扑现在无法编译，不能安装")).toBeInTheDocument();
    expect(screen.getByText("网关的局域网接口不一致")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /安装到网关/ })).toBeDisabled();
    expect(screen.queryByTestId("version-current")).toBeNull();
    const rb = within(await screen.findByTestId("version-previous")).getByRole("button", { name: /回滚/ });
    await waitFor(() => expect(rb).toBeEnabled());
    await userEvent.click(rb);
    await confirmModal("回滚");
    await waitFor(() => expect(api.find("POST /api/rollback")).toHaveLength(1));
    expect(api.find("POST /api/rollback")[0].body).toEqual({ snapshot_only: true });
  });
});

describe("deploy: remote nodes", () => {
  it("states the order, marks keyless nodes and makes 生成密钥并下发 their main action", async () => {
    const t = topology();
    t.nodes = t.nodes.map((n) => (n.id === "hk-2" ? { ...n, server_id: "srv-1", public_key: "PUBKEY=" } : n.id === "us" ? { ...n, server_id: "srv-2" } : n));
    fakeApi({
      "GET /api/topology": () => t,
      "GET /api/servers": () => ({ servers: [server(), server({ id: "srv-2", name: "美国机" })] }),
    });
    renderAt("#/deploy");
    const remote = await screen.findByTestId("remote-node-us");
    expect(screen.getByTestId("page-help")).toHaveTextContent("单独处理时先「生成密钥并下发」到远端节点，再「安装到网关」");
    expect(screen.getByTestId("keyless-nodes")).toHaveTextContent("还没有密钥");
    expect(within(remote).getByTestId("keyless-us")).toHaveTextContent("第一次下发");
    const main = within(remote).getByRole("button", { name: /生成密钥并下发/ });
    expect(main).toHaveClass("ant-btn-primary");
    const withKey = screen.getByTestId("remote-node-hk-2");
    expect(within(withKey).getByRole("button", { name: /下发/ })).not.toHaveClass("ant-btn-primary");
    expect(within(withKey).queryByTestId("keyless-hk-2")).toBeNull();
  });
});

describe("deploy: install pre-check for remote nodes", () => {
  const setup = (handlers: Parameters<typeof fakeApi>[0] = {}) => {
    const t = topology();
    t.nodes = t.nodes.map((n) => (n.id === "us" ? { ...n, server_id: "srv-2" } : n));
    return fakeApi({
      "GET /api/topology": () => t,
      "GET /api/servers": () => ({ servers: [server({ id: "srv-2", name: "美国机", address: "198.51.100.40" })] }),
      ...handlers,
    });
  };

  it("shows target, planned changes and findings by severity, and refuses to execute with a blocking finding", async () => {
    let next: PreflightRecord = preflightRec();
    const api = setup({ "POST /api/provision/preflight": () => ({ preflight: next }) });
    renderAt("#/deploy");
    const row = await screen.findByTestId("remote-node-us");
    await userEvent.click(within(row).getByRole("button", { name: /生成密钥并下发/ }));
    const report = await screen.findByTestId("preflight-report");
    expect(api.find("POST /api/provision/preflight")[0].body).toEqual({ node_id: "us" });
    // Target identity it is bound to.
    expect(report).toHaveTextContent("root@198.51.100.40:2222");
    expect(report).toHaveTextContent("SHA256:pinnedFINGERPRINTexample");
    expect(report).toHaveTextContent("运维密钥");
    // Findings grouped by severity, with what to do.
    const blocking = screen.getByTestId("preflight-blocking");
    expect(blocking).toHaveTextContent("阻断：必须先处理（1）");
    expect(blocking).toHaveTextContent("Docker");
    expect(blocking).toHaveTextContent("处理办法：这一版面板不会替你改 Docker");
    expect(screen.getByTestId("preflight-warning")).toHaveTextContent("内存很紧");
    expect(screen.getByTestId("preflight-info")).toHaveTextContent("Docker 在运行");
    // Planned changes.
    await userEvent.click(screen.getByText(/拟执行的变更（2 项）/));
    expect(await screen.findByTestId("preflight-changes")).toHaveTextContent("m07");
    // Disabled, with the reason; nothing can override it.
    const exec = screen.getByTestId("preflight-execute");
    expect(exec).toBeDisabled();
    expect(screen.getByTestId("preflight-disabled-reason")).toHaveTextContent("1 个阻断项");
    expect(api.find("POST /api/provision")).toHaveLength(0);

    // Fixed on the server; re-run: clean → execute with the reviewed id.
    next = CLEAN();
    api.on("POST /api/provision", () => ({ dry_run: false, node_id: "us", outcome: "installed", public_key: "NEWPUB=", output: "MERIDIAN_PROVISION_OK\n" }));
    await userEvent.click(screen.getByRole("button", { name: btn("重新预检") }));
    await waitFor(() => expect(screen.getByTestId("preflight-execute")).toBeEnabled());
    expect(screen.getByTestId("preflight-ok")).toHaveTextContent("没有发现冲突");
    await userEvent.click(screen.getByTestId("preflight-execute"));
    await waitFor(() => expect(api.find("POST /api/provision")).toHaveLength(1));
    expect(api.find("POST /api/provision")[0].body).toEqual({ node_id: "us", dry_run: false, generate_keys: true, preflight_id: "pf-2" });
    expect(await screen.findByText("脚本已在服务器上执行完毕")).toBeInTheDocument();
  });

  it("shows the planned DOCKER-USER rules, the sysctl scope, a flushing nftables.service as blocking and WARP clues", async () => {
    const tag = "meridian-fw-28d4deac";
    const rec = preflightRec({
      id: "pf-fw",
      footprint: {
        ...preflightRec().footprint,
        units: ["meridian-node.service", "meridian-fwcompat.service"],
        fw_chain: "DOCKER-USER",
        fw_tag: tag,
        fw_rules: ["-i m07 -o eth0", "-i eth0 -o m07 -m conntrack --ctstate RELATED,ESTABLISHED"],
        sysctl_ifaces: ["eth0", "m07"],
      },
      findings: [
        {
          severity: "blocking",
          code: "nftables_flush_on_reload",
          resource: "nftables.service",
          message: "nftables.service 已启用（开机启动），而且它的 ExecStop 是 nft flush ruleset：stop / restart 时清空整个规则集。",
          action: "面板不改这台主机自己的 nftables 配置。① systemctl disable nftables.service（不要执行 systemctl stop nftables）",
        },
        {
          severity: "blocking",
          code: "wan_interface_missing",
          resource: "eth0",
          message: "「WAN 接口」没填，按默认的 eth0 在这台主机上不存在（IPv4 默认路由在 ens5 上；IPv6 默认路由在 ens5 上）。",
          action: "在拓扑里把这个节点的「WAN 接口」改成主机上带默认路由的网卡（见上），保存后重新预检。",
          fix: { kind: "node", id: "us", field: "wan_interface", label: "节点 us 的「WAN 接口」" },
        },
        { severity: "info", code: "ipv6_ra_kept", resource: "ens5", message: "meridian-up.sh 在打开 IPv6 转发之前把这些接口设为 accept_ra=2（转发打开时也接受通告）：ens5（默认路由）。" },
        {
          severity: "warning",
          code: "forward_policy_drop",
          resource: "ipv4 FORWARD",
          message: `ipv4 转发会被 iptables filter 表 FORWARD 策略 DROP 丢弃。面板会在 iptables 的 DOCKER-USER 链顶部加 2 条 ACCEPT 规则，每条带注释 ${tag}。`,
          action: "确认这些规则可以接受。",
        },
        { severity: "info", code: "forward_coexistence", resource: "DOCKER-USER", message: "转发共存：ipv4：FORWARD 策略 DROP；ipv6：FORWARD 策略 ACCEPT，不加规则。" },
        { severity: "info", code: "cloudflare_warp", resource: "warp-svc", message: "检测到主机级 Cloudflare WARP 客户端：接口 CloudflareWARP。依赖线索：conn 127.0.0.1:40000 xray。Meridian 不碰它，也不会停用它。" },
        { severity: "info", code: "sysctl_scope", resource: "sysctl", message: "内核参数：只改受管接口（eth0 m07）上的 rp_filter / ICMP 重定向，其它接口（Docker、WARP、你自己的）不碰。" },
      ],
      changes: [
        { kind: "firewall", action: "add", resource: `iptables -I DOCKER-USER -i m07 -o eth0 -m comment --comment ${tag} -j ACCEPT`, detail: "ipv4 FORWARD 策略 DROP" },
        { kind: "firewall", action: "add", resource: `iptables -I DOCKER-USER -i eth0 -o m07 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment ${tag} -j ACCEPT`, detail: "ipv4 FORWARD 策略 DROP" },
        { kind: "sysctl", action: "set", resource: "net.ipv4.conf.all.send_redirects", detail: "全局（影响所有接口），当前 1" },
        { kind: "sysctl", action: "set", resource: "rp_filter=2、send_redirects=0、accept_redirects=0", detail: "只在这些接口：eth0 m07（受管隧道接口和拓扑里的网卡）；Docker、WARP 等其它接口不改" },
        { kind: "unit", action: "enable", resource: "meridian-node.service" },
      ],
      counts: { blocking: 2, warning: 1, info: 4 },
    });
    const api = setup({ "POST /api/provision/preflight": () => ({ preflight: rec }) });
    renderAt("#/deploy");
    await userEvent.click(within(await screen.findByTestId("remote-node-us")).getByRole("button", { name: /生成密钥并下发/ }));
    await screen.findByTestId("preflight-report");
    // The host firewall rules are visible without opening the change list.
    const fw = screen.getByTestId("preflight-fwcompat");
    expect(fw).toHaveTextContent("在 DOCKER-USER 里加的放行规则（2 条）");
    expect(fw).toHaveTextContent(`-i m07 -o eth0 -m comment --comment ${tag} -j ACCEPT`);
    expect(fw).toHaveTextContent("RELATED,ESTABLISHED");
    expect(fw).toHaveTextContent("不改 Docker 的链和规则");
    // The flushing nftables.service blocks, with the exact remedy.
    const blocking = screen.getByTestId("preflight-blocking");
    expect(blocking.querySelector('[data-code="nftables_flush_on_reload"]')).not.toBeNull();
    expect(blocking).toHaveTextContent("不要执行 systemctl stop nftables");
    // The WAN interface that does not exist links to the node's field.
    expect(blocking.querySelector('[data-code="wan_interface_missing"]')).not.toBeNull();
    expect(within(blocking).getByTestId("preflight-fix")).toHaveTextContent("去拓扑修改：节点 us 的「WAN 接口」");
    expect(screen.getByTestId("preflight-info")).toHaveTextContent("accept_ra=2");
    // Docker's DROP is a warning (handled), WARP and the sysctl scope are info.
    expect(screen.getByTestId("preflight-warning").querySelector('[data-code="forward_policy_drop"]')).not.toBeNull();
    const info = screen.getByTestId("preflight-info");
    expect(info).toHaveTextContent("127.0.0.1:40000 xray");
    expect(info).toHaveTextContent("ipv6：FORWARD 策略 ACCEPT，不加规则");
    expect(info).toHaveTextContent("只改受管接口（eth0 m07）");
    // Change list: the rules under their own kind, sysctl scope named.
    await userEvent.click(screen.getByText(/拟执行的变更（5 项）/));
    const changes = await screen.findByTestId("preflight-changes");
    expect(changes).toHaveTextContent("转发放行规则（DOCKER-USER）");
    expect(changes).toHaveTextContent("Docker、WARP 等其它接口不改");
    expect(changes).toHaveTextContent("meridian-node.service");
    await userEvent.click(screen.getByText(/受管资源/));
    expect(await screen.findByTestId("preflight-managed-fw")).toHaveTextContent(`DOCKER-USER 里 2 条（注释 ${tag}`);
    expect(screen.getByTestId("preflight-managed-sysctl")).toHaveTextContent("eth0 m07");
    expect(screen.getByTestId("preflight-execute")).toBeDisabled();
    expect(api.find("POST /api/provision")).toHaveLength(0);
  });

  it("keeps the dialog open with the new result when the re-run before execution finds something", async () => {
    const api = setup({
      "POST /api/provision/preflight": () => ({ preflight: CLEAN() }),
      "POST /api/provision": () =>
        reply(409, {
          error: "执行前重新预检出现了审阅时没有的问题（port_in_use）",
          code: "preflight_changed",
          preflight: preflightRec({ id: "pf-3", findings: [{ severity: "blocking", code: "port_in_use", resource: "udp 10.66.7.2:53", message: "出口解析器要绑定 udp 10.66.7.2:53，但已被进程 dnsmasq 占用。", action: "换端口或停用占用者。" }], counts: { blocking: 1, warning: 0, info: 0 } }),
        }),
    });
    renderAt("#/deploy");
    await userEvent.click(within(await screen.findByTestId("remote-node-us")).getByRole("button", { name: /生成密钥并下发/ }));
    await waitFor(() => expect(screen.getByTestId("preflight-execute")).toBeEnabled());
    await userEvent.click(screen.getByTestId("preflight-execute"));
    await waitFor(() => expect(api.find("POST /api/provision")).toHaveLength(1));
    expect(await screen.findByText("执行前重新预检出现了新问题，没有执行")).toBeInTheDocument();
    expect(screen.getByTestId("preflight-blocking")).toHaveTextContent("dnsmasq");
    expect(screen.getByTestId("preflight-execute")).toBeDisabled();
  });

  it("states what a failed first install left behind and never shows success", async () => {
    setup({
      "POST /api/provision/preflight": () => ({ preflight: CLEAN() }),
      "POST /api/provision": () =>
        reply(502, {
          error: "下发失败，补偿没有全部完成",
          code: "provision_failed_leftovers",
          outcome: "left_behind",
          leftovers: ["interface m07"],
          kept: ["package wireguard-tools"],
          output: "MERIDIAN_COMPENSATING exit=1\nMERIDIAN_LEFTOVER interface m07\n",
        }),
    });
    renderAt("#/deploy");
    await userEvent.click(within(await screen.findByTestId("remote-node-us")).getByRole("button", { name: /生成密钥并下发/ }));
    await waitFor(() => expect(screen.getByTestId("preflight-execute")).toBeEnabled());
    await userEvent.click(screen.getByTestId("preflight-execute"));
    expect(await screen.findByTestId("provision-leftovers")).toHaveTextContent("interface m07");
    expect(screen.getByTestId("provision-kept")).toHaveTextContent("package wireguard-tools");
    expect(screen.getByText("下发失败，有残留没有撤掉")).toBeInTheDocument();
    expect(screen.queryByText("脚本已在服务器上执行完毕")).toBeNull();
  });

  it("offers the public key to copy only when the server offers publickey login", async () => {
    setup({
      "POST /api/provision/preflight": () =>
        reply(502, {
          error: "美国机 拒绝了 root 的密钥登录（服务器接受密钥登录，但这份凭据没有通过）",
          code: "auth_failed",
          login_help: {
            code: "auth_failed",
            method: "key",
            user: "root",
            address: "198.51.100.40",
            credential_id: "cred-1",
            credential_name: "运维密钥",
            public_key: PUBKEY,
            offered_methods: ["publickey"],
            publickey_offered: true,
            steps: ["服务器接受公钥登录，但没有接受这把密钥：把下面这把公钥追加到 root@198.51.100.40 的 ~/.ssh/authorized_keys", "然后在服务器页重新「测试连接」"],
          },
        }),
    });
    renderAt("#/deploy");
    await userEvent.click(within(await screen.findByTestId("remote-node-us")).getByRole("button", { name: /生成密钥并下发/ }));
    const help = await screen.findByTestId("login-help");
    expect(help).toHaveTextContent(PUBKEY);
    expect(help).toHaveTextContent("authorized_keys");
    expect(within(help).getByTestId("login-offered")).toHaveTextContent("publickey");
    expect(within(help).getByRole("button", { name: /复制公钥/ })).toBeInTheDocument();
    expect(screen.getByTestId("preflight-execute")).toBeDisabled();
  });

  it("keeps a password-only server on its password: no key, no public key to copy", async () => {
    setup({
      "POST /api/provision/preflight": () =>
        reply(502, {
          error: "美国机 不接受密钥登录，这份凭据没有被尝试（服务器提供的登录方式：password）",
          code: "auth_method_unavailable",
          login_help: {
            code: "auth_method_unavailable",
            method: "key",
            user: "root",
            address: "198.51.100.40",
            credential_id: "cred-1",
            credential_name: "运维密钥",
            offered_methods: ["password"],
            publickey_offered: false,
            steps: [
              "服务器不提供公钥登录（服务器提供的登录方式：password）：在凭据页添加这台服务器的密码凭据，在服务器页把认证方式改为密码并选它；用密码登录，面板的全部功能都可以用",
              "想改用密钥时，先在服务器的 sshd_config 里设 PubkeyAuthentication yes 并重载 sshd，再重新「测试连接」",
            ],
          },
        }),
    });
    renderAt("#/deploy");
    await userEvent.click(within(await screen.findByTestId("remote-node-us")).getByRole("button", { name: /生成密钥并下发/ }));
    const help = await screen.findByTestId("login-help");
    expect(help).toHaveTextContent("密码凭据");
    expect(within(help).getByTestId("login-offered")).toHaveTextContent("password");
    expect(help).not.toHaveTextContent(PUBKEY);
    expect(within(help).queryByRole("button", { name: /复制公钥/ })).toBeNull();
    expect(screen.getByText("服务器不接受这种登录方式")).toBeInTheDocument();
  });

  it("shows platform, architecture, binaries and packages of the install plan", async () => {
    setup({
      "POST /api/provision/preflight": () => ({
        preflight: CLEAN({
          host: { os: "Ubuntu 20.04.6 LTS", arch: "aarch64", kernel: "5.15.0-1045-oracle", mem_total_kb: 450560, mem_avail_kb: 204800, complete: true },
          platform: "Ubuntu 20.04 aarch64",
          binaries: [
            { name: "smartdns", version: "1.2026.08.05-0921", arch: "aarch64", path: "/usr/local/sbin/meridian-smartdns", sha256: "1208c556".padEnd(64, "0"), size: 5301472, action: "install", transfer: true, detail: "经 SSH 传输 5178 MB，主机上校验 SHA-256 后安装" },
            { name: "wstunnel", version: "11.1.0", arch: "aarch64", path: "/usr/local/sbin/meridian-wstunnel", sha256: "a2e4e02b".padEnd(64, "0"), size: 10851944, action: "keep", transfer: false, detail: "主机上已是固定版本（摘要一致），不传输" },
          ],
          package_plan: [
            { package: "wireguard-tools", command: "wg", present: true, installed: "1.0.20200513-1~20.04.2", candidate: "1.0.20200513-1~20.04.2", action: "none" },
            { package: "nftables", command: "nft", present: false, candidate: "0.9.3-2", action: "install" },
          ],
          changes: [{ kind: "binary", action: "install", resource: "/usr/local/sbin/meridian-smartdns", detail: "smartdns 1.2026.08.05-0921（aarch64）" }],
        }),
      }),
    });
    renderAt("#/deploy");
    await userEvent.click(within(await screen.findByTestId("remote-node-us")).getByRole("button", { name: /生成密钥并下发/ }));
    const plan = await screen.findByTestId("preflight-install-plan");
    expect(within(plan).getByTestId("preflight-platform")).toHaveTextContent("Ubuntu 20.04 aarch64");
    expect(plan).toHaveTextContent("aarch64");
    expect(plan).toHaveTextContent("共 440 MB，可用 200 MB");
    const bins = within(plan).getByTestId("preflight-binaries");
    expect(bins.querySelector('[data-binary="smartdns"]')).toHaveTextContent("传输并安装");
    expect(bins.querySelector('[data-binary="smartdns"]')).toHaveTextContent("/usr/local/sbin/meridian-smartdns");
    expect(bins.querySelector('[data-binary="wstunnel"]')).toHaveTextContent("已是固定版本，不传输");
    expect(bins).toHaveTextContent("主机不下载任何东西");
    const pkgs = within(plan).getByTestId("preflight-packages");
    expect(pkgs.querySelector('[data-package="nftables"]')).toHaveTextContent("apt 安装");
    expect(pkgs.querySelector('[data-package="nftables"]')).toHaveTextContent("候选 0.9.3-2");
    expect(pkgs.querySelector('[data-package="wireguard-tools"]')).toHaveTextContent("已有");
    await userEvent.click(screen.getByText(/拟执行的变更（1 项）/));
    expect(await screen.findByTestId("preflight-changes")).toHaveTextContent("面板下发的二进制");
    expect(screen.getByTestId("preflight-execute")).toBeEnabled();
  });

  it("marks an unsupported platform in the plan", async () => {
    setup({
      "POST /api/provision/preflight": () => ({
        preflight: preflightRec({
          platform: "",
          findings: [{ severity: "blocking", code: "os_unsupported", resource: "os", message: "系统是 Ubuntu 22.04，不在支持范围内（只支持 Debian 12 x86_64、Debian 13 x86_64、Ubuntu 20.04 aarch64）。", action: "换用支持的系统。" }],
          counts: { blocking: 1, warning: 0, info: 0 },
        }),
      }),
    });
    renderAt("#/deploy");
    await userEvent.click(within(await screen.findByTestId("remote-node-us")).getByRole("button", { name: /生成密钥并下发/ }));
    expect(await screen.findByTestId("preflight-platform")).toHaveTextContent("不在支持范围");
    expect(screen.getByTestId("preflight-blocking")).toHaveTextContent("Ubuntu 20.04 aarch64");
    expect(screen.getByTestId("preflight-execute")).toBeDisabled();
  });
});

describe("deploy: panel-delivered binaries", () => {
  it("lists the pinned binaries and warns when a verified copy is missing", async () => {
    fakeApi({
      "GET /api/artifacts": () => ({
        artifacts: [
          { name: "smartdns", version: "1.2026.08.05-0921", arch: "aarch64", sha256: "1208c556".padEnd(64, "0"), size: 5301472, source_url: "https://github.com/pymumu/smartdns/releases/download/Release48.4/smartdns-aarch64", host_path: "/usr/local/sbin/meridian-smartdns", available: true },
          { name: "wstunnel", version: "11.1.0", arch: "x86_64", sha256: "62b26d0e".padEnd(64, "0"), size: 13752784, source_url: "https://github.com/erebe/wstunnel/releases/download/v11.1.0/wstunnel_11.1.0_linux_amd64.tar.gz", host_path: "/usr/local/sbin/meridian-wstunnel", available: false, error: "wstunnel-x86_64 的 SHA-256 不对：拒绝使用" },
        ],
      }),
    });
    renderAt("#/deploy");
    const missing = await screen.findByTestId("artifacts-missing");
    expect(missing).toHaveTextContent("1 个二进制没有可用的已校验副本");
    expect(missing).toHaveTextContent("wstunnel 11.1.0（x86_64）");
    expect(screen.getByText(/固定版本：smartdns 1.2026.08.05-0921、wstunnel 11.1.0/)).toBeInTheDocument();
  });
});

describe("deploy: gateway install pre-check", () => {
  it("requires a reviewed pre-check for the first install and sends its id", async () => {
    let next = preflightRec({ kind: "gateway", node_id: "gw", node_name: "网关", target: undefined });
    const api = fakeApi({
      "GET /api/status": () => panelStatus({ ...OK_AGENT, installOver: { state: "not_installed" } }),
      "GET /api/host": () => ({ installed: null, pending: null, agent: { ok: true } }),
      "POST /api/host/preflight": () => ({ preflight: next }),
      "POST /api/apply": () => ({ dry_run: false, install: true, wrote: [], order: [], diff: "" }),
    });
    renderAt("#/deploy");
    const install = await screen.findByRole("button", { name: /安装到网关/ });
    await waitFor(() => expect(install).toBeDisabled());
    expect(screen.getByTestId("install-preflight-reason")).toHaveTextContent("先点「安装前预检」");

    await userEvent.click(screen.getByTestId("host-preflight-run"));
    const report = await screen.findByTestId("host-preflight");
    expect(report).toHaveTextContent("本机（经 meridian-host）");
    expect(report).toHaveTextContent("Docker");
    expect(screen.getByRole("button", { name: /安装到网关/ })).toBeDisabled();
    expect(screen.getByTestId("install-preflight-reason")).toHaveTextContent("1 个阻断项");

    next = CLEAN({ id: "pf-gw", kind: "gateway", node_id: "gw", node_name: "网关", target: undefined });
    await userEvent.click(screen.getByTestId("host-preflight-run"));
    await waitFor(() => expect(screen.getByRole("button", { name: /安装到网关/ })).toBeEnabled());
    await userEvent.click(screen.getByRole("button", { name: /安装到网关/ }));
    await confirmModal("安装");
    await waitFor(() => expect(api.find("POST /api/apply")).toHaveLength(1));
    expect(api.find("POST /api/apply")[0].body).toEqual({ dry_run: false, install: true, preflight_id: "pf-gw" });
  });
});

describe("servers: login help", () => {
  it("shows the panel's public keys to paste when the server only accepts keys", async () => {
    const failed = {
      at: NOW,
      ok: false,
      auth_method: "password" as const,
      code: "auth_method_unavailable",
      error: "台湾出口 不接受密码登录，这份凭据没有被尝试（服务器提供的登录方式：publickey）",
      duration_ms: 120,
    };
    let sv = server({ auth: "password", credential: { id: "cred-pw", name: "运维密码", kind: "password" }, missing: ["connection_test"], ready: false });
    fakeApi({
      "GET /api/servers": () => ({ servers: [sv] }),
      "GET /api/servers/:id": () => ({ server: sv }),
      "POST /api/servers/:id/test": () => {
        sv = { ...sv, last_test: failed };
        return {
          test: failed,
          server: sv,
          login_help: {
            code: "auth_method_unavailable",
            method: "password",
            user: "root",
            address: "192.0.2.10",
            offered_methods: ["publickey"],
            publickey_offered: true,
            key_credentials: [{ id: "cred-key", name: "面板密钥", public_key: PUBKEY }],
            steps: ["服务器只接受密钥登录：把面板里一把密钥的公钥追加到 root@192.0.2.10 的 ~/.ssh/authorized_keys"],
          },
        };
      },
    });
    renderAt("#/servers/srv-1");
    const flow = await screen.findByTestId("server-flow");
    await userEvent.click(within(flow).getByRole("button", { name: btn("测试连接") }));
    const help = await within(flow).findByTestId("login-help");
    expect(help).toHaveTextContent("面板密钥 的公钥");
    expect(help).toHaveTextContent(PUBKEY);
    expect(help).toHaveTextContent("authorized_keys");
    expect(within(help).getByTestId("login-offered")).toHaveTextContent("publickey");
    expect(webStorageDump()).not.toContain(PUBKEY);
  });
});

describe("deploy: deployment records and withdraw", () => {
  it("plans first, requires the typed node id, and lists removed and kept on success", async () => {
    const api = fakeApi({
      "GET /api/topology": () => topology(),
      "GET /api/deployments": () => deploymentsView([deployment(), deployment({ node_id: "old", node_name: "旧出口", in_topology: false, server_id: "srv-9", server_name: "旧机" })]),
      "POST /api/provision/withdraw/plan": () => ({ plan: withdrawPlanOf() }),
      "POST /api/provision/withdraw": () => ({
        node_id: "us",
        mode: "manifest",
        outcome: "withdrawn",
        message: "撤回完成：清单列出的内容已移除并复核",
        removed: ["iface m07", "nft inet meridian"],
        kept: ["package wireguard-tools (installed by Meridian, kept on purpose)"],
        leftovers: [],
      }),
    });
    renderAt("#/deploy");
    const row = await screen.findByTestId("deployment-us");
    expect(row).toHaveTextContent("已安装");
    expect(row).toHaveTextContent("root@198.51.100.40:2222");
    expect(row).toHaveTextContent("SHA256:pinnedFINGERPRINTexample");
    expect(await screen.findByTestId("deployment-orphan-old")).toHaveTextContent("节点已从拓扑删除");
    await userEvent.click(within(row).getByTestId("withdraw-us"));
    const dlg = await screen.findByTestId("withdraw-dialog");
    expect(api.find("POST /api/provision/withdraw/plan")).toHaveLength(0);
    await userEvent.click(screen.getByTestId("withdraw-plan"));
    const plan = await screen.findByTestId("withdraw-plan-view");
    expect(api.find("POST /api/provision/withdraw/plan")[0].body).toEqual({ node_id: "us", mode: "manifest" });
    expect(plan).toHaveTextContent("root@198.51.100.40:2222");
    expect(plan).toHaveTextContent("iface m07 present");
    expect(plan).toHaveTextContent("改动过：会保留");
    expect(dlg).toHaveTextContent("wireguard-tools");
    const run = screen.getByTestId("withdraw-run");
    expect(run).toBeDisabled();
    await userEvent.type(screen.getByLabelText("输入节点 ID 确认"), "u");
    expect(run).toBeDisabled();
    await userEvent.type(screen.getByLabelText("输入节点 ID 确认"), "s");
    await waitFor(() => expect(run).toBeEnabled());
    await userEvent.click(run);
    const res = await screen.findByTestId("withdraw-result");
    expect(api.find("POST /api/provision/withdraw")[0].body).toEqual({ node_id: "us", plan_id: "wp-1", confirm: "us" });
    expect(res).toHaveTextContent("撤回完成");
    expect(within(res).getByTestId("withdraw-removed")).toHaveTextContent("iface m07");
    expect(within(res).getByTestId("withdraw-kept")).toHaveTextContent("wireguard-tools");
    expect(within(res).queryByTestId("withdraw-leftovers")).toBeNull();
  });

  it("shows what could not be removed after a partial withdraw and never shows success", async () => {
    fakeApi({
      "GET /api/topology": () => topology(),
      "GET /api/deployments": () => deploymentsView([deployment()]),
      "POST /api/provision/withdraw/plan": () => ({ plan: withdrawPlanOf() }),
      "POST /api/provision/withdraw": () =>
        reply(502, {
          node_id: "us",
          mode: "manifest",
          outcome: "partial",
          code: "withdraw_partial",
          error: "撤回没有全部完成",
          message: "撤回没有全部完成：下面列出了没能移除的内容",
          removed: ["nft inet meridian"],
          kept: [],
          leftovers: ["file /etc/sysctl.d/99-meridian.conf (changed since the install: kept, check it by hand)"],
        }),
    });
    renderAt("#/deploy");
    await userEvent.click(within(await screen.findByTestId("deployment-us")).getByTestId("withdraw-us"));
    await userEvent.click(await screen.findByTestId("withdraw-plan"));
    await screen.findByTestId("withdraw-plan-view");
    await userEvent.type(screen.getByLabelText("输入节点 ID 确认"), "us");
    await userEvent.click(screen.getByTestId("withdraw-run"));
    const res = await screen.findByTestId("withdraw-result");
    expect(res).toHaveTextContent("没有完成");
    expect(res).not.toHaveTextContent("撤回完成");
    expect(within(res).getByTestId("withdraw-leftovers")).toHaveTextContent("99-meridian.conf");
  });

  it("shows the server's refusal reason when the plan is refused", async () => {
    fakeApi({
      "GET /api/topology": () => topology(),
      "GET /api/deployments": () => deploymentsView([deployment()]),
      "POST /api/provision/withdraw/plan": () =>
        reply(409, { code: "withdraw_refused", reason: "manifest_other", owner: "jp dep-7 srv-2", error: "服务器上的清单属于另一个节点或另一个面板部署：不撤回别人的安装" }),
    });
    renderAt("#/deploy");
    await userEvent.click(within(await screen.findByTestId("deployment-us")).getByTestId("withdraw-us"));
    await userEvent.click(await screen.findByTestId("withdraw-plan"));
    const refused = await screen.findByTestId("withdraw-refused");
    expect(refused).toHaveTextContent("没有改动任何东西");
    expect(refused).toHaveTextContent("manifest_other");
    expect(refused).toHaveTextContent("jp dep-7 srv-2");
    expect(screen.queryByTestId("withdraw-run")).toBeNull();
  });

  it("offers recovery from the preflight finding of an interrupted run", async () => {
    const t = topology();
    t.nodes = t.nodes.map((n) => (n.id === "us" ? { ...n, server_id: "srv-2" } : n));
    const api = fakeApi({
      "GET /api/topology": () => t,
      "GET /api/servers": () => ({ servers: [server({ id: "srv-2", name: "美国机", address: "198.51.100.40" })] }),
      "POST /api/provision/preflight": () => ({
        preflight: preflightRec({
          findings: [{ severity: "blocking", code: "previous_run_incomplete", resource: "/var/lib/meridian/node/journal", message: "上一次下发没有正常结束", action: "在部署页恢复" }],
          counts: { blocking: 1, warning: 0, info: 0 },
        }),
      }),
      "POST /api/provision/withdraw/plan": () => ({ plan: withdrawPlanOf({ mode: "journal", items: ["remove file /etc/wireguard/m07.conf"] }) }),
    });
    renderAt("#/deploy");
    await userEvent.click(within(await screen.findByTestId("remote-node-us")).getByRole("button", { name: /生成密钥并下发/ }));
    const fix = await screen.findByTestId("preflight-recovery");
    await userEvent.click(within(fix).getByRole("button", { name: /恢复中断的下发/ }));
    await userEvent.click(await screen.findByTestId("withdraw-plan"));
    await screen.findByTestId("withdraw-plan-view");
    expect(api.find("POST /api/provision/withdraw/plan")[0].body).toEqual({ node_id: "us", mode: "journal" });
  });

  it("withdraws the gateway down to the guard, stating that LAN forwarding stays blocked, only with gw typed", async () => {
    const api = fakeApi({
      "GET /api/topology": () => topology(),
      "GET /api/status": () => panelStatus({ ...OK_AGENT, installOver: { state: "in_sync", installed_version: 3 } }),
      "GET /api/deployments": () =>
        deploymentsView([], {
          installed: true,
          version: 3,
          plan: { files: ["/etc/wireguard/m02.conf"], interfaces: ["m02"], units: ["meridian-failover.service"], nft_tables: ["inet meridian"], route_tables: [100] },
          kept: ["局域网兜底表 inet meridian_guard、它的开机文件 /etc/nftables.d/meridian-guard.nft 和 meridian-guard.service"],
        }),
      "POST /api/host/withdraw": () => ({ status: "withdrawn", removed: { ...EMPTY_SET, interfaces: ["m02"] }, kept: ["转发保持关闭"], host: null }),
    });
    renderAt("#/deploy");
    expect(await screen.findByTestId("gateway-guard-note")).toHaveTextContent("inet meridian_guard");
    expect(screen.getByTestId("gateway-guard-note")).toHaveTextContent("局域网经这台网关的转发继续被拒绝");
    expect(screen.getByTestId("gateway-kept")).toHaveTextContent("meridian-guard.nft");
    await userEvent.click(screen.getByTestId("gateway-withdraw"));
    const box = await screen.findByTestId("typed-confirm");
    const dialog = box.closest(".ant-modal") as HTMLElement;
    const ok = within(dialog).getByRole("button", { name: btn("撤回网关") });
    expect(ok).toBeDisabled();
    await userEvent.type(within(box).getByLabelText("输入确认内容"), "gw");
    await waitFor(() => expect(ok).toBeEnabled());
    await userEvent.click(ok);
    expect(await screen.findByTestId("gateway-withdraw-result")).toHaveTextContent("已撤回（兜底表保留）");
    expect(api.find("POST /api/host/withdraw")[0].body).toEqual({ confirm: "gw" });
  });
});

describe("deploy: managed sysctl after an install", () => {
  it("shows what was written, what is in effect, what is not and what the old file left in the kernel", async () => {
    fakeApi({
      "GET /api/status": () => panelStatus({ ...OK_AGENT, installOver: { state: "changed", installed_version: 3, applied: true, applied_matches: false } }),
      "GET /api/host": () => ({
        installed: { version: 3, files: 10, interfaces: ["m1"], units: ["meridian.service"], nft_tables: ["inet meridian"], route_tables: [100], dns: true },
        pending: null,
        agent: { ok: true },
      }),
      "POST /api/diff": () => ({ diff: "===== nodes/gw/etc/sysctl.d/99-meridian.conf (changed) =====\n-old\n+new\n", order: [], issues: [] }),
      "POST /api/apply": () => ({
        dry_run: false,
        install: true,
        wrote: [],
        order: [],
        diff: "",
        host: {
          transaction: "txn-9",
          kind: "apply",
          from_version: 3,
          to_version: 4,
          diff: { files_changed: ["etc/sysctl.d/99-meridian.conf"] },
          steps: [{ name: "restart meridian.service（meridian-up.sh）", ok: true }],
          warnings: ["内核参数 net.ipv4.conf.all.rp_filter 现在是 1，/etc/sysctl.d/99-meridian.conf 写的是 2"],
          committed: true,
          sysctl: {
            checked: true,
            problems: 1,
            written: [
              { file: "/etc/sysctl.d/99-meridian.conf", key: "net.ipv4.ip_forward", want: "0", got: "1", state: "boot_only" },
              { file: "/etc/sysctl.d/99-meridian.conf", key: "net.ipv4.conf.all.rp_filter", want: "2", got: "1", state: "differs" },
              { file: "/etc/sysctl.d/99-meridian.conf", key: "net.ipv4.conf.all.send_redirects", want: "0", got: "0", state: "in_effect" },
              { file: "/etc/meridian/forwarding.conf", key: "net.ipv4.ip_forward", want: "1", got: "1", state: "in_effect" },
            ],
            removed: [{ file: "/etc/sysctl.d/99-meridian.conf", key: "net.ipv6.conf.eth7.accept_ra", want: "2", state: "stale" }],
          },
        },
      }),
    });
    renderAt("#/deploy");
    await userEvent.click(await screen.findByRole("button", { name: /安装到网关/ }));
    await confirmModal("安装");
    const rep = await screen.findByTestId("sysctl-report");
    expect(rep).toHaveTextContent("写入 4 项");
    expect(rep).toHaveTextContent("已生效 2");
    expect(rep).toHaveTextContent("未生效 1");
    expect(rep).toHaveTextContent("开机值 1");
    expect(rep).toHaveTextContent("旧文件遗留 1");
    const problems = within(rep).getByTestId("sysctl-problems");
    expect(problems).toHaveTextContent("net.ipv4.conf.all.rp_filter");
    expect(problems).toHaveTextContent("文件 2，内核 1");
    expect(problems).toHaveTextContent("net.ipv6.conf.eth7.accept_ra");
    expect(problems).toHaveTextContent("内核保留到重启");
    expect(problems).not.toHaveTextContent("send_redirects");
  });

  it("does not claim an effect when the kernel was not read", async () => {
    fakeApi({
      "GET /api/status": () => panelStatus({ ...OK_AGENT, installOver: { state: "changed", installed_version: 3, applied: true, applied_matches: false } }),
      "GET /api/host": () => ({ installed: { version: 3, files: 1, interfaces: [], units: [], nft_tables: [], route_tables: [], dns: false }, pending: null, agent: { ok: true } }),
      "POST /api/apply": () => ({
        dry_run: false,
        install: true,
        order: [],
        diff: "",
        host: {
          transaction: "txn-10",
          kind: "apply",
          from_version: 3,
          to_version: 4,
          diff: {},
          committed: true,
          sysctl: { checked: false, reason: "安装写到测试目录，没有读取运行中的内核", problems: 0, written: [{ file: "/etc/sysctl.d/99-meridian.conf", key: "net.ipv4.conf.all.rp_filter", want: "2", state: "not_checked" }] },
        },
      }),
    });
    renderAt("#/deploy");
    await userEvent.click(await screen.findByRole("button", { name: /安装到网关/ }));
    await confirmModal("安装");
    const rep = await screen.findByTestId("sysctl-report");
    expect(screen.getByTestId("page-help")).toHaveTextContent("没有读取运行中的内核");
    expect(rep).not.toHaveTextContent("已生效");
  });
});

// ------------------------------------------------ SSH rate limit, ports (N1) ---

describe("ssh rate limiting", () => {
  afterEach(() => clearCooldowns());

  const limitedMsg =
    "台湾出口（192.0.2.20:22）暂时拒绝来自面板这个来源地址的连接：SSH 握手之前它只回了一行「Not allowed at this time」就断开了。这不是密码、密钥或主机指纹的问题，面板没有尝试登录。";

  it("says the server refuses this source, not the password, and disables test and discovery for the cooldown", async () => {
    const limited = { at: new Date().toISOString(), ok: false, auth_method: "password" as const, code: "ssh_rate_limited", error: limitedMsg, retry_after: 90, duration_ms: 30 };
    let sv = server({ id: "srv-rl", name: "台湾出口", auth: "password", credential: { id: "cred-pw", name: "运维密码", kind: "password" }, missing: ["connection_test"], ready: false });
    const api = fakeApi({
      "GET /api/servers": () => ({ servers: [sv] }),
      "GET /api/servers/:id": () => ({ server: sv }),
      "POST /api/servers/:id/test": () => {
        sv = { ...sv, last_test: limited };
        return { test: limited, server: sv };
      },
    });
    renderAt("#/servers/srv-rl");
    const flow = await screen.findByTestId("server-flow");
    await userEvent.click(within(flow).getByRole("button", { name: btn("测试连接") }));
    expect(await within(flow).findByText("测试失败：服务器暂时拒绝面板的来源地址（限速），稍后再试")).toBeInTheDocument();
    expect(within(flow).getByTestId("rate-limit-note")).toHaveTextContent("不是密码、密钥或主机指纹的问题");
    await waitFor(() => expect(within(flow).getByTestId("test-button")).toBeDisabled());
    expect(within(flow).getByTestId("test-button")).toHaveTextContent(/秒后可重试/);
    expect(within(flow).getByTestId("discover-button")).toBeDisabled();
    expect(within(flow).queryByTestId("login-help")).toBeNull();
    expect(api.find("POST /api/servers/srv-rl/test")).toHaveLength(1);
  });

  it("shows a refused preflight as rate limited and keeps re-run and execute disabled", async () => {
    const t = topology();
    t.nodes = t.nodes.map((n) => (n.id === "us" ? { ...n, server_id: "srv-rl2" } : n));
    const api = fakeApi({
      "GET /api/topology": () => t,
      "GET /api/servers": () => ({ servers: [server({ id: "srv-rl2", name: "美国机", address: "198.51.100.40" })] }),
      "POST /api/provision/preflight": () => reply(503, { error: limitedMsg, code: "ssh_rate_limited", retry_after: 120 }),
    });
    renderAt("#/deploy");
    await userEvent.click(within(await screen.findByTestId("remote-node-us")).getByRole("button", { name: /生成密钥并下发/ }));
    expect(await screen.findByText("服务器暂时拒绝面板的来源地址（限速），稍后再试")).toBeInTheDocument();
    expect(screen.getByTestId("rate-limit-note")).toHaveTextContent(/1[0-2]\d 秒内面板不会再连接/);
    expect(screen.getByTestId("preflight-rerun")).toBeDisabled();
    expect(screen.getByTestId("preflight-rerun")).toHaveTextContent(/秒后可重新预检/);
    expect(screen.getByTestId("preflight-execute")).toBeDisabled();
    expect(screen.queryByTestId("login-help")).toBeNull();
    expect(api.find("POST /api/provision/preflight")).toHaveLength(1);
  });
});
