// Small tests for two honesty fixes (kept out of the big page suites):
// the whole-topology save leaves the independent blocks out and shows a
// refusal with where to change them; the preflight's file list puts what
// changes first, counts the unchanged files and says "nothing changes"
// plainly.

import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import * as api from "./api";
import { PreflightReport } from "./Preflight";
import { fakeApi, reply } from "./testing";
import type { PreflightRecord, Topology } from "./types";
import { ApiErrorAlert } from "./ui";

function doc(): Topology {
  return {
    settings: { draft: false, lan_interface: "eth0", sniff: { enabled: true, ports: [443] } },
    nodes: [{ id: "gw", name: "网关", role: "gateway" }],
    links: [],
    rules: [],
    rule_sets: [{ id: "rs1", name: "规则集", url: "https://rules.example.net/a.list" }],
    service_groups: [{ id: "svc-a", name: "服务 A", target_group: "hk" }],
    mihomo_import: { mapping: { Line: "group:hk" } },
    remote_access: { enabled: false },
  } as unknown as Topology;
}

describe("whole-topology save", () => {
  it("sends the document without the blocks owned by their own endpoints", async () => {
    const fake = fakeApi({ "PUT /api/topology": (req) => ({ topology: req.body, issues: [], paths: [], draft: false }) });
    await api.putTopology(doc(), false);
    const sent = fake.find("PUT /api/topology")[0].body as Record<string, unknown>;
    for (const k of ["service_groups", "rule_sets", "mihomo_import", "remote_access"]) expect(sent).not.toHaveProperty(k);
    expect(sent.settings).not.toHaveProperty("sniff");
    expect((sent.settings as Record<string, unknown>).lan_interface).toBe("eth0");
    expect((sent.nodes as unknown[]).length).toBe(1);
  });

  it("shows a refusal with each resource and where to change it", async () => {
    fakeApi({
      "PUT /api/topology": () =>
        reply(409, {
          error: "整份拓扑保存不能修改独立资源：服务组（service_groups，用 /api/service-groups）。没有保存任何内容。",
          code: "independent_resource_changed",
          fields: [
            { field: "service_groups", resource: "服务组", endpoint: "/api/service-groups", methods: ["PATCH /api/service-groups/{id}"], items: ["svc-a"] },
            { field: "remote_access", resource: "远程接入", endpoint: "/api/remote-access", methods: ["PUT /api/remote-access"], items: ["settings"] },
          ],
        }),
    });
    let err: api.ApiError | null = null;
    try {
      await api.putTopology(doc(), false);
    } catch (e) {
      err = e as api.ApiError;
    }
    expect(err?.code).toBe("independent_resource_changed");
    render(<ApiErrorAlert error={err} />);
    expect(screen.getByText("这些内容要在各自的页面修改，整份拓扑保存没有写入任何内容")).toBeInTheDocument();
    const list = screen.getByTestId("independent-fields");
    const sg = within(list).getByText("服务组").closest("li")!;
    expect(sg).toHaveTextContent("svc-a");
    expect(within(sg).getByRole("link")).toHaveAttribute("href", "#/rules");
    expect(sg).toHaveTextContent("/api/service-groups");
    const ra = list.querySelector('[data-field="remote_access"]')!;
    expect(within(ra as HTMLElement).getByRole("link")).toHaveAttribute("href", "#/remote");
  });
});

/** The change list is collapsed: open it. */
function openChanges() {
  fireEvent.click(screen.getByText(/拟执行的变更/));
  return screen.getByTestId("preflight-changes");
}

function rec(over: Partial<PreflightRecord>): PreflightRecord {
  return {
    id: "pf-1",
    kind: "gateway",
    node_id: "gw",
    node_name: "网关",
    role: "gateway",
    deployment: "dep",
    bundle: "b",
    first_install: false,
    at: "2026-11-14T10:00:00Z",
    expires_at: "2099-01-01T00:00:00Z",
    host: { mem_total_kb: 1, mem_avail_kb: 1, complete: true },
    footprint: { files: [], interfaces: [], listens: [], route_tables: [], nft_tables: [], units: [], packages: [], binaries: [] },
    not_checked: [],
    ownership: "same",
    blocking: false,
    findings: [],
    changes: [],
    counts: { blocking: 0, warning: 0, info: 0 },
    ...over,
  };
}

describe("preflight file list", () => {
  it("lists what changes first and counts the unchanged files", () => {
    render(
      <PreflightReport
        rec={rec({
          changes: [
            { kind: "interface", action: "update", resource: "m01", detail: "已存在、受管" },
            { kind: "file", action: "remove", resource: "/etc/meridian/old.conf", detail: "不再由拓扑生成：安装会删除它" },
            { kind: "file", action: "change", resource: "/etc/smartdns/smartdns.conf", detail: "内容有变化" },
          ],
          file_changes: {
            basis: "installed_manifest",
            added: [],
            changed: ["/etc/smartdns/smartdns.conf"],
            removed: ["/etc/meridian/old.conf"],
            unchanged: ["/etc/a.conf", "/etc/b.conf", "/etc/c.conf"],
            not_compared: [],
            summary: "文件：内容变化 1 个、不再生成 1 个；3 个与已安装的内容相同。",
          },
        })}
      />,
    );
    expect(screen.getByTestId("preflight-file-summary")).toHaveTextContent("内容变化 1 个");
    expect(screen.getByTestId("preflight-file-summary")).toHaveAttribute("data-none", "false");
    const changes = openChanges();
    const items = [...changes.querySelectorAll("[data-change]")].map((e) => e.getAttribute("data-change"));
    // Files first, the changed one before the removed one; other kinds as they were.
    expect(items).toEqual(["file:change", "file:remove", "interface:update"]);
    expect(within(changes).getByTestId("preflight-unchanged")).toHaveTextContent("3 个文件内容不变");
  });

  it("says plainly that no file changes", () => {
    render(
      <PreflightReport
        rec={rec({
          file_changes: {
            basis: "installed_manifest",
            added: [],
            changed: [],
            removed: [],
            unchanged: ["/etc/a.conf"],
            not_compared: [],
            summary: "没有文件变化：这次安装写入的 1 个文件与已安装的内容相同。",
          },
        })}
      />,
    );
    const s = screen.getByTestId("preflight-file-summary");
    expect(s).toHaveAttribute("data-none", "true");
    expect(s).toHaveTextContent("没有文件变化");
    expect(openChanges()).toHaveTextContent("没有要改动的文件");
  });

  it("keeps the old list when there is nothing to compare with", () => {
    render(<PreflightReport rec={rec({ changes: [{ kind: "file", action: "create", resource: "/etc/a.conf" }] })} />);
    expect(screen.queryByTestId("preflight-file-summary")).toBeNull();
    openChanges();
    expect(screen.queryByTestId("preflight-unchanged")).toBeNull();
    expect(document.querySelector('[data-change="file:create"]')).not.toBeNull();
  });
});
