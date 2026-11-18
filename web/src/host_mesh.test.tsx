// Host-level Mesh detection display: synthetic detections only.

import { render, screen } from "@testing-library/react";
import { App as AntApp } from "antd";
import { describe, expect, it } from "vitest";
import { HostMeshTable, InstallPlans } from "./host_mesh";
import type { HostMeshDetection } from "./types";

const base: HostMeshDetection = {
  node_id: "us",
  checked_at: "2026-11-16T00:00:00Z",
  state: "existing_node",
  reasons: [],
  warp_svc: true,
  warp_cli: true,
  mode: "connector",
  account: "matched",
  mesh_addr: "100.96.0.7",
  iface: "CloudflareWARP",
  docker: false,
  compose: false,
  apt: true,
  systemd: true,
  mem_avail_mb: 65,
  coexist: { ok: true, warp_rules: [], warp_tables: [65743], global_default: false, conflicts: [] },
  reusable: true,
  origin: "existing_host",
  panel_owned: false,
};

describe("HostMeshTable", () => {
  it("shows reuse, conflicts, failures and the install plan", () => {
    const dets: Record<string, HostMeshDetection> = {
      us: base,
      jp: { ...base, node_id: "jp", reusable: false, coexist: { ...base.coexist, ok: false, conflicts: ["Meridian 也用路由表 65743"] } },
      sg: { ...base, node_id: "sg", state: "detect_failed", reasons: ["SSH 检测失败：timeout"] },
      ix: {
        ...base,
        node_id: "ix",
        state: "no_node",
        reasons: ["主机上没有 WARP 客户端"],
        reusable: false,
        origin: "none",
        install: {
          recommended: "host_connector",
          requires_confirmation: true,
          options: [
            {
              kind: "host_connector",
              feasible: true,
              installs: ["cloudflare-warp"],
              needs: ["内存"],
              blockers: [],
              repo: "https://pkg.cloudflareclient.com/",
              key_fingerprint: "0123456789ABCDEF0123456789ABCDEF01234567",
              packages: ["cloudflare-warp"],
              services: ["warp-svc.service"],
              mem_estimate_mb: 160,
              mem_note: "估计值",
            },
          ],
        },
      },
    };
    render(
      <AntApp>
        <HostMeshTable nodes={["us", "jp", "sg", "ix", "hk"].map((id) => ({ id }))} detections={dets} busy={false} onDetect={() => {}} />
      </AntApp>,
    );
    expect(screen.getAllByText("已有 Mesh · 可沿用").length).toBeGreaterThan(0);
    expect(screen.getAllByText("已有 Mesh · 冲突").length).toBeGreaterThan(0);
    expect(screen.getAllByText(/阻断：Meridian 也用路由表 65743/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/SSH 检测失败/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/需安装：主机级 Linux 节点（cloudflare-warp connector）（部署前由你确认）/).length).toBeGreaterThan(0);
    expect(screen.queryByText(/sidecar|Docker/)).toBeNull();
    expect(screen.getAllByText("Mesh 未检测").length).toBeGreaterThan(0);
    expect(screen.getAllByText("主机已有（沿用）").length).toBeGreaterThan(0);
  });

  it("labels panel-installed nodes and legacy sidecar records", () => {
    const dets: Record<string, HostMeshDetection> = {
      ix: { ...base, node_id: "ix", origin: "panel_host", panel_owned: true },
      jp: { ...base, node_id: "jp", state: "no_node", reusable: false, origin: "panel_sidecar", panel_owned: true, reasons: ["旧版"] },
    };
    render(
      <AntApp>
        <HostMeshTable nodes={["ix", "jp"].map((id) => ({ id }))} detections={dets} busy={false} onDetect={() => {}} />
      </AntApp>,
    );
    expect(screen.getAllByText("Mesh · 面板安装").length).toBeGreaterThan(0);
    expect(screen.getAllByText("面板安装").length).toBeGreaterThan(0);
    expect(screen.getAllByText("旧版 sidecar（只能撤回）").length).toBeGreaterThan(0);
  });

  it("shows the full install plan and keeps blockers visible", () => {
    const ix = { ...base, node_id: "ix", state: "no_node" as const, reusable: false, origin: "none" as const, os: "debian", codename: "bookworm", arch: "x86_64", repo_reach: "unreachable",
      install: { requires_confirmation: true, options: [{ kind: "host_connector" as const, feasible: false, installs: [], needs: [], blockers: ["主机连不上官方软件源：停止，不安装"], repo: "https://pkg.cloudflareclient.com/", key_fingerprint: "", packages: ["cloudflare-warp"], services: ["warp-svc.service"], mem_estimate_mb: 160 }] } };
    render(
      <AntApp>
        <InstallPlans nodes={["ix"]} detections={{ ix }} />
      </AntApp>,
    );
    expect(screen.getAllByText(/阻断：主机连不上官方软件源/).length).toBeGreaterThan(0);
    expect(screen.getAllByText("未配置").length).toBeGreaterThan(0);
    expect(screen.getAllByText(/源不可达/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/内存约 160 MB（估计）/).length).toBeGreaterThan(0);
  });
});
