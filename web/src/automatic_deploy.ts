import * as api from "./api";
import type { DeployPhase, DeployView, MTUChange, Topology } from "./types";

export function applyDeployLinkChanges(topo: Topology, changes: MTUChange[]): Topology {
  return {
    ...topo,
    links: topo.links.map(link => {
      const change = changes.find(c => c.link_id === link.id);
      if (change?.field === "mtu" && change.from === (link.mtu ?? 0)) return { ...link, mtu: change.to };
      if (change?.field === "wg_port" && link.auto_wg_port && change.from === link.wg_port) return { ...link, wg_port: change.to };
      return link;
    }),
  };
}

function withDeployPhase(view: DeployView, nodeId: string, phase: DeployPhase): DeployView {
  if (!view.run) return view;
  return {
    ...view,
    run: {
      ...view.run,
      steps: view.run.steps.map(step => step.node_id === nodeId ? { ...step, phase } : step),
    },
  };
}

/** Use the same pinned, preflight-bound operations as the deployment guide. */
export async function deployPendingNodes(
  onUpdate: (view: DeployView) => void = () => {},
  onLinkChanged?: (changes: MTUChange[]) => void,
  /**
   * The nodes the operator confirmed installing. A new plan that installs
   * others is refused, and no step outside this list is ever installed:
   * a replan or another tab's run that adds a node stops here for a new
   * confirmation (every install goes through this loop, one node at a time).
   */
  confirmed?: string[],
) {
  const repaired = new Set<string>();
  const replacedPorts = new Set<string>();
  const waited = new Set<string>();
  const renewed = new Set<string>();
  const retriedTimeouts = new Set<string>();
  let view = await api.getDeploy();
  const open = view.run?.state === "active" || view.run?.state === "stopped";
  if (!open) {
    if (!view.plan?.steps.length) return;
    if (confirmed && !sameNodes(view.plan.steps.filter((s) => !s.verify_only).map((s) => s.node_id), confirmed)) {
      throw new api.ApiError(409, { error: "部署计划在你确认之后变了：请看过新的计划再部署。" });
    }
    view = await api.startDeploy(view.topology_version);
  }
  onUpdate(view);

  for (;;) {
    const run = view.run;
    if (!run || run.stale || run.in_flight || (run.state === "cancelled" || run.state === "partial")) {
      throw new api.ApiError(409, { error: "部署计划已变化或仍有操作在运行，请在部署页查看。" });
    }
    if (run.state === "done") return;
    const step = run.steps.find(s => s.node_id === run.current);
    if (!step) {
      const verification = run.steps.find(s => s.verify_only && (s.can_verify || s.can_preflight));
      if (verification) {
        view = await api.deployVerify(run.id, { nodeId: verification.node_id });
        onUpdate(view);
        if (view.run?.steps.some(s => s.node_id === verification.node_id && s.phase === "done")) continue;
      }
      throw new api.ApiError(409, { error: run.stop_reason || "部署已暂停，请查看部署页。" });
    }

    if (confirmed && !confirmed.includes(step.node_id)) {
      throw new api.ApiError(409, { error: `部署计划里出现了你确认时没有的节点「${step.node_name || step.node_id}」：已停下，请看过后重新确认。` });
    }

    if (step.wait_seconds) {
      if (step.wait_seconds > 120 || waited.has(step.node_id)) {
        throw new api.ApiError(409, { error: `${step.node_name}：SSH 限流，请在 ${step.wait_seconds} 秒后继续部署。` });
      }
      waited.add(step.node_id);
      await new Promise(resolve => setTimeout(resolve, step.wait_seconds! * 1000));
      const fresh = await api.getDeploy();
      if (fresh.run?.id !== run.id || fresh.run.topology_version !== run.topology_version) {
        throw new api.ApiError(409, { error: "等待 SSH 限流期间部署计划已变化，请在部署页查看。" });
      }
      view = fresh;
      onUpdate(view);
      continue;
    }

    let checked = step;
    if (!step.confirmation_valid || !step.can_install) {
      for (let attempt = 0; attempt < 2; attempt++) {
        onUpdate(withDeployPhase(view, step.node_id, "preflighting"));
        view = await api.deployPreflight(run.id, step.node_id);
        onUpdate(view);
        const updated = view.run?.steps.find(s => s.node_id === step.node_id);
        if (!updated || view.run?.stale || view.run?.in_flight) {
          throw new api.ApiError(409, { error: "部署计划已变化或仍有操作在运行，请在部署页查看。" });
        }
        checked = updated;
        if (checked.wait_seconds) break;
        if (checked.phase !== "blocked" || !checked.can_preflight) break;
      }
    }
    if (checked.phase === "done" || checked.wait_seconds) continue;
    if (checked.code === "timeout" && checked.not_executed && checked.safe_to_retry && checked.can_preflight &&
        !retriedTimeouts.has(step.node_id)) {
      retriedTimeouts.add(step.node_id);
      await new Promise(resolve => setTimeout(resolve, 2000));
      continue;
    }
    if (!checked?.can_install || !checked.preflight_id) {
      const report = view.run?.preflight;
      const findings = checked.phase === "blocked" && report && report.id === checked.preflight_id
        ? report.findings.filter(f => f.severity === "blocking")
        : [];
      if (onLinkChanged && findings.length && findings.every(f =>
        f.code === "uplink_mtu_too_small" && f.fix?.kind === "link" && f.fix.field === "mtu" && !repaired.has(f.fix.id)
      )) {
        const linkIDs = new Set(findings.map(f => f.fix!.id));
        const { proposal } = await api.uplinkMTU();
        const changes = proposal?.changes.filter(change => change.field === "mtu" && linkIDs.has(change.link_id)) ?? [];
        if (!proposal?.error && changes.length === linkIDs.size) {
          const adopted = await api.adoptUplinkMTU(changes, run.id);
          adopted.adopted.forEach(change => repaired.add(change.link_id));
          onLinkChanged(adopted.adopted);
          view = await api.deployReplan(run.id);
          onUpdate(view);
          continue;
        }
      }
      const portFix = findings[0]?.fix;
      if (onLinkChanged && checked.preflight_id && portFix?.kind === "link" &&
          portFix.field === "wg_port" && !replacedPorts.has(portFix.id) &&
          findings.every(f => f.code === "port_in_use" && f.fix?.kind === "link" &&
            f.fix.field === "wg_port" && f.fix.id === portFix.id)) {
        let change: MTUChange | undefined;
        try {
          ({ change } = await api.deployRepairWGPort(run.id, checked.preflight_id));
        } catch (error) {
          if (!(error instanceof api.ApiError) || error.code !== "deploy_port_repair_unavailable") throw error;
        }
        if (change) {
          replacedPorts.add(change.link_id);
          onLinkChanged([change]);
          view = await api.deployReplan(run.id);
          onUpdate(view);
          continue;
        }
      }
      const detail = findings.map(f => [f.message, f.action].filter(Boolean).join(" ")).join("；");
      throw new api.ApiError(409, { error: `${step.node_name}：${detail || checked.message || "预检未通过"}` });
    }

    try {
      onUpdate(withDeployPhase(view, step.node_id, "installing"));
      view = await api.deployInstall(run.id, step.node_id, checked.preflight_id);
    } catch (error) {
      // The server invalidates the review before it reports expiration.
      if (!(error instanceof api.ApiError) || error.code !== "deploy_confirmation_invalid" ||
          !error.message.startsWith("预检结果已过期") || renewed.has(step.node_id)) throw error;
      renewed.add(step.node_id);
      const fresh = await api.getDeploy();
      if (fresh.run?.id !== run.id || fresh.run.topology_version !== run.topology_version ||
          fresh.run.current !== step.node_id) throw error;
      view = fresh;
      onUpdate(view);
      continue;
    }
    onUpdate(view);
    const installed = view.run?.steps.find(s => s.node_id === step.node_id);
    if (installed?.phase === "unknown" && installed.can_preflight && !view.run?.stale && !view.run?.in_flight) {
      // Read the installed state through the existing recovery preflight.
      // Only adopt a matching installation here. A new install needs review.
      view = await api.deployPreflight(run.id, step.node_id);
      onUpdate(view);
      const reconciled = view.run?.steps.find(s => s.node_id === step.node_id);
      if (reconciled?.phase === "done") continue;
      throw new api.ApiError(409, { error: `${step.node_name}：自动复核未确认安装完成，请到部署页查看${reconciled?.message ? `（${reconciled.message}）` : ""}。` });
    }
    if (installed?.phase !== "done") {
      throw new api.ApiError(409, { error: `${step.node_name}：${installed?.message || "下发未完成"}` });
    }
  }
}

export async function deployTopology(
  includeMesh: boolean,
  onUpdate?: (view: DeployView) => void,
  onLinkChanged?: (changes: MTUChange[]) => void,
) {
  if (!includeMesh) return deployPendingNodes(onUpdate, onLinkChanged);

  await api.meshDetect();
  const mesh = await api.getMesh();
  const pending = mesh.plan?.legs?.filter(leg =>
    !mesh.journal?.legs?.some(old => old.link_id === leg.link_id && old.state === "published"),
  ) ?? [];
  if (!pending.length && !mesh.plan_error) return deployPendingNodes(onUpdate, onLinkChanged);
  const issue = mesh.plan?.issues?.[0];
  if (mesh.plan_error || issue) {
    throw new api.ApiError(409, { error: mesh.plan_error || issue?.message || "Mesh 预检未通过" });
  }
  if (mesh.journal && !["published", "withdrawn", "failed"].includes(mesh.journal.state)) {
    throw new api.ApiError(409, { error: "先在 Cloudflare 页处理未完成的 Mesh 撤回或恢复。" });
  }

  await deployPendingNodes(onUpdate);
  if (mesh.plan?.install_confirm?.length) {
    // The first pass installs fail-closed routes required by connector preflight.
    // The connector then supplies the address for the second provisioning pass.
    await api.meshDeploy({ confirm_install: true });
    await deployPendingNodes(onUpdate);
  }
  await api.meshDeploy();
}

function sameNodes(a: string[], b: string[]) {
  return a.length === b.length && [...a].sort().join("\n") === [...b].sort().join("\n");
}
