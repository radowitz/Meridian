import * as api from "./api";
import type { DeployView } from "./types";

/** Use the same pinned, preflight-bound operations as the deployment guide. */
export async function deployPendingNodes(onUpdate: (view: DeployView) => void = () => {}) {
  let view = await api.getDeploy();
  const open = view.run?.state === "active" || view.run?.state === "stopped";
  if (!open) {
    if (!view.plan?.steps.length) return;
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
      const verification = run.steps.find(s => s.verify_only && s.can_preflight);
      if (verification) {
        view = await api.deployVerify(run.id, { nodeId: verification.node_id });
        onUpdate(view);
        if (view.run?.steps.some(s => s.node_id === verification.node_id && s.phase === "done")) continue;
      }
      throw new api.ApiError(409, { error: run.stop_reason || "部署已暂停，请查看部署页。" });
    }

    let checked = step;
    if (!step.confirmation_valid || !step.can_install) {
      for (let attempt = 0; attempt < 2; attempt++) {
        view = await api.deployPreflight(run.id, step.node_id);
        onUpdate(view);
        const updated = view.run?.steps.find(s => s.node_id === step.node_id);
        if (!updated || view.run?.stale || view.run?.in_flight) {
          throw new api.ApiError(409, { error: "部署计划已变化或仍有操作在运行，请在部署页查看。" });
        }
        checked = updated;
        if (checked.phase !== "blocked" || !checked.can_preflight) break;
      }
    }
    if (checked?.phase === "done") continue;
    if (!checked?.can_install || !checked.preflight_id) {
      const report = view.run?.preflight;
      const findings = checked.phase === "blocked" && report && report.id === checked.preflight_id
        ? report.findings.filter(f => f.severity === "blocking").map(f => [f.message, f.action].filter(Boolean).join(" "))
        : [];
      throw new api.ApiError(409, { error: `${step.node_name}：${findings.join("；") || checked.message || "预检未通过"}` });
    }

    view = await api.deployInstall(run.id, step.node_id, checked.preflight_id);
    onUpdate(view);
    const installed = view.run?.steps.find(s => s.node_id === step.node_id);
    if (installed?.phase !== "done") {
      throw new api.ApiError(409, { error: `${step.node_name}：${installed?.message || "下发未完成"}` });
    }
  }
}

export async function deployTopology(includeMesh: boolean) {
  if (!includeMesh) return deployPendingNodes();

  await api.meshDetect();
  const mesh = await api.getMesh();
  const pending = mesh.plan?.legs?.filter(leg =>
    !mesh.journal?.legs?.some(old => old.link_id === leg.link_id && old.state === "published"),
  ) ?? [];
  if (!pending.length && !mesh.plan_error) return deployPendingNodes();
  const issue = mesh.plan?.issues?.[0];
  if (mesh.plan_error || issue) {
    throw new api.ApiError(409, { error: mesh.plan_error || issue?.message || "Mesh 预检未通过" });
  }
  if (mesh.journal && !["published", "withdrawn", "failed"].includes(mesh.journal.state)) {
    throw new api.ApiError(409, { error: "先在 Cloudflare 页处理未完成的 Mesh 撤回或恢复。" });
  }

  await deployPendingNodes();
  if (mesh.plan?.install_confirm?.length) {
    // The first pass installs fail-closed routes required by connector preflight.
    // The connector then supplies the address for the second provisioning pass.
    await api.meshDeploy({ confirm_install: true });
    await deployPendingNodes();
  }
  await api.meshDeploy();
}
