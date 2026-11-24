import { expect, it } from "vitest";
import { deployPendingNodes, deployTopology } from "./automatic_deploy";
import { fakeApi } from "./testing";

it("stops on a blocked base provisioning preflight before installing the connector", async () => {
  const pending = { link_id: "hub-us" };
  const step = { node_id: "us", node_name: "US", phase: "pending" };
  const run = { id: "deploy-1", state: "active", current: "us", steps: [step] };
  const a = fakeApi({
    "POST /api/mesh/detect": () => ({ detections: [] }),
    "GET /api/mesh": () => ({ plan: { legs: [pending], install_confirm: ["hub"] } }),
    "POST /api/mesh/deploy": () => ({}),
    "GET /api/deploy": () => ({ plan: { steps: [step] }, topology_version: "v1" }),
    "POST /api/deploy/runs": () => ({ run }),
    "POST /api/deploy/runs/deploy-1/preflight": () => ({
      run: { ...run, steps: [{ ...step, phase: "blocked", message: "缺少 SSH 凭据" }] },
    }),
  });
  await expect(deployTopology(true)).rejects.toThrow("US：缺少 SSH 凭据");
  expect(a.find("POST /api/mesh/deploy")).toHaveLength(0);
  expect(a.find("POST /api/deploy/runs/deploy-1/install")).toHaveLength(0);
});

it("uses the confirmed preflight and finalizes the Mesh leg after node installation", async () => {
  const step = { node_id: "us", node_name: "US", phase: "pending" };
  const run = { id: "deploy-1", state: "active", current: "us", steps: [step] };
  const phases: string[] = [];
  const a = fakeApi({
    "POST /api/mesh/detect": () => ({ detections: [] }),
    "GET /api/mesh": () => ({ plan: { legs: [{ link_id: "hub-us" }], install_confirm: ["hub"] } }),
    "POST /api/mesh/deploy": () => {
      phases.push("mesh");
      return {};
    },
    "GET /api/deploy": () => ({ run }),
    "POST /api/deploy/runs/deploy-1/preflight": () => ({
      run: { ...run, steps: [{ ...step, phase: "review", can_install: true, preflight_id: "pf-1" }] },
    }),
    "POST /api/deploy/runs/deploy-1/install": () => {
      phases.push("provision");
      return { run: { ...run, state: "done", steps: [{ ...step, phase: "done" }] } };
    },
  });
  await deployTopology(true);
  expect(a.find("POST /api/deploy/runs/deploy-1/install")[0].body).toEqual({ node_id: "us", preflight_id: "pf-1" });
  expect(a.find("POST /api/mesh/deploy").map(call => call.body)).toEqual([{ confirm_install: true }, {}]);
  expect(phases).toEqual(["provision", "mesh", "provision", "mesh"]);
});

it.each([false, true])("continues with a valid pinned preflight (already reviewed: %s)", async alreadyReviewed => {
  const pending = { node_id: "us7", node_name: "us7", phase: "pending" };
  const reviewed = { ...pending, phase: "review", can_install: true, confirmation_valid: true, preflight_id: "pf-us7" };
  const run = { id: "deploy-1", state: "active", current: "us7" };
  let attempts = 0;
  const a = fakeApi({
    "GET /api/deploy": () => ({ run: { ...run, steps: [alreadyReviewed ? reviewed : pending] } }),
    "POST /api/deploy/runs/deploy-1/preflight": () => ({
      run: { ...run, steps: [++attempts === 1 ? { ...pending, phase: "blocked", can_preflight: true } : reviewed] },
    }),
    "POST /api/deploy/runs/deploy-1/install": () => ({
      run: { ...run, state: "done", steps: [{ ...reviewed, phase: "done" }] },
    }),
  });
  await deployTopology(false);
  expect(attempts).toBe(alreadyReviewed ? 0 : 2);
  expect(a.find("POST /api/deploy/runs/deploy-1/install")[0].body).toEqual({ node_id: "us7", preflight_id: "pf-us7" });
});

it.each([true, false])("rechecks an unknown installation once without reinstalling (adopted: %s)", async adopted => {
  const step = { node_id: "us", node_name: "US", phase: "review", can_install: true, confirmation_valid: true, preflight_id: "pf-1" };
  const run = { id: "deploy-1", state: "active", current: step.node_id };
  const a = fakeApi({
    "GET /api/deploy": () => ({ run: { ...run, steps: [step] } }),
    "POST /api/deploy/runs/deploy-1/install": () => ({
      run: { ...run, state: "stopped", steps: [{ ...step, phase: "unknown", can_preflight: true }] },
    }),
    "POST /api/deploy/runs/deploy-1/preflight": () => ({
      run: {
        ...run,
        state: adopted ? "done" : "active",
        steps: [{ ...step, phase: adopted ? "done" : "review", preflight_id: "pf-2" }],
      },
    }),
  });
  if (adopted) await expect(deployTopology(false)).resolves.toBeUndefined();
  else await expect(deployTopology(false)).rejects.toThrow("自动复核未确认安装完成");
  expect(a.find("POST /api/deploy/runs/deploy-1/preflight")).toHaveLength(1);
  expect(a.find("POST /api/deploy/runs/deploy-1/install")).toHaveLength(1);
});

it("adopts the targeted MTU change and installs against a fresh preflight", async () => {
  const step = { node_id: "us", node_name: "US", phase: "pending" };
  const run = { id: "deploy-1", state: "active", current: step.node_id };
  const change = { link_id: "hub-us", field: "mtu", from: 1420, to: 1360 };
  let replanned = false;
  const a = fakeApi({
    "GET /api/deploy": () => ({ run: { ...run, steps: [step] } }),
    "POST /api/deploy/runs/deploy-1/preflight": () => replanned ? {
      run: { ...run, steps: [{ ...step, phase: "review", can_install: true, preflight_id: "fresh" }] },
    } : {
      run: {
        ...run,
        steps: [{ ...step, phase: "blocked", preflight_id: "old" }],
        preflight: {
          id: "old",
          findings: [{ severity: "blocking", code: "uplink_mtu_too_small", fix: { kind: "link", id: "hub-us", field: "mtu" } }],
        },
      },
    },
    "GET /api/mtu/uplinks": () => ({ proposal: { changes: [change, { ...change, link_id: "unrelated" }] } }),
    "POST /api/mtu/adopt": () => ({ adopted: [change] }),
    "POST /api/deploy/runs/deploy-1/replan": () => {
      replanned = true;
      return { run: { ...run, steps: [step] } };
    },
    "POST /api/deploy/runs/deploy-1/install": () => ({
      run: { ...run, state: "done", steps: [{ ...step, phase: "done" }] },
    }),
  });
  const adopted: unknown[] = [];
  await deployTopology(false, undefined, changes => adopted.push(...changes));
  expect(adopted).toEqual([change]);
  expect(a.find("POST /api/mtu/adopt")[0].body).toEqual({ changes: [change] });
  expect(a.find("POST /api/deploy/runs/deploy-1/install")[0].body).toEqual({ node_id: "us", preflight_id: "fresh" });
});

it("refuses a plan that changed after the confirmation", async () => {
  const a = fakeApi({
    "GET /api/deploy": () => ({ plan: { steps: [{ node_id: "us", node_name: "US", phase: "pending" }, { node_id: "gw", node_name: "网关", phase: "pending" }] }, topology_version: "v2" }),
    "POST /api/deploy/runs": () => ({ run: null }),
  });
  await expect(deployPendingNodes(undefined, undefined, ["gw"])).rejects.toThrow("部署计划在你确认之后变了");
  expect(a.find("POST /api/deploy/runs")).toHaveLength(0);
});

it("never installs a node outside the confirmed list, even in a run opened elsewhere", async () => {
  const run = { id: "r9", state: "active", current: "other", steps: [{ node_id: "other", node_name: "另一台", phase: "pending", can_preflight: true }] };
  const a = fakeApi({
    "GET /api/deploy": () => ({ run }),
    "POST /api/deploy/runs/r9/preflight": () => ({ run }),
  });
  await expect(deployPendingNodes(undefined, undefined, ["gw"])).rejects.toThrow("你确认时没有的节点「另一台」");
  expect(a.find("POST /api/deploy/runs/r9/preflight")).toHaveLength(0);
});

it("verifies a verify-only step the server marks can_verify", async () => {
  const pending = { id: "r8", state: "active", steps: [{ node_id: "hk", node_name: "hk", phase: "pending", verify_only: true, can_verify: true, can_preflight: false }] };
  const a = fakeApi({
    "GET /api/deploy": () => ({ run: pending }),
    "POST /api/deploy/runs/r8/verify": () => ({ run: { ...pending, state: "done", steps: [{ ...pending.steps[0], phase: "done" }] } }),
  });
  await deployPendingNodes(undefined, undefined, []);
  expect(a.find("POST /api/deploy/runs/r8/verify")).toHaveLength(1);
});
