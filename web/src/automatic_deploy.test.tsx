import { expect, it } from "vitest";
import { deployTopology } from "./automatic_deploy";
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
