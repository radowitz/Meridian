// A coalesced automatic install finishes after the save answered: the line
// follows it to the outcome instead of staying on 将自动生效.
import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { fakeApi, reply } from "./testing";
import { act } from "react";
import { RulesApplyLine, RULES_APPLY_POLL_MAX, RULES_APPLY_POLL_MS } from "./ui_base";

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("RulesApplyLine follows a scheduled install", () => {
  it("shows 已生效（vN） once the pending run applied", async () => {
    let pending = true;
    fakeApi({
      "GET /api/rules/auto-apply": () =>
        reply(200, pending
          ? { enabled: true, pending: true, last: { status: "scheduled", at: "t", trigger: "unlock" } }
          : { enabled: true, pending: false, last: { status: "applied", version: 38, at: "t", trigger: "coalesced" } }),
    });
    render(<RulesApplyLine fa={{ status: "scheduled" }} />);
    expect(screen.getByTestId("rules-apply-line").textContent).toBe("将自动生效");
    pending = false;
    await waitFor(() => expect(screen.getByTestId("rules-apply-line").textContent).toBe("已生效（v38）"), { timeout: RULES_APPLY_POLL_MS * 3 });
  });

  it("shows the reason when the pending run was refused", async () => {
    fakeApi({
      "GET /api/rules/auto-apply": () =>
        reply(200, { enabled: true, pending: false, last: { status: "required", reason: "地区组的首选出口由 hk-hub 切换，需要到部署页安装", at: "t", trigger: "coalesced" } }),
    });
    render(<RulesApplyLine fa={{ status: "scheduled" }} />);
    await waitFor(() => expect(screen.getByTestId("rules-apply-line").textContent).toContain("未自动生效：地区组的首选出口"), { timeout: RULES_APPLY_POLL_MS * 3 });
  });

  it("does not poll for a final answer", async () => {
    const api = fakeApi();
    render(<RulesApplyLine fa={{ status: "applied", version: 7 }} />);
    expect(screen.getByTestId("rules-apply-line").textContent).toBe("已生效（v7）");
    await new Promise((r) => setTimeout(r, RULES_APPLY_POLL_MS + 200));
    expect(api.calls.some((c) => c.path === "/api/rules/auto-apply")).toBe(false);
  });

  it("ends on 结果待确认 when the polls run out, and looks again on request", async () => {
    vi.useFakeTimers();
    const last: Record<string, unknown> = { status: "scheduled", at: "t", trigger: "unlock" };
    const api = fakeApi({
      "GET /api/rules/auto-apply": () => reply(200, { enabled: true, pending: true, last }),
    });
    render(<RulesApplyLine fa={{ status: "scheduled" }} />);
    for (let i = 0; i < RULES_APPLY_POLL_MAX + 2; i++) await act(() => vi.advanceTimersByTimeAsync(RULES_APPLY_POLL_MS));
    const n = api.calls.filter((c) => c.path === "/api/rules/auto-apply").length;
    expect(n).toBe(RULES_APPLY_POLL_MAX);
    expect(screen.getByTestId("rules-apply-line").textContent).toContain("结果待确认");
    expect(screen.getByRole("link", { name: "去部署" })).toBeTruthy();
    await act(() => vi.advanceTimersByTimeAsync(RULES_APPLY_POLL_MS * 5));
    expect(api.calls.filter((c) => c.path === "/api/rules/auto-apply").length).toBe(n);
    const after = { status: "required", reason: "面板重启，合并的自动生效没有执行，需要到部署页安装", at: "t", trigger: "unlock", interrupted: true };
    const again = screen.getByRole("button", { name: "重新查看" });
    // pending false now: the panel restarted and marked the record interrupted
    api.on("GET /api/rules/auto-apply", () => reply(200, { enabled: true, pending: false, last: after }));
    await act(async () => {
      again.click();
    });
    for (let i = 0; i < 5; i++) await act(() => vi.advanceTimersByTimeAsync(50));
    expect(screen.getByTestId("rules-apply-line").textContent).toContain("未自动生效：面板重启");
  });

  it("stops polling on unmount and ignores a late answer", async () => {
    vi.useFakeTimers();
    let release: (() => void) | undefined;
    const api = fakeApi({
      "GET /api/rules/auto-apply": () =>
        new Promise((r) => {
          release = () => r(reply(200, { enabled: true, pending: false, last: { status: "applied", version: 9, at: "t", trigger: "coalesced" } }) as never);
        }),
    });
    const v = render(<RulesApplyLine fa={{ status: "scheduled" }} />);
    await act(() => vi.advanceTimersByTimeAsync(RULES_APPLY_POLL_MS));
    v.unmount();
    release?.();
    await act(() => vi.advanceTimersByTimeAsync(RULES_APPLY_POLL_MS * 4));
    expect(api.calls.filter((c) => c.path === "/api/rules/auto-apply").length).toBe(1);
  });

  it("a newer save's answer replaces an older scheduled line; the old poll's late answer is dropped", async () => {
    vi.useFakeTimers();
    let release: (() => void) | undefined;
    fakeApi({
      "GET /api/rules/auto-apply": () =>
        new Promise((r) => {
          release = () => r(reply(200, { enabled: true, pending: false, last: { status: "applied", version: 3, at: "t", trigger: "coalesced" } }) as never);
        }),
    });
    const v = render(<RulesApplyLine fa={{ status: "scheduled" }} />);
    await act(() => vi.advanceTimersByTimeAsync(RULES_APPLY_POLL_MS));
    v.rerender(<RulesApplyLine fa={{ status: "required", reason: "新保存的原因" }} applyRequired />);
    await act(async () => {
      release?.();
      await vi.advanceTimersByTimeAsync(10);
    });
    expect(screen.getByTestId("rules-apply-line").textContent).toContain("未自动生效：新保存的原因");
  });
});
