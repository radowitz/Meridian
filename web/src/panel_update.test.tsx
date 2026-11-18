// Upgrade notice (PanelUpdate.tsx): the served build id differs from the one
// the bundle was built with → a non-blocking「面板已更新」notice with a
// 刷新 button; nothing reloads by itself; listeners and timers go away on
// unmount. The chunk-load failure state is in lazy_routes.test.tsx and below.

import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App as AntApp } from "antd";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PageSlot, lazyPage, panelReload } from "./App";
import { POLL_MS, PanelUpdate } from "./PanelUpdate";

function setVisibility(state: "visible" | "hidden") {
  Object.defineProperty(document, "visibilityState", { configurable: true, get: () => state });
  document.dispatchEvent(new Event("visibilitychange"));
}

afterEach(() => {
  vi.useRealTimers();
  Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "visible" });
});

describe("panel update notice", () => {
  it("shows the notice and a refresh button when the served build differs (on becoming visible)", async () => {
    const reload = vi.spyOn(panelReload, "run").mockImplementation(() => {});
    const fetchVersion = vi.fn(async () => "new-build");
    render(<PanelUpdate build="old-build" fetchVersion={fetchVersion} />);
    expect(screen.queryByTestId("panel-update")).toBeNull();
    await act(async () => setVisibility("visible"));
    const notice = await screen.findByTestId("panel-update");
    expect(notice).toHaveTextContent("面板已更新");
    expect(reload).not.toHaveBeenCalled(); // no automatic reload
    await userEvent.click(screen.getByRole("button", { name: /刷\s*新/ }));
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it("stays quiet for the same build, a missing version file, and while hidden", async () => {
    const fetchVersion = vi.fn(async () => "same");
    render(<PanelUpdate build="same" fetchVersion={fetchVersion} />);
    await act(async () => setVisibility("visible"));
    expect(fetchVersion).toHaveBeenCalledTimes(1);
    fetchVersion.mockResolvedValue(null as unknown as string);
    await act(async () => setVisibility("visible"));
    await act(async () => setVisibility("hidden"));
    expect(fetchVersion).toHaveBeenCalledTimes(2); // not fetched while hidden
    expect(screen.queryByTestId("panel-update")).toBeNull();
  });

  it("polls at a low frequency and finds a change", async () => {
    vi.useFakeTimers();
    const fetchVersion = vi.fn(async () => "b2");
    render(<PanelUpdate build="b1" fetchVersion={fetchVersion} />);
    await act(async () => vi.advanceTimersByTime(POLL_MS - 1));
    expect(fetchVersion).not.toHaveBeenCalled();
    await act(async () => vi.advanceTimersByTime(1));
    expect(fetchVersion).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId("panel-update")).toHaveTextContent("面板已更新");
    // Once shown, checking stops.
    await act(async () => vi.advanceTimersByTime(POLL_MS * 3));
    expect(fetchVersion).toHaveBeenCalledTimes(1);
  });

  it("removes its listener and timer on unmount", async () => {
    vi.useFakeTimers();
    const add = vi.spyOn(document, "addEventListener");
    const remove = vi.spyOn(document, "removeEventListener");
    const clear = vi.spyOn(window, "clearInterval");
    const fetchVersion = vi.fn(async () => "b1");
    const { unmount } = render(<PanelUpdate build="b1" fetchVersion={fetchVersion} />);
    const handler = add.mock.calls.find((c) => c[0] === "visibilitychange")![1];
    unmount();
    expect(remove).toHaveBeenCalledWith("visibilitychange", handler);
    expect(clear).toHaveBeenCalled();
    await act(async () => vi.advanceTimersByTime(POLL_MS * 2));
    setVisibility("visible");
    expect(fetchVersion).not.toHaveBeenCalled();
  });

  it("does nothing without a build id (dev server, tests, demo build)", async () => {
    const fetchVersion = vi.fn(async () => "x");
    render(<PanelUpdate build={undefined} fetchVersion={fetchVersion} />);
    await act(async () => setVisibility("visible"));
    expect(fetchVersion).not.toHaveBeenCalled();
  });
});

describe("chunk load failure", () => {
  it("shows 面板已更新，请刷新 and never reloads by itself", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const reload = vi.spyOn(panelReload, "run").mockImplementation(() => {});
    const load = vi.fn(() => Promise.reject(new TypeError("Failed to fetch dynamically imported module: /assets/LeakPage-0000.js")));
    const Broken = lazyPage(load);
    render(
      <AntApp>
        <PageSlot page="leak" component={Broken} />
      </AntApp>,
    );
    const failed = await screen.findByTestId("page-load-failed");
    expect(failed).toHaveTextContent("面板已更新，请刷新");
    expect(screen.getByRole("button", { name: /刷\s*新/ })).toBeInTheDocument();
    await new Promise((r) => setTimeout(r, 50));
    expect(reload).not.toHaveBeenCalled();
    expect(load).toHaveBeenCalledTimes(1); // no retry loop
  });
});
