// The first-start gate: a fresh panel (403 setup_required) shows the
// administrator setup form instead of the token screen; finishing it keeps
// the returned token in the tab only. An initialised panel with an
// administrator offers the password login, and the token stays usable.
// Synthetic data only.

import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { fakeApi, renderAt, reply } from "./testing";

afterEach(() => {
  vi.restoreAllMocks();
  sessionStorage.clear();
});

describe("setup gate", () => {
  it("a fresh panel asks for the one-time code and an administrator", async () => {
    let ready = false;
    const api = fakeApi({
      "GET /api/meta": () => (ready ? { phase: 3, features: [] } : reply(403, { error: "面板还没有初始化", code: "setup_required" })),
      "POST /api/setup": (req) => {
        const b = req.body as { code: string; username: string; password: string };
        expect(b).toEqual({ code: "AAAAA-BBBBB", username: "admin", password: "a long enough password" });
        ready = true;
        return { token: "t".repeat(64) };
      },
    });
    renderAt("#/");
    expect(await screen.findByText("首次使用：创建管理员账户")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("初始化码"), { target: { value: "AAAAA-BBBBB" } });
    fireEvent.change(screen.getByLabelText("密码"), { target: { value: "a long enough password" } });
    fireEvent.change(screen.getByLabelText("再输一次"), { target: { value: "a long enough password" } });
    fireEvent.click(screen.getByRole("button", { name: /创建并进入/ }));
    await waitFor(() => expect(api.calls.some((c) => c.method === "POST" && c.path === "/api/setup")).toBe(true));
    await waitFor(() => expect(screen.queryByText("首次使用：创建管理员账户")).toBeNull());
    expect(localStorage.getItem("meridian.token")).toBeNull();
  });

  it("an initialised panel with an administrator offers the password login", async () => {
    let authed = false;
    fakeApi({
      "GET /api/meta": () => (authed ? { phase: 3, features: [] } : reply(401, { error: "需要面板口令" })),
      "GET /api/setup/status": () => ({ state: "ready", admin: true, token_login: true }),
      "POST /api/auth/login": () => {
        authed = true;
        return { token: "u".repeat(64) };
      },
    });
    renderAt("#/");
    expect(await screen.findByText(/管理员登录/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "改用面板口令" })).toBeTruthy();
    fireEvent.change(screen.getByLabelText("用户名"), { target: { value: "admin" } });
    fireEvent.change(screen.getByLabelText("密码"), { target: { value: "whatever password" } });
    fireEvent.click(screen.getByRole("button", { name: /进\s*入/ }));
    await waitFor(() => expect(screen.queryByText(/管理员登录/)).toBeNull());
  });
});
