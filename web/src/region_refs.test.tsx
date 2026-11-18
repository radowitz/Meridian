// The 「被 x 处引用」 list of a region group also names rule-sets and the
// rules that reach the group through them (N4); each entry
// links to where it is edited, and the link marks that exact row on the
// rules page. Synthetic names only.

import { render, screen, waitFor, within } from "@testing-library/react";
import { App as AntApp } from "antd";
import { afterEach, describe, expect, it, vi } from "vitest";
import { RuleSetsSection } from "./RulesImport";
import { RouterProvider } from "./state";
import { fakeApi } from "./testing";
import { RefList } from "./ui";

afterEach(() => {
  vi.restoreAllMocks();
  window.location.hash = "";
});

describe("region group referrers", () => {
  it("lists rule-sets and rules reached through them, with links", () => {
    render(
      <RefList
        refs={[
          { kind: "rule", id: "r1", name: "直连规则" },
          { kind: "rule", id: "r2", name: "视频（规则集 视频集）" },
          { kind: "rule_set", id: "rs-video", name: "视频集" },
        ]}
      />,
    );
    const items = screen.getAllByRole("listitem");
    expect(items.map((li) => li.textContent)).toEqual([
      "分流规则 直连规则 r1",
      "分流规则 视频（规则集 视频集） r2",
      "规则集 视频集 rs-video",
    ]);
    expect(within(items[1]).getByRole("link")).toHaveAttribute("href", "#/rules/r2");
    expect(within(items[2]).getByRole("link")).toHaveAttribute("href", "#/rules?rule_set=rs-video");
  });

  const status = { state: "ok" };
  const sets = [
    { rule_set: { id: "rs-a", name: "甲集", url: "https://lists.example.test/a.yaml" }, status, used_by: [], candidates: [] },
    { rule_set: { id: "rs-video", name: "视频集", url: "https://lists.example.test/v.yaml" }, status, used_by: [], candidates: [] },
  ];
  it.each([
    ["#/rules?rule_set=rs-video", "rule_set:rs-video", "rule_set:rs-a"],
  ])("%s marks and scrolls to that row", async (hash, want, other) => {
    window.location.hash = hash;
    fakeApi({ "GET /api/rule-sets": () => ({ rule_sets: sets, formats: [] }) });
    const seen: string[] = [];
    vi.spyOn(Element.prototype, "scrollIntoView").mockImplementation(function (this: Element) {
      seen.push(this.getAttribute("data-focus-row") ?? "");
    });
    const { container } = render(
      <AntApp>
        <RouterProvider>
          <RuleSetsSection dirty={false} onChanged={() => {}} />
        </RouterProvider>
      </AntApp>,
    );
    await waitFor(() => expect(container.querySelector(`[data-focus-row="${want}"]`)).toHaveClass("row-focus"));
    expect(container.querySelector(`[data-focus-row="${other}"]`)).not.toHaveClass("row-focus");
    await waitFor(() => expect(seen).toContain(want));
  });
});
