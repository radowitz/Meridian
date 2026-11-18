// The keyword capability note: the rule list's per-rule note and the
// drawer's help show the backend's text for the sniff state (off, on,
// saved but not in effect); with the text unreadable the drawer says only
// the conservative claim. Small renders: one rule, one drawer.

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { KEYWORD_HELP_UNREAD, RuleDrawer } from "./RulesPage";
import { fakeApi, renderAt } from "./testing";
import type { Rule, Topology } from "./types";

afterEach(() => {
  vi.restoreAllMocks();
  sessionStorage.clear();
  localStorage.clear();
});

const NOTES = {
  off: "网关上只匹配已下载名单里含这个词的域名（SmartDNS 不能按子串匹配）",
  on: "嗅探已生效：TCP 接管端口上读得到名字的连接按子串匹配；UDP（含 QUIC）、其它端口和读不到名字的连接仍只匹配已下载名单里含这个词的域名（近似）",
  pending: "嗅探安装并正常运行后，TCP 接管端口上读得到名字的连接才按子串匹配；现在仍只匹配已下载名单里含这个词的域名（近似）",
} as const;

const KW: Rule = {
  id: "kw",
  name: "kw",
  manual: true,
  priority: 10,
  enabled: true,
  overridden: false,
  match_type: "keyword",
  match_value: "vendor",
  target_group: "hk",
  require_residential: false,
  require_v6: false,
};

function topo(): Topology {
  return {
    settings: { draft: false, default_group: "hk", lan_interface: "eth0" } as Topology["settings"],
    nodes: [],
    links: [],
    rules_ordered: true,
    rules: [KW],
    rule_sets: [],
    region_groups: [{ id: "hk", name: "香港", region: "hk", members: [], mode: "auto" }],
  } as unknown as Topology;
}

describe("keyword rules: the capability note follows the sniff state", () => {
  it.each(["off", "on", "pending"] as const)("rule list note, sniff %s", async (state) => {
    fakeApi({
      "GET /api/topology": () => topo(),
      "GET /api/rules/analysis": () => ({
        rules: [{ rule_id: "kw", entries: 1, shadowed: 0, fully_shadowed: false, keywords: 1, keyword_note: NOTES[state] }],
        keyword_state: state,
        keyword_note: NOTES[state],
        shared_address: "",
      }),
      "GET /api/rule-sets": () => ({ rule_sets: [], formats: [] }),
    });
    renderAt("#/rules");
    fireEvent.click(await screen.findByTestId("rule-hints-kw"));
    await waitFor(() => expect(screen.getByTestId("rule-shadow-kw")).toHaveTextContent(NOTES[state]));
    if (state === "off") expect(screen.getByTestId("rule-shadow-kw")).not.toHaveTextContent("嗅探");
  });

  it.each([
    ["off", NOTES.off],
    ["on", NOTES.on],
    ["pending", NOTES.pending],
    ["unread", KEYWORD_HELP_UNREAD],
  ] as const)("drawer help, %s", async (_state, text) => {
    render(<RuleDrawer open rule={KW} topo={topo()} keywordNote={_state === "unread" ? undefined : text} onClose={() => undefined} onApply={() => undefined} />);
    expect(await screen.findByText(text)).toBeInTheDocument();
  });
});
