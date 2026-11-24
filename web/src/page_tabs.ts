// Pages shown as tabs of one menu entry: each keeps its own address (deep
// links, ?section= and the jumps between pages are unchanged); the menu has
// one entry (the first tab's address) and the page header shows the group's
// title with the tabs.

export interface PageTabGroup {
  title: string;
  tabs: { key: string; label: string }[];
}

export const PAGE_TABS: PageTabGroup[] = [
  {
    title: "解析与名单",
    tabs: [
      { key: "dns", label: "解析设置" },
      { key: "lists", label: "名单" },
    ],
  },
  {
    title: "日志",
    tabs: [
      { key: "conn-log", label: "连接日志" },
      { key: "dns-log", label: "解析日志" },
      { key: "link-log", label: "链路日志" },
    ],
  },
  {
    title: "服务器与密钥",
    tabs: [
      { key: "servers", label: "服务器" },
      { key: "keys", label: "密钥" },
    ],
  },
];

/** The tab group a page belongs to (undefined: a page of its own). */
export function tabGroupOf(page: string): PageTabGroup | undefined {
  return PAGE_TABS.find((g) => g.tabs.some((t) => t.key === page));
}

/** The menu entry a page selects: the first tab of its group, or the page itself. */
export function menuKeyOf(page: string): string {
  return tabGroupOf(page)?.tabs[0].key ?? page;
}
