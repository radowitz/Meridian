// What jsdom can verify of the shared layout pieces in ui.tsx: structure,
// class names, tooltips for cut text, the collapsible explanation and its
// always-visible safety variant, header actions and keyboard access. Real
// widths, wrapping and sticky behaviour are NOT provable here; they are the
// browser checks listed in docs/ui-layout.md.

import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  BREAKPOINTS,
  CommandBlock,
  DataTable,
  EllipsisText,
  Explain,
  Facts,
  GridCell,
  KV,
  Mono,
  PageHeader,
  SafetyNotice,
  StatusReason,
  StickyBar,
  MATRIX_LAYOUT,
  TABLE_BUDGET,
  TABLE_SCROLL,
  WideGrid,
  joinReasons,
  type DataColumn,
} from "./ui";
import { phoneWidth } from "./testing";

const LONG = "synthetic-identifier-" + "x".repeat(120);

afterEach(() => vi.restoreAllMocks());

describe("key/value rows", () => {
  it("Facts keeps label and value in their own cells and can stack a row", () => {
    const { container } = render(<Facts items={[["承载枢纽", LONG], ["说明", "短", "stacked"]]} labelMin={120} />);
    const dl = container.querySelector("dl.facts") as HTMLElement;
    expect(dl.style.getPropertyValue("--m-fact-label")).toBe("120px");
    const rows = dl.querySelectorAll(".fact");
    expect(rows).toHaveLength(2);
    expect(rows[0].querySelector("dt")).toHaveTextContent("承载枢纽");
    expect(rows[0].querySelector("dd")).toHaveTextContent(LONG);
    expect(rows[0]).not.toHaveClass("fact-stacked");
    expect(rows[1]).toHaveClass("fact-stacked");
  });

  it("Facts can stack every row", () => {
    const { container } = render(<Facts stacked items={[["a", "b"]]} />);
    expect(container.querySelector("dl")).toHaveClass("facts", "facts-stacked");
  });

  it("KV has a label that does not shrink and a value cell of its own", () => {
    const { container } = render(
      <>
        <KV label="承载枢纽">{LONG}</KV>
        <KV label="探测通道" stacked>
          x
        </KV>
      </>,
    );
    const rows = container.querySelectorAll(".kv");
    expect(rows[0].querySelector(".kv-label")).toHaveTextContent("承载枢纽");
    expect(rows[0].querySelector(".kv-value")).toHaveTextContent(LONG);
    expect(rows[0]).not.toHaveClass("kv-stacked");
    expect(rows[1]).toHaveClass("kv-stacked");
  });
});

describe("long technical text", () => {
  it("Mono is monospace inline text", () => {
    const { container } = render(<Mono>{LONG}</Mono>);
    expect(container.querySelector(".mono")).toHaveTextContent(LONG);
  });

  it("Mono renders a dash for nothing", () => {
    render(<Mono>{null}</Mono>);
    expect(screen.getByText("—")).toBeInTheDocument();
  });

  it("a command block scrolls in its own box, is keyboard focusable and names itself", async () => {
    const { container } = render(<CommandBlock label="读取口令的命令">docker compose exec app cat /data/token</CommandBlock>);
    const box = container.querySelector(".mono-block-scroll") as HTMLElement;
    expect(box).toBeInTheDocument();
    const code = within(box).getByRole("group", { name: "读取口令的命令" });
    expect(code).toHaveClass("mono-scroll");
    expect(code.tagName).toBe("CODE");
    await userEvent.tab();
    expect(code).toHaveFocus();
    expect(within(box).getByRole("button", { name: /复制/ })).toBeInTheDocument();
  });

  it("a plain block wraps (no scroll box)", () => {
    const { container } = render(<Mono block>{LONG}</Mono>);
    expect(container.querySelector(".mono-block")).not.toHaveClass("mono-block-scroll");
    expect(container.querySelector("code")).not.toHaveAttribute("tabindex");
  });

  it("cut text is reachable with the keyboard and shows the full text", async () => {
    render(<EllipsisText text={LONG} mono />);
    const el = screen.getByText(LONG);
    expect(el).toHaveClass("ellipsis-text", "mono");
    expect(el).toHaveAttribute("tabindex", "0");
    await userEvent.tab();
    expect(el).toHaveFocus();
    expect(await screen.findByRole("tooltip")).toHaveTextContent(LONG);
  });

  it("Mono ellipsis uses the same cut-with-tooltip text", async () => {
    render(<Mono ellipsis>{LONG}</Mono>);
    await userEvent.hover(screen.getByText(LONG));
    expect(await screen.findByRole("tooltip")).toHaveTextContent(LONG);
  });
});

describe("explanations", () => {
  it("shows the summary and keeps the rest collapsed until asked", async () => {
    render(
      <Explain summary="一句话说明">
        <p>很长的补充说明</p>
      </Explain>,
    );
    const toggle = screen.getByRole("button", { name: "了解更多" });
    expect(screen.getByText("一句话说明")).toBeVisible();
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    const more = document.getElementById(toggle.getAttribute("aria-controls")!)!;
    expect(more).toHaveAttribute("hidden");
    expect(screen.getByText("很长的补充说明", { selector: "p" })).not.toBeVisible();
    await userEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(toggle).toHaveTextContent("收起");
    expect(more).not.toHaveAttribute("hidden");
    expect(screen.getByText("很长的补充说明")).toBeVisible();
    await userEvent.click(toggle);
    expect(more).toHaveAttribute("hidden");
  });

  it("toggles from the keyboard", async () => {
    render(<Explain summary="s">rest</Explain>);
    await userEvent.tab();
    expect(screen.getByRole("button", { name: "了解更多" })).toHaveFocus();
    await userEvent.keyboard("{Enter}");
    expect(screen.getByRole("button", { name: "收起" })).toHaveAttribute("aria-expanded", "true");
  });

  it("has no toggle when there is nothing more", () => {
    render(<Explain summary="只有一句" />);
    expect(screen.queryByRole("button")).toBeNull();
  });

  it("popover mode puts the rest in a popover", async () => {
    render(
      <Explain summary="s" mode="popover">
        弹出的说明
      </Explain>,
    );
    expect(screen.queryByText("弹出的说明")).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "了解更多" }));
    expect(await screen.findByText("弹出的说明")).toBeInTheDocument();
  });

  it("a safety notice is always visible and cannot be collapsed", () => {
    render(
      <>
        <SafetyNotice kind="unverified" title="数据面未验证">
          还没有在真实设备上验证。
        </SafetyNotice>
        <SafetyNotice kind="failclosed">服务停止时连接失败，不会绕出去。</SafetyNotice>
        <SafetyNotice kind="signoff">需要人工签收。</SafetyNotice>
      </>,
    );
    const notes = screen.getAllByRole("note");
    expect(notes.map((n) => n.getAttribute("data-safety"))).toEqual(["unverified", "failclosed", "signoff"]);
    for (const n of notes) {
      expect(n).toBeVisible();
      expect(n.querySelector("button")).toBeNull();
      expect(n.querySelector("[hidden]")).toBeNull();
      expect(n.querySelector("[aria-expanded]")).toBeNull();
    }
    expect(screen.getByText("还没有在真实设备上验证。")).toBeVisible();
    expect(within(notes[1]).getByText("失败关闭")).toBeInTheDocument();
  });
});

describe("status with a reason", () => {
  it("joins reasons without repeating one", () => {
    expect(joinReasons(["读取失败", "读取失败", "  ", null, "读取失败：超时"])).toBe("读取失败：超时");
    expect(joinReasons(["a", "b"])).toBe("a；b");
    expect(joinReasons("正常", "正常")).toBe("");
    expect(joinReasons(undefined)).toBe("");
  });

  it("is a short tag plus one line of reason", () => {
    const { container } = render(<StatusReason kind="attention" label="需要处理" reason={["枢纽未回报", "枢纽未回报"]} />);
    const block = container.querySelector(".status-reason") as HTMLElement;
    expect(block).toHaveAttribute("data-status", "attention");
    expect(within(block).getByText("需要处理")).toBeInTheDocument();
    expect(block.querySelectorAll(".status-reason-text")).toHaveLength(1);
    expect(block.querySelector(".status-reason-text")).toHaveTextContent(/^枢纽未回报$/);
  });

  it("wraps when asked and shows only the tag without a reason", () => {
    const { container, rerender } = render(<StatusReason kind="failed" reason="很长的原因" wrap />);
    expect(container.querySelector(".status-reason-text.wrap")).toBeInTheDocument();
    rerender(<StatusReason kind="ok" />);
    expect(container.querySelector(".status-reason-text")).toBeNull();
  });
});

describe("page header and sticky bar", () => {
  it("puts the actions in a wrapping area of their own", () => {
    render(<PageHeader title="规则" description="d" extra={<button type="button">保存</button>} />);
    const actions = screen.getByTestId("page-header-actions");
    expect(actions).toHaveClass("page-header-extra");
    expect(within(actions).getByRole("button", { name: "保存" })).toBeInTheDocument();
    expect(actions.parentElement).toHaveClass("page-header");
    expect(screen.getByRole("heading", { name: "规则" }).parentElement).toHaveClass("page-header-text");
  });

  it("has no action area without actions", () => {
    render(<PageHeader title="规则" />);
    expect(screen.queryByTestId("page-header-actions")).toBeNull();
  });

  it("collapses secondary actions into a menu", async () => {
    const onClick = vi.fn();
    render(<PageHeader title="规则" menu={[{ key: "imp", label: "导入", onClick }]} />);
    const btn = screen.getByRole("button", { name: "更多操作" });
    expect(screen.queryByText("导入")).toBeNull();
    await userEvent.click(btn);
    await userEvent.click(await screen.findByText("导入"));
    expect(onClick).toHaveBeenCalledOnce();
  });

  it("StickyBar is the shared sticky area", () => {
    const { container } = render(<StickyBar className="doc-bar">x</StickyBar>);
    expect(container.firstElementChild).toHaveClass("sticky-bar", "doc-bar");
  });
});

interface Row {
  id: string;
  name: string;
  path: string;
  note: string;
}
const rows: Row[] = [{ id: "r1", name: "规则一", path: LONG, note: "次要说明" }];
const cols: DataColumn<Row>[] = [
  { title: "ID", dataIndex: "id", kind: "fixed", width: 80 },
  { title: "名称", dataIndex: "name", kind: "flex", width: 200 },
  { title: "路径", dataIndex: "path", kind: "ellipsis", width: 180, mono: true },
  { title: "操作", kind: "actions", width: 90, render: () => <button type="button">编辑</button> },
];

function mockOverflow(scrollWidth: number, clientWidth: number) {
  vi.spyOn(HTMLElement.prototype, "scrollWidth", "get").mockReturnValue(scrollWidth);
  vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockReturnValue(clientWidth);
}

describe("DataTable", () => {
  it("gives every column its width class, and pins only the action column", () => {
    const { container } = render(<DataTable<Row> rowKey="id" columns={cols} dataSource={rows} />);
    expect(container.querySelector("th.col-fixed")).toHaveTextContent("ID");
    expect(container.querySelector("th.col-flex")).toHaveTextContent("名称");
    expect(container.querySelector("th.col-ellipsis")).toHaveTextContent("路径");
    expect(container.querySelector("th.col-actions")).toHaveTextContent("操作");
    expect(container.querySelectorAll(".ant-table-cell-fix-right").length).toBeGreaterThan(0);
    expect(container.querySelector("td.col-ellipsis")?.closest(".data-table")).toBeInTheDocument();
    // Explicit widths: the colgroup carries them (no max-content).
    const widths = Array.from(container.querySelectorAll("colgroup col")).map((c) => (c as HTMLElement).style.width);
    expect(widths).toEqual(expect.arrayContaining(["80px", "180px", "90px"]));
    const table = container.querySelector("table") as HTMLElement;
    expect(table.style.width).not.toBe("max-content");
  });

  it("keeps the whole text of a cut cell reachable by keyboard and hover", async () => {
    render(<DataTable<Row> rowKey="id" columns={cols} dataSource={rows} />);
    const cell = screen.getByText(LONG);
    expect(cell).toHaveClass("ellipsis-text", "mono");
    expect(cell).toHaveAttribute("tabindex", "0");
    await userEvent.hover(cell);
    expect(await screen.findByRole("tooltip")).toHaveTextContent(LONG);
  });

  it("moves secondary fields into an expandable row", async () => {
    render(<DataTable<Row> rowKey="id" columns={cols} dataSource={rows} secondary={(r) => <span>{r.note}</span>} />);
    expect(screen.queryByText("次要说明")).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: /展开|expand/i }));
    expect(await screen.findByText("次要说明")).toBeInTheDocument();
    expect(document.querySelector(".row-secondary")).toBeInTheDocument();
  });

  it("paginates long lists and leaves short ones whole", () => {
    const many = Array.from({ length: 45 }, (_, i) => ({ id: `r${i}`, name: `n${i}`, path: "p", note: "" }));
    const { container, unmount } = render(<DataTable<Row> rowKey="id" columns={cols} dataSource={many} pageSize={20} />);
    expect(container.querySelectorAll("tbody tr.ant-table-row")).toHaveLength(20);
    expect(container.querySelector(".ant-pagination")).toBeInTheDocument();
    unmount();
    const { container: c2 } = render(<DataTable<Row> rowKey="id" columns={cols} dataSource={rows} />);
    expect(c2.querySelector(".ant-pagination")).toBeNull();
  });

  it("shows a scroll hint only when the table scrolls inside its box", async () => {
    const { container, unmount } = render(<DataTable<Row> rowKey="id" columns={cols} dataSource={rows} />);
    expect(container.querySelector(".scroll-hint")).toBeNull();
    expect(container.querySelector(".data-table-wrap")).toHaveAttribute("data-overflow", "false");
    unmount();
    mockOverflow(1200, 600);
    const r = render(<DataTable<Row> rowKey="id" columns={cols} dataSource={rows} />);
    await waitFor(() => expect(r.container.querySelector(".scroll-hint")).toHaveTextContent("可左右滚动"));
    expect(r.container.querySelector(".data-table-wrap")).toHaveAttribute("data-overflow", "true");
  });
});

describe("DataTable at phone width (stacked cards)", () => {
  interface Card {
    id: string;
    name: string;
    addr: string;
    when: string;
  }
  const many: Card[] = Array.from({ length: 25 }, (_, i) => ({ id: `c${i}`, name: `服务器 ${i} 的名字很长很长很长`, addr: LONG, when: `${i} 天前` }));
  const ccols: DataColumn<Card>[] = [
    { title: "名称", dataIndex: "name", kind: "flex", width: 160 },
    { title: "地址", dataIndex: "addr", kind: "ellipsis", width: 180, mono: true },
    { title: "创建", dataIndex: "when", kind: "fixed", width: 100, card: "detail" },
    { title: "操作", kind: "actions", width: 100, render: (_, r) => <button type="button">{`编辑 ${r.id}`}</button> },
  ];

  it("renders one card per row with the title, labelled key fields and the actions, no table and no pinned column", () => {
    phoneWidth();
    const { container } = render(
      <DataTable<Card> rowKey="id" columns={ccols} dataSource={many.slice(0, 3)} onRow={(r) => ({ "data-testid": `row-${r.id}` }) as React.HTMLAttributes<HTMLElement>} />,
    );
    expect(container.querySelector("table")).toBeNull();
    expect(container.querySelector(".ant-table-cell-fix-right")).toBeNull();
    expect(container.querySelector(".data-table-wrap")).toHaveAttribute("data-stacked", "true");
    const card = screen.getByTestId("row-c1");
    expect(card).toHaveClass("data-card");
    expect(card.querySelector(".data-card-title")).toHaveTextContent("服务器 1 的名字很长很长很长");
    // Key field: label + value; the cut value keeps its full text and focus.
    const field = within(card).getByText("地址").closest(".data-card-field")!;
    expect(field.querySelector("dd .ellipsis-text")).toHaveTextContent(LONG);
    expect(field.querySelector("dd .ellipsis-text")).toHaveAttribute("tabindex", "0");
    // Every action is in the card's corner.
    expect(within(card.querySelector<HTMLElement>(".data-card-actions")!).getByRole("button", { name: "编辑 c1" })).toBeInTheDocument();
    // A detail field is not shown until the card's details are opened.
    expect(within(card).queryByText("1 天前")).toBeNull();
  });

  it("opens details and secondary fields per card, and paginates like the table", async () => {
    phoneWidth();
    const { container } = render(<DataTable<Card> rowKey="id" columns={ccols} dataSource={many} pageSize={10} secondary={(r) => <span>{`次要 ${r.id}`}</span>} />);
    expect(container.querySelectorAll(".data-card")).toHaveLength(10);
    const first = container.querySelector<HTMLElement>(".data-card")!;
    const toggle = within(first).getByRole("button", { name: "详情" });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    await userEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(within(first).getByText("0 天前")).toBeInTheDocument();
    expect(within(first).getByText("次要 c0")).toBeInTheDocument();
    // Next page: rows 11–20.
    await userEvent.click(within(container.querySelector<HTMLElement>(".data-cards-pagination")!).getByTitle("2"));
    expect(container.querySelector(".data-card .data-card-title")).toHaveTextContent("服务器 10 ");
  });

  it("follows a controlled page and expansion (as the rules table drives them)", async () => {
    phoneWidth();
    const onExpand = vi.fn();
    const onPage = vi.fn();
    const { container } = render(
      <DataTable<Card>
        rowKey="id"
        columns={ccols}
        dataSource={many}
        secondary={(r) => <span>{`次要 ${r.id}`}</span>}
        expandable={{ expandedRowKeys: ["c21"], onExpandedRowsChange: onExpand, rowExpandable: (r) => r.id !== "c22" }}
        pagination={{ current: 3, pageSize: 10, onChange: onPage, showTotal: (t) => `共 ${t} 条` }}
      />,
    );
    expect([...container.querySelectorAll(".data-card-title")].map((t) => t.textContent)).toEqual(
      ["c20", "c21", "c22", "c23", "c24"].map((id) => many.find((m) => m.id === id)!.name),
    );
    expect(screen.getByText("次要 c21")).toBeInTheDocument();
    expect(container.textContent).toContain("共 25 条");
    // c22 cannot expand, but its detail field still has a toggle.
    await userEvent.click(within(container.querySelectorAll<HTMLElement>(".data-card")[2]).getByRole("button", { name: "详情" }));
    expect(screen.queryByText("次要 c22")).toBeNull();
    expect(onExpand).toHaveBeenCalledWith(["c21", "c22"]);
    await userEvent.click(within(container.querySelector<HTMLElement>(".data-cards-pagination")!).getByTitle("1"));
    expect(onPage).toHaveBeenCalledWith(1, 10);
  });

  it("keeps the scrolling table when a table opts out, and at desktop width", () => {
    phoneWidth();
    const { container, unmount } = render(<DataTable<Card> rowKey="id" columns={ccols} dataSource={many.slice(0, 2)} stack={false} />);
    expect(container.querySelector("table")).not.toBeNull();
    unmount();
    vi.restoreAllMocks();
    const r = render(<DataTable<Card> rowKey="id" columns={ccols} dataSource={many.slice(0, 2)} />);
    expect(r.container.querySelector(".data-card")).toBeNull();
  });
});

describe("wide grids", () => {
  it("is a focusable, named scroll region with a hint when it overflows", async () => {
    mockOverflow(1500, 700);
    render(
      <WideGrid label="服务 × 出口矩阵">
        <table>
          <thead>
            <tr>
              <th>服务</th>
              <th>出口甲</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>某服务</td>
              <td>
                <GridCell note={LONG}>
                  <span className="cat-chip">已过期</span>
                </GridCell>
              </td>
            </tr>
          </tbody>
        </table>
      </WideGrid>,
    );
    const region = screen.getByRole("region", { name: "服务 × 出口矩阵" });
    expect(region).toHaveClass("wide-grid-scroll");
    await userEvent.tab();
    expect(region).toHaveFocus();
    await waitFor(() => expect(document.querySelector(".scroll-hint")).toBeInTheDocument());
    expect(within(region).getByText("已过期").closest(".grid-cell-main")).toBeInTheDocument();
    expect(within(region).getByText(LONG)).toHaveClass("grid-cell-note");
    fireEvent.scroll(region);
  });
});

describe("unlock matrix widths", () => {
  it("fit 9 exits next to the service column inside the grid's box at 1280", () => {
    expect(MATRIX_LAYOUT.box).toBe(TABLE_BUDGET.section - 2);
    expect(MATRIX_LAYOUT.firstCol + MATRIX_LAYOUT.fitExits * MATRIX_LAYOUT.exitCol).toBeLessThanOrEqual(MATRIX_LAYOUT.box);
  });
});

describe("shared constants", () => {
  it("states the breakpoints once", () => {
    expect(BREAKPOINTS).toEqual({ desktopXL: 1440, desktop: 1280, laptop: 1024, tablet: 768, phone: 390 });
  });
  it("keeps TABLE_SCROLL for pages not yet migrated", () => {
    expect(TABLE_SCROLL).toEqual({ x: "max-content" });
  });
});
