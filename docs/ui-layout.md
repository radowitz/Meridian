# Panel layout rules (`web/`)

One set of layout rules, implemented once in `web/src/styles.css` and the shared
components in `web/src/ui.tsx`. Pages adopt the shared pieces; they do not patch
layout locally. Everything here is display layer only. It stays within React,
antd and the `--m-*` theme variables (light and dark); there are no new
dependencies.

## Breakpoints

Stated once as `BREAKPOINTS` in `ui.tsx` (CSS cannot read it, so the media
queries in `styles.css` repeat the values, in a block headed "breakpoints").

| Name | Width | Behaviour of the shared pieces |
|---|---|---|
| desktop-xl | 1440 | Page content is at most 1320 px wide, centred. |
| desktop | 1280 and up | Every table shows its key columns without sideways scrolling. Secondary columns are already in the expandable row. |
| laptop | 1024 to 1279 | Tile grid gets narrower tiles. Tables may scroll inside their own box; the hint appears. |
| tablet | 768 to 1023 | One-column card grids, tighter section padding. |
| phone | 767 and below, 390 target | Header actions fill the row and wrap. `Facts` become label-over-value. Sticky bars get less padding. Below 480: 12 px content padding, one-column tiles, 32 px minimum button height. |

At every width the document itself must not scroll horizontally because of a
shared component. Wide things scroll inside their own box (`DataTable`,
`WideGrid`, the command block) and say so.

## The rules

1. **Key/value rows.** The label column has a minimum width (`--m-fact-label`,
   96 px) and never wraps. The value cell has `min-width: 0` and breaks long
   content inside itself. A long value can no longer squeeze a label into one
   character per line.
2. **Single-line controls.** Text in tags, badges, buttons, table headers, tabs
   and segmented controls never wraps (global rule, no per-table class needed).
   Long running text belongs in a value cell, not in one of these.
3. **Long technical text** (identifiers, paths, addresses, fingerprints,
   commands) is monospace through `Mono` and never wider than its container.
4. **Explanations** are a short visible summary with the rest collapsed.
   **Safety notices are never collapsed.**
5. **A status is a short tag plus one line of reason**, and the same reason is
   not repeated.
6. **Header actions** wrap inside the header and never widen the page.
7. **Sticky toolbars** stick at exactly the top bar's height, opaque, so the top
   bar and the toolbar are one continuous area.
8. **Tables** declare a width policy per column; truncated text is reachable;
   secondary fields go in an expandable row; a scrolling table says so.
9. **Wide grids** (unlock matrix, coverage) freeze the first column, show a
   scroll hint, and keep compact cells.
10. **Hidden text inside a scrolling box needs a positioned ancestor inside
    that box.** `.sr-only` (visually hidden labels) is `position: absolute`.
    If its containing block is outside the `overflow-x: auto` box (for
    example `.wide-grid`, which is positioned, around `.wide-grid-scroll`,
    which was not), the box does not clip it, and the hidden labels of cells
    scrolled out to the right widen every ancestor up to the document (the
    unlock page was 127 px wider than a 1024 px viewport). Every horizontally
    scrolling box is therefore `position: relative` (`.wide-grid-scroll`,
    `.matrix-wrap`, the DataTable's `.ant-table-content` / `.ant-table-body`,
    the command box), and so are the small wrappers that hold hidden text
    (`.cat-chip.compact`, `.matrix-btn`, `.matrix-expired`, `.split-status`).
    `web/tools/ui-audit.js` reports violations as `absOut`.

## Shared pieces (all in `web/src/ui.tsx`)

### Key/value: `Facts`, `KV`

```tsx
<Facts items={[["承载枢纽", longText], ["说明", veryLong, "stacked"]]} />   // third element: value under the label
<Facts stacked labelMin={120} items={...} />                               // every row stacked / wider label column
<KV label="承载枢纽" stacked>{longSentence}</KV>                           // one row in a tile or card
```

Classes: `.facts`, `.fact`, `.fact-stacked`, `.facts-stacked`, `.kv`, `.kv-label`,
`.kv-value`, `.kv-stacked`. Use `stacked` when the value is a sentence or an
identifier; use the default for short values.

### Technical text: `Mono`, `CommandBlock`, `EllipsisText`

```tsx
<Mono>{id}</Mono>                         // inline, may break anywhere
<Mono ellipsis>{fingerprint}</Mono>       // one line, "…", full text on hover and keyboard focus
<Mono block copy>{publicKey}</Mono>       // own box, wraps
<Mono block scroll copy label="…">{cmd}</Mono>  // own box, scrolls inside itself, never splits; focusable
<CommandBlock label="…">{cmd}</CommandBlock>    // same as the line above
<EllipsisText text={s} mono />            // the cut-with-tooltip text on its own
```

Classes: `.mono`, `.mono-block`, `.mono-block-scroll`, `.mono-scroll`,
`.mono-ellipsis-wrap`, `.ellipsis-text`. `EllipsisText` is a focusable span with
an antd tooltip on hover and focus.

### Explanations: `Explain`, `SafetyNotice`

```tsx
<Explain summary="一句话说明">更长的补充说明……</Explain>                // "了解更多" toggle, aria-expanded
<Explain summary="…" mode="popover">…</Explain>                       // click popover
<SafetyNotice kind="unverified" title="数据面未验证">……</SafetyNotice>   // kinds: unverified | failclosed | signoff
```

`Explain` collapses by design, so nothing safety-relevant goes into its
children. `SafetyNotice` has no collapse, summary or popover prop at all: the API
itself says it cannot be hidden. It renders `role="note"` with a status tag
(`未验证` / `失败关闭` / `待人工签收`). Classes: `.explain`, `.explain-toggle`,
`.explain-more`, `.safety-notice`, `.safety-<kind>`.

### Status with a reason: `StatusReason`

```tsx
<StatusReason kind="attention" label="需要处理" reason={["枢纽未回报", "枢纽未回报"]} />  // reason shown once
<StatusReason kind="failed" reason={why} wrap />   // wrap: the reason is itself safety-relevant, do not cut it
```

The reason is one line cut with "…" (full text on hover/focus) unless `wrap`.
`joinReasons(list, label)` drops blanks, duplicates, reasons contained in a
longer one, and the label itself. Classes: `.status-reason`, `.status-reason-text`.

### Page header: `PageHeader` / `Page`

```tsx
<Page title="规则" description="…" extra={<Button type="primary">保存</Button>} menu={[{ key, label, onClick }]}>
```

`extra` is the primary action; `menu` puts secondary actions behind "更多操作".
`.page-header-extra` wraps and has `max-width: 100%`; below 768 it fills the row.
The one-sentence description is fine; longer text goes in `Explain`.

### Sticky bars: `StickyBar`

`TopologyDocBar` uses it (`.sticky-bar`, `top: calc(var(--m-topbar-h) - 1px)`,
opaque `--m-surface`). The top bar height is the variable `--m-topbar-h` (56 px);
never write a literal offset. Any other page toolbar that must stick uses
`<StickyBar>`.

### Tables: `DataTable`

```tsx
<DataTable<Row>
  rowKey="id"
  dataSource={rows}
  columns={[
    { title: "#", dataIndex: "pos", kind: "fixed", width: 56 },
    { title: "名称", dataIndex: "name", kind: "flex", width: 200 },         // takes the rest, min 200, wraps
    { title: "路径", dataIndex: "path", kind: "ellipsis", width: 220, mono: true },
    { title: "操作", kind: "actions", width: 120, render: (_, r) => <RowActions …/> },
  ]}
  secondary={(r) => <Facts items={[…]} />}   // expandable row for secondary fields
  pageSize={20}                              // pagination past 20 rows (default), false-like for short lists
/>
```

Column kinds: `fixed` (exact width, never wraps), `flex` (rest of the width, at
least `width`, default 160), `ellipsis` (one line, "…", focusable tooltip with
the full text), `actions` (pinned right, opaque). The table is as wide as the sum
of the widths (at least its container), not `max-content`; when it scrolls, a
hint ("还有更多列，可左右滚动 →") shows below it. `scroll` is set by the
component, do not pass it. Classes: `.data-table`, `.data-table-wrap`,
`.col-fixed`, `.col-flex`, `.col-ellipsis`, `.col-actions`, `.row-secondary`,
`.scroll-hint`. Hook `useScrollHint(ref, selector?)` is exported for custom use.

Fixed action column: it is only pinned, never overlapping, because every other
column has an explicit width and sums into the table width. When the table does
scroll, content slides under the pinned column as under any sticky column; keep
the actions column narrow (at most 120 px; extra actions in `RowActions`'s menu)
and put the long text in `ellipsis`/`flex` columns that are not adjacent-critical,
or move it to `secondary`.

`TABLE_SCROLL` is kept and unchanged for pages not yet migrated.

### Wide grids: `WideGrid`, `GridCell`

```tsx
<WideGrid label="服务 × 出口矩阵">
  <table>… <td><GridCell note="近 24 小时无结果"><span className="cat-chip">已过期</span></GridCell></td> …</table>
</WideGrid>
```

The wrapper is a focusable `role="region"` scroll box; first column (`th/td:first-child`)
is frozen and opaque; cells have `min-width: 104px` so a chip such as 已过期 is
never squeezed into a vertical strip; chips never wrap; the note under a chip is
one line with a tooltip. The existing `.matrix` table already gets the same cell
rules from CSS (min width, nowrap chips) without any markup change.

### Shell

`App.tsx`: the top bar has the fixed height `--m-topbar-h` and an opaque
background; the login screen's hint command is a `CommandBlock` (one line, scrolls
inside its box, code box never split).

## Migration notes for N3 (old pattern, new pattern)

| Old | New |
|---|---|
| `<Table scroll={TABLE_SCROLL} columns=…>` with `className: "cell-name"`, `cell-text`, `cell-actions` | `<DataTable columns=…>` with `kind: "fixed" / "flex" / "ellipsis" / "actions"` and widths; drop `scroll`. `cell-name` becomes `fixed` (or `ellipsis` if names can be long), `cell-text` becomes `flex`, `cell-actions` becomes `actions` |
| Many columns so the table scrolls at 1280 | Keep at most the key columns (about 5 plus actions) and move the rest into `secondary` |
| Tooltip or `ellipsis` on `Typography.Text` | `EllipsisText` / `Mono ellipsis` / an `ellipsis` column |
| `<div className="tile-row">` / local `Row` helpers | `<KV label>`; long value: `<KV stacked>` (done on the overview) |
| `<Typography.Text type="secondary">` paragraphs of explanation | `<Explain summary>` with the detail inside |
| Safety sentence in grey text or `Alert` that may be shortened | `<SafetyNotice kind>`; never inside `Explain` |
| `<StatusTag>` followed by a sentence, or a sentence repeating the same reason | `<StatusReason kind reason>` |
| `<Mono block copy>{command}</Mono>` for a command | `<CommandBlock>` (or `Mono block scroll copy`) |
| Header with many `extra` buttons | One primary in `extra`, the rest in `menu` |
| `position: sticky; top: 64px` anywhere | `<StickyBar>` / `.sticky-bar` |
| Unlock matrix / coverage `table` in its own overflow div | `<WideGrid label>` + `<GridCell>` |
| Local `.facts`-like grids | `<Facts>` |

Things N3 must handle page by page: the rules table (about 160 rows: pagination
comes with `DataTable`, the 要求/遮蔽 text is an `flex` column, ids and positions
`fixed`); the unlock coverage table and matrix (`WideGrid`); `Typography.Text
className="mono" ellipsis` in `RulesImport.tsx` (the URL column); the topology
node card text and canvas height (not touched here, canvas CSS only); the
`.cell-note` and `.group-live` / `.hub-state-bar` blocks on the exits page
(`StatusReason` for the repeated hub reason); `RemotePage.tsx`'s router command
(`Mono block copy` becomes `CommandBlock`); dialogs and drawers (`Facts` inside
them).


## Applied to the pages

Every page, drawer and dialog now uses the shared pieces. `TABLE_SCROLL` is no
longer used by any page (it stays exported for the N2 tests). New shared
piece: `SplitStatus` (below). Page-level CSS is in `styles.css` under
"N3: pages".

### `SplitStatus`

```tsx
<SplitStatus kind="unverified" label="未验证 · 读不到" />                    // tag 未验证, then "· 读不到" as one muted line
<SplitStatus kind="unverified" label="实际未知 · 未验证 · 未读取" detail="hidden" title={why} />  // tight rows: rest in tooltip + screen readers
```

A tag holds one short status only. Labels made of several dot-separated facts
are split: the first fact in the tag, the rest beside it (`inline`, cut with
"…") or only in the tooltip and a visually hidden span (`hidden`). The wrapper
carries `data-status` and the whole label as its text. Used for the group
actual state (exits, overview), Cloudflare permission check ("可读 · 写权限未确认"),
server login "未选择 · 密码", node key "还没有 · 第一次装机".

### Per page

| Page / part | Tables: key columns (secondary = expandable row) | Collapsed (`Explain`) | Always visible |
|---|---|---|---|
| Shell | — | — | Top bar: main column has `min-width: 0`, status group does not wrap, so the right group (install, theme, lock) stays in the viewport. Drawers are at most `100vw` wide; modals at most `100vw - 32px`. Login hint is a `CommandBlock`. |
| Overview | — | — | Tiles at least 360 px (fewer columns, not narrower tiles). 出口地区组: one grid row per group (name with "…" and tooltip / mode / one `SplitStatus` tag with details in the tooltip). Mesh 账户 stacked (address + short tag). 探测通道: tag + reason that wraps under it. 国内中继分担 tile: one compact row per relay (name, status tag, share, "45 ms · 0.4%"), details in tooltips; facts as `KV` rows. |
| Topology | — | — | Node cards 200 px, 14 px name, one line per fact cut with "…" (whole text in the card title). Canvas `clamp(520px, 100vh - 250px, 960px)`. Nodes that were never placed get a layered position (`autoLayout`: gateway → relay → IX → hub → exit, 300 × 130 px grid, at most 5 per column; exits of one region group adjacent; an exit reached through another exit in a layer to the right, in its carrier's order); saved positions are kept; 「自动排列」re-lays all nodes on request (marks the document changed; positions are saved with the topology). Edge labels have padded backgrounds. |
| Exits | Relay sharing (exits page): 中继, 状态, 份额, 质量, 流量, 吞吐探测 with widths | Mode rules once above the groups (`group-modes-note`), DNS / relay costs, exit kinds | Hub bar: a head (title, carrying hub, read button) and one row per hub (tier tag, name and server cut with "…", last read + short tag, cause on one line with its fix; read errors wrap). Single hub: `Facts` rows 枢纽 / 上次读取 / 原因. A hub report that is unusable for the same reason in every group (`sharedHubReports`) is said once on that hub's row ("各地区组的报告：…"); each card then shows only "主枢纽 [未验证]" / "备用枢纽 [未验证]" with the reason in the tooltip and hidden text; cards that differ keep their full line. Each card: `SplitStatus` for the actual state, the cause on one line (`joinReasons`) with the fix; unverified exit kinds as `SafetyNotice`. |
| Rules | 顺序 124, 规则 (two lines: the name cut with "…" and its origin tag on the same line, then a one-line match with full text) flex, 去向 flex (one line: tag + name cut with "…"), 要求与遮蔽 flex (wraps, never under the action column), 校验 92, 启用 60, 操作 104; sum 962 px | Order explanation, AAAA / unlisted-name note, upgrade notes after the first, shared-address note | DNS fail-closed sentence (`SafetyNotice failclosed`); header: 添加规则 + "更多操作" (导入, QUIC 开关, Apple 模板). |
| Rules: import drawer | mapping, services, rule-sets, ordered preview (行 / 原文 ellipsis / 映射为 / 状态 / 说明 / 删除), 50 per page | Preview notes after the first | "确认之前不写入任何东西" alert; blocking status. |
| Rules: rule-sets, service groups, tester, sniffing | Rule-sets: 名称 (+ auth tag), URL ellipsis, 状态 (+ 部分生效 tag, errors), 使用, 操作 (立即更新 + menu); secondary: URL, format, counts, unsupported, used by. Sniff decisions: 时间, 原目的地址, 判断依据, 规则, 目标, 结果; secondary: 来源 | Section intros | Sniff fail-closed sentence (`SafetyNotice`); coverage (by name / by address / costs) as three short lists. |
| Lists | Report: 名单, 结果, 生效来源, 版本时间, 条数, 尝试; secondary: 文件, 丢弃 | — | Source option cards unchanged. |
| Servers | 名称, 地址 (one line, full text on focus), 主机指纹, 状态, 操作; secondary: 登录, 节点, 最近测试, fingerprint, channel | — | — |
| Keys | SSH: 名称, 种类, 指纹 (ellipsis), 创建, 最近轮换, 使用者, 操作; SOCKS likewise | — | "不可查看" next to 已设置. |
| Cloudflare / Mesh | Accounts: 名称, Account ID (ellipsis + copy), Token, 权限检查 (`SplitStatus`), Mesh, 绑定部署, 操作; checks and permission tables with widths; Mesh readiness: tag 未就绪 + "还需：…" text; pinned hosts with ellipsis | — | "写权限未确认" alert. |
| Remote access | Devices: 设备, 模式, 地址 (ellipsis), 状态, 密钥, 启用, 操作 | — | Router command is a `CommandBlock` (one line, scrolls in its box). |
| Deploy | Remote nodes: 节点, 服务器, 安装状态, 密钥 (`SplitStatus`), 操作 (one button + menu); binaries: ellipsis SHA / path; guide plan and run: #, 节点, 现在/状态, 为什么在这个位置/说明 (flex 320, wraps); deployment records: 节点, 服务器 (fingerprint on one line), 状态, 操作 (撤回 or 删除记录 + menu: 恢复中断的装机, 放弃) | Guide order, push/preflight explanation, binaries, diff intro, deployment-record intro | "不会一次确认全部"、"已装好不是端到端验证"、retry note, all alerts about refusals, leftovers and unknown outcomes. |
| Unlock | Matrix: compact cells (one word per family, grade as "*", expiry as a clock icon; full label in title + hidden text; detail drawer), exit header names cut with tooltip, `WideGrid` (frozen first column, scroll hint), filters by region group / exit / service / family; catalog 服务, 能告诉你什么, 检测的平台, 地址族, 规则; state, history, owner candidate tables with widths; coverage: 地区 96, 项目 ellipsis, 脚本 ellipsis, 结果 (tag + adapter / reason), 说明 flex (wraps), filters by section and by implemented / not | Legend descriptions, schedule details, routing details, catalog intro | Validation notice; launcher fail-closed note; "自动选择未在真实平台和真实网关上验证" and "自动安装未在真实网关上验证" (`SafetyNotice unverified`); coverage "只在合成样本上测过" (`SafetyNotice`). |
| Leak checks | 检查 flex, 状态 132, 说明 flex; all rows on one page (no item can hide on page 2) | — | Every status tag (未执行 / 待人工签收). |
| WSS | Links: 链路, 拨号端, 路径, 操作; parties: 一端, 已安装, 下次下发 | — | — (border colour now uses the theme variable, was a light-only fallback). |


### Table width budget

At 1280 px with the sidebar expanded, the space a table really has was
measured in a browser and is stated once as `TABLE_BUDGET` in `ui.tsx`:
1016 px directly in the page; 974 px inside a `Section` (42 px of padding and
border); a drawer or dialog body is its width minus 48 px; a bordered card
inside a section takes 26 px more, a Collapse body 34 px, an expanded table
row 32 px. **Rule:** a `DataTable`'s minimum width — the sum of its declared
column widths (flex columns count their minimum, 160 by default), plus 48 px
for the expand column when rows expand (`secondary` or `expandable`) — must
not exceed its container's budget. `tableMinWidth(columns, expandable)`
computes it (it is the table's `scroll.x`). When a table does not fit, move
secondary columns into the expandable row rather than shrinking key columns.

`web/src/table_budget.test.tsx` renders the pages with synthetic rows (long
names, addresses and notes) and checks every rendered DataTable against the
budget of where it sits in the DOM (`tableBudgets()` in `testing.tsx`);
`layout_pages.test.tsx` and `rules_ordered.test.tsx` do the same for the rules,
unlock and import-drawer tables.

| Table | Container | Budget | Min width |
|---|---|---|---|
| Rules | page | 1016 | 970 |
| Servers (login, node, last test, fingerprint, channel in the expandable row) | page | 1016 (kept within 974) | 748 |
| SSH keys | page | 1016 | 950 |
| SOCKS credentials | section | 974 | 910 |
| Remote devices | section | 974 | 906 |
| Cloudflare accounts (+ expand) | section | 974 | 938 |
| Permission checks | expanded row in a section | 942 | 710 |
| Token how-to permissions | collapse in a section | 940 | 540 |
| Mesh readiness / pinned hosts | section | 974 | 794 / 820 |
| Deploy remote nodes | section | 974 | 822 |
| Binaries | collapse in a section | 940 | 800 |
| Guide plan / run | section | 974 | 718 / 778 |
| Deployment records (+ expand) | section | 974 | 788 |
| WSS links / parties | card in a section | 948 | 658 / 540 |
| Lists report (+ expand) / configured | section | 974 | 838 / 480 |
| Rule-sets (+ expand) / service groups | section | 974 | 848 / 740 |
| Sniff decisions (+ expand) | section | 974 | 898 |
| Import drawer: mapping / services / rule-sets / rows | section in a 1100 px drawer | 1010 | 660 / 760 / 740 / 932 |
| Unlock catalog / services / history / coverage / candidates | section | 974 | 788 / 760 / 826 / 806 / 580 |
| Result detail parts (+ expand) | 560 px drawer | 512 | 448 |
| Relay sharing (exits page) | section | 974 | 920 |
| Leak checks | section | 974 | 672 |

### Rules table pagination

`RULES_PAGE_SIZE` = 50 (20 / 50 / 100 selectable). The order number in the
first column is the rule's position in the whole (filtered or not) list, so
page 2 starts at 51. Moving works on whole-list positions: up / down, to the
top / bottom and 「移到第 N 条」 change the list as before and the table then
switches to the page that holds the moved rule (also after adding a rule at a
position, a QUIC switch or a template, and when the page is opened with
`#/rules/<id>`). Changing the search or the filter goes back to page 1.

### Unlock matrix

At 1280 the content box is about 976 px inside a section: a 132–180 px service
column plus 9 exit columns of about 84 px fit without scrolling because each
cell holds only "v4 未解锁" (family + one word; tcp-only exits add "仅 TCP"). With
more exits, filter by region group or exit; at narrow widths the grid scrolls
in its own box with the first column frozen and the scroll hint.

### Left as is / not done

- No new API: the overview relay tile links to the exits page for the full relay table (the data is the same; nothing new is fetched).
- Tables with fewer than 20 rows show no pagination; very long free text (alerts with server messages) still wraps inside its alert.
- The topology canvas cannot reduce label overlap for saved positions that are close together; 「自动排列」 is the remedy and is explicit.

## Tests (pages)

`web/src/layout_pages.test.tsx` uses a synthetic fixture of real size and
checks per page what jsdom can prove: rules pagination and global numbering
across pages (move up across a page boundary, move to N onto page 3), key
columns and declared widths of the rules table, full text of cut cells, header
actions (one primary + menu), rule-set pagination, unlock matrix structure
(region, compact cells, hidden full labels, expiry icon) and the exit filter,
coverage section filter, exits page (shared cause once, short tags), overview
group rows, topology `autoLayout` without overlapping cards, and that no
safety notice is inside a collapsed `Explain`.

## Tests

`web/src/ui_layout.test.tsx` (jsdom) covers: Facts/KV structure and stacking;
Mono, command block and ellipsis text (class names, focusability, tooltip with
the full text); `Explain` collapse, keyboard toggle and popover; `SafetyNotice`
having no hidden part or toggle; `StatusReason` and `joinReasons` de-duplication;
header actions structure and the "更多操作" menu; `StickyBar` class; `DataTable`
column classes, explicit widths, pagination, expandable secondary row, scroll
hint (with mocked sizes); `WideGrid` region and hint; `BREAKPOINTS` and
`TABLE_SCROLL`.

## Checks only a real browser can prove

Not verified by tests; run on a local panel with realistic data, in light and
dark, at 1440, 1280, 1024, 768 and 390 px:

1. The document has no horizontal scroll (`documentElement.scrollWidth` equals the viewport width) on every page, and at 390 px the rules page header no longer widens it.
2. No label is squeezed into a vertical strip (overview 出口地区组 / 承载枢纽, unlock matrix 已过期).
3. Tags, badges, buttons, table headers, tabs and segmented controls are one line.
4. Commands (login hint, remote access) stay inside their box and scroll there; the code box is not split.
5. The sticky toolbar and the top bar form one opaque area: scroll the rules and topology pages and confirm no row shows between them, in both themes.
6. Tables at 1280 and above show all key columns without scrolling; at 1024 and below the scroll hint appears exactly when the table scrolls and disappears at the end.
7. The pinned action column does not cover the neighbouring column's text (rules table).
8. The wide grids: frozen first column stays opaque while scrolling, the hint matches reality, cells are not squeezed.
9. Truncated cells show the full text on hover and on keyboard focus (tooltip visible and not clipped).
10. Header actions wrap or collapse at 768 and 390 and stay reachable; touch targets are at least 32 px.
11. Colours and contrast of safety notices, status tags and the scroll hint in both themes.
12. Per page with real-size data (about 14 nodes, 7 groups, 165 rules, 56 rule-sets, 17 service groups, 41 adapters, 9 exits): the rules table at 1280 and 1440 without horizontal scroll (declared sum 962 px plus pagination); the unlock matrix with 9 exits without scroll at 1280; the coverage table and the deployment guide tables without scroll at 1280; the deploy node and record tables at 1280.
13. Overview at 1280, 1440 and a very wide window: tiles at least 360 px, group rows one line each, relay tile rows inside the tile; healthy and unavailable variants (agent ok / missing, relay sharing present / absent, Mesh account present / absent).
14. Top bar at every width: the lock button is fully inside the viewport.
15. Topology: node cards readable at the fitted zoom, 「自动排列」 gives a layout without overlapping cards or labels hidden under nodes; saved positions unchanged after reload.
16. Drawers (rule, import 1100 px, node, result detail) and dialogs at 768 and 390: never wider than the viewport, content scrolls inside.
17. Unlock page at 1024, 768 and 390: document scrollWidth equals the viewport (hidden matrix labels clipped by the grid's scroll box); `__audit` reports no `absOut`.

### Audit script

`web/tools/ui-audit.js` is a console tool for the checks above. Paste it into the
browser console on the local panel (the origin it is served from), then:

```js
const r = await __audit(1280, ["", "rules", "unlock"], 1500); // width, page hashes ("" is the overview), wait ms
console.log(__fmt(r));
```

It loads the panel in an iframe of the given width and reports per page (the wrap check ignores `.sr-only` text; `absOut` lists absolutely positioned elements outside the horizontally scrolling box around them when that box is not their containing block):
document overflow (`ox`), content spilling out of its box (`spill`), tables and
boxes that scroll (`hscroll`), elements beyond the viewport (`beyond`) or their
card (`outCard`), labels/tags/buttons that wrap (`wrap`) and text squeezed into
a one-character column (`squeeze`). It is a manual tool, not part of the test
suite or the bundle.

### Demo preview

The "everything works" states (agent ok, relays sharing, hub read, groups
with an actual member, deployment guide runs, sniff running, Mesh deployed)
cannot be produced by a local panel without a host agent and real servers.
The demo preview renders the real shell and pages on responses generated
from the Go handlers on a synthetic gateway of real size (web/README.md
「演示预览」 has the scenario list, where the data comes from and how it is
kept apart from production). It is a development and acceptance tool:
nothing seen in it counts as verified on a real host, and the checks in
"Checks only a real browser can prove" stay unverified until they are run
in a real browser.

Build and serve it (offline; no external resource):

```sh
npm --prefix web run demo:build
npm --prefix web run demo:serve        # http://127.0.0.1:4174/  (or any static server on web/dist-demo)
```

URL scheme: `/?scenario=<id>&theme=light|dark#/<page>` — scenarios
`healthy`, `degraded`, `unavailable`, `deploy-running`,
`deploy-rate-limited`, `deploy-compensated`, `deploy-unknown`,
`deploy-done`, `preflight-blocked`, `save-refused`; no `theme` follows the
system. The red bar at the bottom ("演示数据", scenario and theme pickers)
and the faint watermark are always there; they are marked
`[data-demo-chrome]` and skipped by the audit. The bar adds its own height plus
8 px (44 px on a wide window; more where it wraps) of bottom padding to the
page (height only, widths are unchanged).

Audit on the demo: open the demo, paste `web/tools/ui-audit.js` into its
console, then

```js
// one scenario, theme and width
const r = await __audit(1280, ["", "exits", "deploy"], 1500, { scenario: "degraded", theme: "dark" });
console.log(__fmt(r));
// the matrix: all pages × scenarios × themes × widths (defaults: every page,
// the demo's scenarios, light and dark, 1440/1280/1024/768/390). At 1.5 s
// per page the full matrix takes about half an hour; narrow it with
// scenarios / themes / widths / pages.
const m = await __auditDemo({ scenarios: ["healthy", "degraded"], widths: [1280, 390] });
console.log(__fmtDemo(m)); // only the combinations with findings, and any request the demo could not answer
```

`opts.url` points the iframe at another origin or path (for example the
demo's dev server, `http://127.0.0.1:5174/demo.html`). On the real panel
`__audit(width, pages, wait)` behaves as before.

The demo's own tests (`web/src/demo/*.test.tsx`) prove in jsdom that every
endpoint of `api.ts` is answered in every scenario and that every page
renders in the main scenarios without the error boundary; they say nothing
about widths, wrapping or overlap.

