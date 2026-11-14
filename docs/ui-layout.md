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

### Audit script

`web/tools/ui-audit.js` is a console tool for the checks above. Paste it into the
browser console on the local panel (the origin it is served from), then:

```js
const r = await __audit(1280, ["", "rules", "unlock"], 1500); // width, page hashes ("" is the overview), wait ms
console.log(__fmt(r));
```

It loads the panel in an iframe of the given width and reports per page:
document overflow (`ox`), content spilling out of its box (`spill`), tables and
boxes that scroll (`hscroll`), elements beyond the viewport (`beyond`) or their
card (`outCard`), labels/tags/buttons that wrap (`wrap`) and text squeezed into
a one-character column (`squeeze`). It is a manual tool, not part of the test
suite or the bundle.
