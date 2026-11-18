// Shared building blocks for every page. See web/README.md「面板约定」.
// The shell-level part (status tags, errors, links, monospace text, the
// pending-install indicator) is in ui_base.tsx and re-exported here.

import {
  ClockCircleOutlined,
  EyeInvisibleOutlined,
  EllipsisOutlined,
  QuestionCircleOutlined,
} from "@ant-design/icons";
import {
  Alert,
  App as AntApp,
  Button,
  Dropdown,
  Empty,
  Input,
  Modal,
  Pagination,
  Popover,
  Skeleton,
  Space,
  Table,
  Tooltip,
  Typography,
  type FormInstance,
  type InputRef,
  type TableColumnType,
  type TableProps,
} from "antd";
import { createContext, useCallback, useContext, useEffect, useId, useLayoutEffect, useMemo, useRef, useState, type CSSProperties, type HTMLAttributes, type Key, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { ApiError, isApiError } from "./api";
import { useTopologyDoc, useUnsavedGuard } from "./state";
import type { Issue } from "./types";
import {
  STATUS,
  StatusTag,
  errorTitle,
  ApiErrorAlert,
  Link,
  RefList,
  RulesApplyLine,
  EllipsisText,
  type StatusKind,
} from "./ui_base";

// The shell-level pieces live in ui_base.tsx (loaded with the entry); pages
// import them from here as before.
export * from "./ui_base";

// ============================================================== page layout ===

/**
 * Header of every page: the title (the page's one h1) and its actions. No
 * subtitle and no 「说明」 on the page: explanations live in the one usage
 * guide (使用说明, the header's question-mark button). The action area
 * wraps, so it can never widen the page. `menu` puts the secondary actions
 * behind a 「…」 dropdown; keep the one primary action in `extra`.
 */
export function PageHeader({
  title,
  extra,
  menu,
}: {
  title: ReactNode;
  extra?: ReactNode;
  menu?: MoreAction[];
}) {
  const items = (menu ?? []).filter(Boolean);
  return (
    <div className="page-header">
      <div className="page-header-text">
        <h1 className="page-title" data-testid="page-title">
          {title}
        </h1>
      </div>
      {extra || items.length > 0 ? (
        <div className="page-header-extra" data-testid="page-header-actions">
          {extra}
          {items.length > 0 ? (
            <Dropdown
              trigger={["click"]}
              menu={{
                items: items.map((m) => ({ key: m.key, label: m.label, icon: m.icon, danger: m.danger, disabled: m.disabled })),
                onClick: ({ key }) => items.find((m) => m.key === key)?.onClick(),
              }}
            >
              <Button icon={<EllipsisOutlined />} aria-label="更多操作" data-testid="page-more" />
            </Dropdown>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

/**
 * Where a page's explanations go: every Note/Help rendered in the page body
 * (outside drawers, dialogs, popovers, alerts and data tables) is moved
 * through a portal into the current page's section of the usage guide
 * (HelpGuide). The shell provides the target node; it is attached to the
 * guide while the guide is open and detached otherwise, so the page itself
 * shows no explanation.
 */
interface PageHelpCtx {
  target: HTMLElement | null;
  add: () => () => void;
}
const PageHelpContext = createContext<PageHelpCtx | null>(null);

/** The shell's guide slot for the current page (HelpGuide). */
export const HelpSlotContext = createContext<HTMLElement | null>(null);

/** Where a Note/Help stays in place instead of moving into the usage guide: dialogs and drawers (their own panel), table rows, and the explanation of a state (alerts, empty states, safety notices) next to that state. */
const NOTE_LOCAL = ".ant-drawer, .ant-modal, .ant-popover, .ant-alert, .empty-state, .safety-notice, .ant-table-wrapper, .data-cards, .page-header, .help-guide, [data-note-local]";

function useHoist(ref: { current: HTMLElement | null }): HTMLElement | null {
  const ctx = useContext(PageHelpContext);
  const [hoist, setHoist] = useState(false);
  useLayoutEffect(() => {
    if (!ctx || hoist) return;
    const el = ref.current;
    if (el && el.isConnected && !el.closest(NOTE_LOCAL)) setHoist(true);
  }, [ctx, hoist, ref]);
  const add = ctx?.add;
  useEffect(() => (hoist && add ? add() : undefined), [hoist, add]);
  return hoist && ctx?.target ? ctx.target : null;
}

function HoistedHelp({ target, title, children, testId }: { target: HTMLElement; title?: ReactNode; children: ReactNode; testId?: string }) {
  return createPortal(
    <div className="page-help-item" data-testid={testId}>
      {title ? <h3 className="page-help-title">{title}</h3> : null}
      <div>{children}</div>
    </div>,
    target,
  );
}

export function Page({
  title,
  extra,
  menu,
  children,
}: {
  title: ReactNode;
  extra?: ReactNode;
  menu?: MoreAction[];
  children: ReactNode;
}) {
  const shellSlot = useContext(HelpSlotContext);
  // Outside the shell (a page mounted alone) the explanations go to a hidden
  // store of the page's own, so the page still shows none.
  const [own, setOwn] = useState<HTMLElement | null>(null);
  const slot = shellSlot ?? own;
  const add = useCallback(() => () => undefined, []);
  const ctx = useMemo(() => ({ target: slot, add }), [slot, add]);
  return (
    <div className="page" data-testid="page">
      <PageHeader title={title} extra={extra} menu={menu} />
      {shellSlot ? null : <div ref={setOwn} hidden data-testid="page-help" />}
      <PageHelpContext.Provider value={ctx}>{children}</PageHelpContext.Provider>
    </div>
  );
}

/** A titled block inside a page. */
export function Section({ title, extra, help, children, id }: { title: ReactNode; extra?: ReactNode; help?: ReactNode; children: ReactNode; id?: string }) {
  const headId = useId();
  return (
    <section className="section" id={id} aria-labelledby={headId}>
      <div className="section-head">
        <h2 className="section-title" id={headId}>
          {title}
        </h2>
        {extra ? <div>{extra}</div> : null}
      </div>
      {help ? <Note title={title}>{help}</Note> : null}
      {children}
    </section>
  );
}

/**
 * A collapsible section: the title and a one-line summary are always
 * visible; the details open on click. Children stay mounted (hidden), so
 * anchors, forms and their state survive collapsing. Problems belong in the
 * summary (coloured); everything else stays muted.
 */
/** Whether folds start open (a test or an embedding can open every fold; the panel starts them closed). */
export const FoldsOpenContext = createContext(false);

export function Fold({
  title,
  summary,
  extra,
  defaultOpen = false,
  id,
  testId,
  children,
}: {
  title: ReactNode;
  summary?: ReactNode;
  extra?: ReactNode;
  defaultOpen?: boolean;
  id?: string;
  testId?: string;
  children: ReactNode;
}) {
  const allOpen = useContext(FoldsOpenContext);
  const [open, setOpen] = useState(defaultOpen || allOpen);
  useEffect(() => {
    if (defaultOpen) setOpen(true);
  }, [defaultOpen]);
  const headId = useId();
  const bodyId = useId();
  return (
    <section className="section fold" id={id} aria-labelledby={headId} data-testid={testId} data-open={open ? "true" : "false"}>
      <div className="section-head fold-head">
        <h2 className="section-title" id={headId}>
          <button type="button" className="fold-toggle" aria-expanded={open} aria-controls={bodyId} onClick={() => setOpen((o) => !o)}>
            {title}
          </button>
        </h2>
        {summary ? <span className="fold-summary">{summary}</span> : null}
        {extra ? <div className="fold-extra">{extra}</div> : null}
      </div>
      <div id={bodyId} className="fold-body" hidden={!open}>
        {children}
      </div>
    </section>
  );
}

// =============================================================== data hooks ===

export interface ApiState<T> {
  data: T | undefined;
  error: ApiError | null;
  loading: boolean;
  /** Re-run the loader; keeps the old data while loading. */
  reload: () => Promise<void>;
  /** Replace the data locally (after a mutation returned the new object). */
  setData: (fn: T | ((old: T | undefined) => T | undefined)) => void;
}

function toApiError(e: unknown): ApiError {
  if (isApiError(e)) return e;
  return new ApiError(0, { error: e instanceof Error ? e.message : String(e) }, "client");
}

/** `const servers = useApi(() => api.listServers(), [])`. */
export function useApi<T>(loader: () => Promise<T>, deps: unknown[] = []): ApiState<T> {
  const [data, setDataState] = useState<T | undefined>(undefined);
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(true);
  const seq = useRef(0);
  const loaderRef = useRef(loader);
  loaderRef.current = loader;

  const reload = useCallback(async () => {
    const my = ++seq.current;
    setLoading(true);
    try {
      const d = await loaderRef.current();
      if (my !== seq.current) return;
      setDataState(d);
      setError(null);
    } catch (e) {
      if (my !== seq.current) return;
      setError(toApiError(e));
    } finally {
      if (my === seq.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  const setData = useCallback((fn: T | ((old: T | undefined) => T | undefined)) => {
    setDataState((old) => (typeof fn === "function" ? (fn as (o: T | undefined) => T | undefined)(old) : fn));
  }, []);

  return { data, error, loading, reload, setData };
}

/**
 * Runs mutations: `busy` disables the buttons while one is in flight, `error`
 * holds the last failure (show it with <ApiErrorAlert>); `onError` gets it
 * right away (e.g. to put a `field` error on a form field).
 * `const act = useAction(); act.run(() => api.deleteServer(id))`.
 */
export function useAction() {
  const [busy, setBusy] = useState<string | false>(false);
  const [error, setError] = useState<ApiError | null>(null);
  const run = useCallback(
    async <R,>(fn: () => Promise<R>, key = "default", onError?: (e: ApiError) => void): Promise<R | undefined> => {
      setBusy(key);
      setError(null);
      try {
        return await fn();
      } catch (e) {
        const ae = toApiError(e);
        setError(ae);
        onError?.(ae);
        return undefined;
      } finally {
        setBusy(false);
      }
    },
    [],
  );
  return { run, busy, error, setError, clear: () => setError(null) };
}

/**
 * A refused change or delete (409 in_use, account_locked …) as a dialog
 * listing the referrers as links. Render it in the page:
 * `<RefusedDialog error={refused} onClose={() => setRefused(null)} />`.
 */
export function RefusedDialog({ error, title, onClose }: { error: ApiError | null; title?: ReactNode; onClose: () => void }) {
  return (
    <Modal open={!!error} title={title ?? (error ? errorTitle(error) : "")} onCancel={onClose} footer={<Button onClick={onClose}>知道了</Button>} destroyOnHidden>
      {error ? (
        <div data-testid="refused-dialog">
          {error.message && error.message !== errorTitle(error) ? <Typography.Paragraph>{error.message}</Typography.Paragraph> : null}
          {error.inUseBy.length > 0 ? (
            <>
              <Typography.Text type="secondary">先处理这些引用：</Typography.Text>
              <RefList refs={error.inUseBy} onNavigate={onClose} />
            </>
          ) : null}
        </div>
      ) : null}
    </Modal>
  );
}

/**
 * Puts an API error with a `field` onto the matching form field (one of
 * `fields`; `map` translates API names to form names). Returns true when it did.
 */
export function showFieldError(
  form: FormInstance,
  err: ApiError | null | undefined,
  fields: string[],
  map: Record<string, string> = {},
): boolean {
  if (!err?.field) return false;
  const name = map[err.field] ?? err.field;
  if (!fields.includes(name)) return false;
  form.setFields([{ name, errors: [err.message || errorTitle(err)] }]);
  return true;
}

// =============================================================== data view ===

/**
 * Loading (skeleton), error (message + retry), empty (what it is + primary
 * action) and data, in one place:
 * `<DataView state={servers} isEmpty={d => d.servers.length === 0} empty={…}>{d => …}</DataView>`.
 */
export function DataView<T>({
  state,
  isEmpty,
  empty,
  children,
  rows = 4,
}: {
  state: ApiState<T>;
  isEmpty?: (d: T) => boolean;
  empty?: ReactNode;
  children: (d: T) => ReactNode;
  rows?: number;
}) {
  if (state.data === undefined) {
    if (state.error) return <ApiErrorAlert error={state.error} onRetry={() => void state.reload()} />;
    return <Skeleton active paragraph={{ rows }} />;
  }
  return (
    <>
      {state.error ? <ApiErrorAlert error={state.error} onRetry={() => void state.reload()} /> : null}
      {isEmpty && isEmpty(state.data) && empty ? empty : children(state.data)}
    </>
  );
}

/** Empty state: what this is, and the primary action. */
export function EmptyState({ title, description, action }: { title: ReactNode; description?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty-state">
      <Empty
        image={Empty.PRESENTED_IMAGE_SIMPLE}
        description={
          <div>
            <div className="empty-title">{title}</div>
            {description ? <Note>{description}</Note> : null}
          </div>
        }
      >
        {action}
      </Empty>
    </div>
  );
}

/**
 * Offers text as a file download, built in the browser (no network, no
 * storage). The object URL is revoked right away.
 */
export function downloadText(filename: string, text: string) {
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function pad(n: number) {
  return n < 10 ? `0${n}` : String(n);
}

export function formatAbsolute(d: Date) {
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function formatRelative(d: Date, now = new Date()) {
  const s = Math.round((now.getTime() - d.getTime()) / 1000);
  const future = s < 0;
  const a = Math.abs(s);
  let t: string;
  if (a < 45) t = "刚刚";
  else if (a < 3600) t = `${Math.round(a / 60)} 分钟`;
  else if (a < 86400) t = `${Math.round(a / 3600)} 小时`;
  else if (a < 86400 * 30) t = `${Math.round(a / 86400)} 天`;
  else return formatAbsolute(d).slice(0, 10);
  if (t === "刚刚") return t;
  return future ? `${t}后` : `${t}前`;
}

/** Relative time, absolute time on hover. Empty / zero times render "—". */
export function TimeText({ value, empty = "—" }: { value: string | null | undefined; empty?: ReactNode }) {
  if (!value || value.startsWith("0001-")) return <Typography.Text type="secondary">{empty}</Typography.Text>;
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return <span>{value}</span>;
  return (
    <Tooltip title={formatAbsolute(d)}>
      <span className="time-text">
        <ClockCircleOutlined style={{ marginRight: 4, opacity: 0.6 }} />
        {formatRelative(d)}
      </span>
    </Tooltip>
  );
}

// ============================================================== SecretField ===

/**
 * Write-only secret input for antd Form (`<Form.Item name="password"><SecretField …/></Form.Item>`).
 *
 * - Never prefilled; autocomplete off; not spell-checked.
 * - With `isSet`, shows「已设置 · 替换」until the user chooses to replace it.
 * - The parent clears the field after every request, success or failure
 *   (`form.setFieldValue(name, undefined)`, or unmount the form).
 */
export function SecretField({
  value,
  onChange,
  isSet,
  multiline,
  placeholder,
  rows = 6,
  id,
  "aria-label": ariaLabel,
}: {
  value?: string;
  onChange?: (v: string | undefined) => void;
  isSet?: boolean;
  multiline?: boolean;
  placeholder?: string;
  rows?: number;
  id?: string;
  "aria-label"?: string;
}) {
  const [replacing, setReplacing] = useState(!isSet);
  const inputRef = useRef<InputRef>(null);
  useEffect(() => {
    if (!isSet) setReplacing(true);
  }, [isSet]);
  if (isSet && !replacing) {
    return (
      <Space>
        <StatusTag kind="ok">已设置</StatusTag>
        <Typography.Text type="secondary">
          <EyeInvisibleOutlined /> 不可查看
        </Typography.Text>
        <Button size="small" onClick={() => setReplacing(true)}>
          替换
        </Button>
      </Space>
    );
  }
  const common = {
    id,
    "aria-label": ariaLabel,
    value: value ?? "",
    placeholder,
    autoComplete: "off",
    spellCheck: false,
    "data-secret": "true",
    "data-1p-ignore": "true",
    "data-lpignore": "true",
  } as const;
  return (
    <Space direction="vertical" style={{ width: "100%" }}>
      {multiline ? (
        <Input.TextArea
          {...common}
          rows={rows}
          className="mono secret-textarea"
          onChange={(e) => onChange?.(e.target.value || undefined)}
        />
      ) : (
        <Input.Password
          {...common}
          ref={inputRef}
          autoComplete="new-password"
          visibilityToggle={false}
          onChange={(e) => onChange?.(e.target.value || undefined)}
        />
      )}
      {isSet ? (
        <Button
          size="small"
          type="link"
          style={{ padding: 0 }}
          onClick={() => {
            onChange?.(undefined);
            setReplacing(false);
          }}
        >
          不替换，保留已设置的值
        </Button>
      ) : null}
    </Space>
  );
}

// ============================================================ danger confirm ===

/**
 * Destructive actions: one sentence stating the consequence.
 * `const confirm = useConfirmDanger(); confirm({title, consequence, okText, onOk})`.
 * onOk may return a promise; the dialog stays open (button loading) until it settles.
 */
export function useConfirmDanger() {
  const { modal } = AntApp.useApp();
  return useCallback(
    (o: { title: ReactNode; consequence: ReactNode; okText?: string; danger?: boolean; onOk: () => unknown }) => {
      modal.confirm({
        title: o.title,
        content: o.consequence,
        okText: o.okText ?? "确定",
        okButtonProps: { danger: o.danger ?? true },
        cancelText: "取消",
        onOk: async () => {
          await o.onOk();
        },
      });
    },
    [modal],
  );
}

// =================================================================== tables ===

/**
 * LEGACY (kept so pages not yet migrated behave as before; new work uses
 * <DataTable>, see docs/ui-layout.md). Table props: the table is as wide as its
 * content and scrolls sideways inside its own box when the page is narrower
 * (never clipping columns). Give the name column `className: "cell-name"`
 * (no wrapping), long free text `className: "cell-text"` with a width, and
 * the action column `fixed: "right"` with `className: "cell-actions"`.
 */
export const TABLE_SCROLL = { x: "max-content" } as const;

export interface MoreAction {
  key: string;
  label: ReactNode;
  icon?: ReactNode;
  danger?: boolean;
  disabled?: boolean;
  onClick: () => void;
}

/**
 * Row actions in a table: the one or two actions used most stay as buttons,
 * the rest go into a "…" menu, so the column stays narrow and nothing is cut.
 * `label` names the row for the menu button ("<name> 的更多操作").
 */
export function RowActions({ children, more, label }: { children?: ReactNode; more?: MoreAction[]; label: string }) {
  const items = (more ?? []).filter(Boolean);
  return (
    <Space size={2} className="table-actions">
      {children}
      {items.length > 0 ? (
        <Dropdown
          trigger={["click"]}
          menu={{
            items: items.map((m) => ({ key: m.key, label: m.label, icon: m.icon, danger: m.danger, disabled: m.disabled })),
            onClick: ({ key }) => items.find((m) => m.key === key)?.onClick(),
          }}
        >
          <Button type="text" size="small" icon={<EllipsisOutlined />} aria-label={`${label} 的更多操作`} />
        </Dropdown>
      ) : null}
    </Space>
  );
}

// ================================================================ misc bits ===

/** One Facts row: [label, value] or [label, value, "stacked"] to put a long value on its own line. */
export type FactItem = [ReactNode, ReactNode] | [ReactNode, ReactNode, "stacked"];

/**
 * Key/value rows. The label column is at least `labelMin` px wide and never
 * wraps; the value cell may shrink to nothing and breaks long text inside
 * itself, so a long value can no longer squeeze the label. A row marked
 * "stacked" (or all rows with `stacked`) puts the value on its own line
 * under the label.
 */
export function Facts({ items, stacked, labelMin }: { items: FactItem[]; stacked?: boolean; labelMin?: number }) {
  return (
    <dl className={stacked ? "facts facts-stacked" : "facts"} style={labelMin ? ({ "--m-fact-label": `${labelMin}px` } as CSSProperties) : undefined}>
      {items.map(([k, v, mode], i) => (
        <div key={i} className={mode === "stacked" ? "fact fact-stacked" : "fact"}>
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

/**
 * One "label: value" row for tiles and cards (what the overview's local Row
 * was). Same rules as Facts: the label never wraps and keeps its width, the
 * value wraps inside its own cell. `stacked` puts the value under the label.
 */
export function KV({ label, children, stacked }: { label: ReactNode; children: ReactNode; stacked?: boolean }) {
  return (
    <div className={stacked ? "kv kv-stacked" : "kv"}>
      <span className="kv-label">{label}</span>
      <span className="kv-value">{children}</span>
    </div>
  );
}

/** Small tile used on the overview and summary rows. */
export function Tile({ title, extra, children, to }: { title: ReactNode; extra?: ReactNode; children: ReactNode; to?: string }) {
  return (
    <div className="tile">
      <div className="tile-head">
        <span className="tile-title">{to ? <Link to={to}>{title}</Link> : title}</span>
        {extra}
      </div>
      <div className="tile-body">{children}</div>
    </div>
  );
}

export function bytes(n: number) {
  if (n < 1024) return `${n} B`;
  const u = ["KiB", "MiB", "GiB", "TiB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${u[i]}`;
}

// ======================================================== topology doc bar ===

/** Validation issues of the topology document. */
export function IssueList({ issues }: { issues: Issue[] }) {
  if (issues.length === 0) return null;
  return (
    <div className="issues">
      {issues.map((iss, i) => (
        <Alert
          key={i}
          type={iss.severity === "error" ? "error" : "warning"}
          showIcon
          message={iss.message}
          description={
            [iss.node_id && `节点 ${iss.node_id}`, iss.link_id && `链路 ${iss.link_id}`, iss.rule_id && `规则 ${iss.rule_id}`, iss.group_id && `地区组 ${iss.group_id}`]
              .filter(Boolean)
              .join(" · ") || undefined
          }
        />
      ))}
    </div>
  );
}

/**
 * Save bar for pages that edit the whole topology document (topology,
 * rules, leak settings). Registers the unsaved-changes guard while dirty.
 */
export function TopologyDocBar() {
  const doc = useTopologyDoc();
  const act = useAction();
  const { message } = AntApp.useApp();
  useUnsavedGuard(doc.dirty, "拓扑有未保存的修改，离开后会丢失。");
  const errors = doc.issues.filter((i) => i.severity === "error");
  return (
    <div className="doc-bar sticky-bar">
      <Space wrap>
        {doc.dirty ? (
          <StatusTag kind="attention">有未保存的修改</StatusTag>
        ) : doc.rulesApply ? (
          <RulesApplyLine fa={doc.rulesApply.fast_apply} applyRequired={doc.rulesApply.apply_required} />
        ) : (
          <Typography.Text type="secondary">拓扑已保存</Typography.Text>
        )}
      </Space>
      <Space wrap>
        <Button onClick={() => act.run(() => doc.validate(), "validate")} loading={act.busy === "validate"}>
          校验
        </Button>
        <Button disabled={!doc.dirty} onClick={() => void doc.reload()}>
          放弃修改
        </Button>
        <Button
          disabled={!doc.dirty}
          loading={act.busy === "draft"}
          onClick={() => act.run(async () => (await doc.save(true)) && message.success("已保存为草稿"), "draft")}
        >
          保存草稿
        </Button>
        <Button
          type="primary"
          disabled={!doc.dirty || errors.length > 0}
          loading={act.busy === "save" || doc.saving}
          onClick={() =>
            act.run(async () => {
              const res = await doc.save(false);
              if (res) message.success(res.fast_apply ? "已保存" : "已保存；安装后在网关生效");
            }, "save")
          }
        >
          保存
        </Button>
      </Space>
      {act.error ? <ApiErrorAlert error={act.error} onClose={act.clear} style={{ width: "100%", marginTop: 12, marginBottom: 0 }} /> : null}
    </div>
  );
}

// ===================================================== layout primitives ===
// The global layout rules live in styles.css and here; docs/ui-layout.md is
// the reference (rules, recipes, migration notes, browser-only checks).

/**
 * The breakpoints of the panel, stated once. CSS cannot read these, so the
 * media queries in styles.css repeat them as max-width values (marked
 * "BREAKPOINT" there): desktop-xl >= 1440, desktop >= 1280 (every table shows
 * its key columns without sideways scrolling from here up), laptop 1024
 * (max-width 1279 and down: secondary columns move into the expandable row),
 * tablet 768 (max-width 1023 / 767: one-column grids, header actions fill
 * the row), phone 390 (max-width 479: tables scroll in their box or become
 * cards, buttons keep a 32 px touch height).
 */
export const BREAKPOINTS = { desktopXL: 1440, desktop: 1280, laptop: 1024, tablet: 768, phone: 390 } as const;

/**
 * A toolbar that sticks under the top bar as ONE continuous opaque area: its
 * top is the top bar's height (--m-topbar-h) minus the border pixel, and its
 * background is opaque, so no table row shows through between the two.
 */
export function StickyBar({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={["sticky-bar", className ?? ""].filter(Boolean).join(" ")}>{children}</div>;
}

/**
 * Collapsed explanation: a small 「? 说明」 toggle; the text only renders
 * (inline below, or in a popover) after it is opened. The default state of
 * every page shows no explanatory prose beyond its one-sentence header.
 */
export function Note({
  children,
  label = "说明",
  mode = "inline",
  defaultOpen = false,
  inline,
  testId,
  title,
}: {
  children: ReactNode;
  testId?: string;
  /** Heading of this piece once it is moved into the page's 「说明」. */
  title?: ReactNode;
  label?: string;
  mode?: "inline" | "popover";
  defaultOpen?: boolean;
  /** Render as an inline-level element (inside a line of text). */
  inline?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const id = useId();
  const probe = useRef<HTMLElement | null>(null);
  const target = useHoist(probe);
  const Box = inline ? "span" : "div";
  if (target) return <HoistedHelp target={target} title={title} testId={testId}>{children}</HoistedHelp>;
  if (mode === "popover") {
    return (
      <Box ref={probe as never} className="explain explain-popover note" data-testid={testId}>
        <Popover trigger="click" content={<div className="explain-pop">{children}</div>}>
          <button type="button" className="explain-toggle" aria-label={label}>
            <QuestionCircleOutlined aria-hidden="true" /> {label}
          </button>
        </Popover>
      </Box>
    );
  }
  return (
    <Box ref={probe as never} className="explain note" data-testid={testId}>
      <button type="button" className="explain-toggle" aria-expanded={open} aria-controls={id} onClick={() => setOpen((o) => !o)}>
        <QuestionCircleOutlined aria-hidden="true" /> {open ? "收起" : label}
      </button>
      <div id={id} className="explain-more" hidden={!open}>
        {children}
      </div>
    </Box>
  );
}

/** Field/title help. Native button supports Enter/Space; Escape closes and
 * returns focus. Never put errors, blocking reasons or consequences here. */
export function Help({ title, children, testId }: { title: string; children: ReactNode; testId?: string }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  const button = useRef<HTMLButtonElement>(null);
  const probe = useRef<HTMLDivElement>(null);
  const target = useHoist(probe);
  if (target) {
    // Moved into the page's single 说明: nothing is left in place.
    return <HoistedHelp target={target} title={title} testId={testId}>{children}</HoistedHelp>;
  }
  return (
    <div ref={probe} className="field-help" data-testid={testId} onKeyDown={(e) => {
      if (e.key === "Escape" && open) {
        e.stopPropagation();
        setOpen(false);
        button.current?.focus();
      }
    }}>
      <span>{title}</span>{" "}
      <button ref={button} type="button" className="help-button" aria-label={`${title}：帮助`} aria-expanded={open} aria-controls={id} onClick={() => setOpen(!open)}>
        <QuestionCircleOutlined aria-hidden="true" />
      </button>
      <div id={id} className="field-help-content" hidden={!open}>{children}</div>
    </div>
  );
}

export type SafetyKind = "unverified" | "failclosed" | "signoff";

const SAFETY: Record<SafetyKind, { status: StatusKind; label: string }> = {
  unverified: { status: "unverified", label: "未验证" },
  failclosed: { status: "attention", label: "失败关闭" },
  signoff: { status: "signoff", label: "待人工签收" },
};

/**
 * A safety-relevant notice: not verified, fail-closed, needs a human
 * sign-off. Always fully visible; there is deliberately no collapse, summary
 * or popover prop. Keep the wording short, but do not drop it.
 */
export function SafetyNotice({ kind, title, children }: { kind: SafetyKind; title?: ReactNode; children?: ReactNode }) {
  const k = SAFETY[kind];
  // "未验证" stays visible as a tag (plus its short title); the explanation of
  // what is not verified is behind 「说明」. Fail-closed and sign-off notices are
  // blocking statements and stay fully visible.
  const collapse = kind === "unverified";
  return (
    <div className={`safety-notice safety-${kind}`} role="note" data-safety={kind}>
      <StatusTag kind={k.status}>{k.label}</StatusTag>
      <div className="safety-text">
        {title ? <div className="safety-title">{title}</div> : null}
        {children ? collapse ? <Note>{children}</Note> : <div>{children}</div> : null}
      </div>
    </div>
  );
}

/**
 * A short status tag plus ONE line of reason. The reason is not part of the
 * tag and repeats nothing: empty, duplicate and already-contained reasons
 * (also when equal to the label) are dropped, the rest joined with "；".
 * One line, cut with "…" with the full text on hover/focus; `wrap` lets it
 * wrap (use it where the reason is itself safety-relevant).
 */
export function StatusReason({
  kind,
  label,
  reason,
  wrap,
}: {
  kind: StatusKind;
  label?: ReactNode;
  reason?: string | (string | null | undefined)[] | null;
  wrap?: boolean;
}) {
  const text = joinReasons(reason, typeof label === "string" ? label : STATUS[kind].label);
  return (
    <div className="status-reason" data-status={kind}>
      <StatusTag kind={kind}>{label}</StatusTag>
      {text ? wrap ? <span className="status-reason-text wrap">{text}</span> : <EllipsisText className="status-reason-text" text={text} /> : null}
    </div>
  );
}

/**
 * A status label made of several dot-separated facts ("未验证 · 状态过期"):
 * the tag holds only the first, short part; the rest follows as one line of
 * muted text (`detail="inline"`, cut with "…") or only in the tooltip and for
 * screen readers (`detail="hidden"`, for tight rows such as overview tiles).
 * The wrapper carries `data-status` and the whole label as its text.
 */
export function SplitStatus({
  kind,
  label,
  title,
  detail = "inline",
  testId,
}: {
  kind: StatusKind;
  label: string;
  title?: ReactNode;
  detail?: "inline" | "hidden";
  testId?: string;
}) {
  const [head, ...rest] = label.split(" · ");
  const tail = rest.join(" · ");
  const tag = <StatusTag kind={kind}>{head}</StatusTag>;
  return (
    <span className={`split-status split-${detail}`} data-status={kind} data-testid={testId}>
      {title || (detail === "hidden" && tail) ? (
        <Tooltip title={title ?? label}>
          <span className="split-status-tag" tabIndex={detail === "hidden" ? 0 : undefined}>
            {tag}
          </span>
        </Tooltip>
      ) : (
        tag
      )}
      {tail ? (
        detail === "hidden" ? (
          <span className="sr-only"> · {tail}</span>
        ) : (
          <span className="split-status-detail">
            <span className="split-status-sep"> · </span>
            {tail}
          </span>
        )
      ) : null}
    </span>
  );
}

/** Reasons without blanks, duplicates, parts of a longer reason, or the label itself; joined with "；". */
export function joinReasons(reason: string | (string | null | undefined)[] | null | undefined, label?: string): string {
  const list = (Array.isArray(reason) ? reason : [reason]).map((r) => (r ?? "").trim()).filter((r) => r !== "" && r !== label);
  const uniq = list.filter((r, i) => list.indexOf(r) === i);
  return uniq.filter((r) => !uniq.some((o) => o !== r && o.includes(r))).join("；");
}

// -------------------------------------------------------------------- tables

/**
 * How a column takes width (docs/ui-layout.md):
 * - fixed: exactly `width` px, never wraps (ids, counts, times, tags)
 * - flex: takes the remaining width, at least `width` px (default 160), wraps normally
 * - ellipsis: `width` px, one line cut with "…"; the full text is a
 *   keyboard-reachable tooltip
 * - actions: `width` px, pinned right with an opaque background
 */
export type ColKind = "fixed" | "flex" | "ellipsis" | "actions";

/**
 * Where a column goes when the table is shown as stacked cards (phone width,
 * see DataTable `stack`):
 * - title: the card's heading (one per table; the row's identity). Without
 *   one, the first column that declares no place is the heading.
 * - key: label + value, always visible (default)
 * - detail: label + value under the card's 「详情」 toggle, with `secondary`
 * - hidden: not shown in the card (its content is already in another field)
 * The `actions` column is always the card's top-right corner.
 */
export type CardRole = "title" | "key" | "detail" | "hidden";

export interface DataColumn<T> extends Omit<TableColumnType<T>, "width" | "fixed" | "ellipsis"> {
  kind?: ColKind;
  width?: number;
  /** Render the value in monospace with fixed-width digits (addresses, versions, rates, latencies). */
  mono?: boolean;
  /** Place of the column in the stacked cards (default "key"; the actions column is always the card's corner). */
  card?: CardRole;
}

const FLEX_MIN = 160;

/** Width antd gives the expand-icon column of a table with an expandable row. */
export const EXPAND_COL = 48;

/**
 * Width a table really has at a 1280 px viewport with the sidebar expanded
 * (216 px) and the content padding (24 px each side), measured in a real
 * browser on the local panel: the content column is 1016 px; a table directly
 * in the page gets all of it; a Section card takes 2 × 20 px padding + 2 × 1 px
 * border (974 px inside). Drawers and dialogs: their width minus 2 × 24 px body
 * padding. Smaller insets: a bordered card inside a section (WSS listener,
 * 2 × 12 + 2), a Collapse panel body (2 × 16 + 2) and an expanded table row
 * (2 × 16). The sum of a DataTable's declared minimum column widths (see
 * tableMinWidth) must not exceed the width of its container, or the table
 * scrolls at 1280 (docs/ui-layout.md, "Table width budget").
 */
export const TABLE_BUDGET = {
  viewport: 1280,
  page: 1016,
  section: 974,
  sectionInset: 42,
  drawerPadding: 48,
  modalPadding: 48,
  cardInset: 26,
  collapseInset: 34,
  expandedRowInset: 32,
} as const;

/**
 * The unlock matrix's column widths (rendered as a <colgroup> with
 * table-layout: fixed, so the browser uses exactly these; cell padding and
 * borders are inside them, box-sizing is border-box). `box` is the grid's
 * scroll box at 1280 (a Section's 974 px minus the box's 2 px border):
 * the service column plus 9 exit columns fit it without scrolling.
 */
export const MATRIX_LAYOUT = { box: TABLE_BUDGET.section - 2, firstCol: 180, exitCol: 86, fitExits: 9 } as const;

/**
 * The minimum width a DataTable forces: fixed / ellipsis / actions widths,
 * flex minimums (default 160) and the expand column when rows expand. This is
 * the table's `scroll.x`, so it is what has to fit its container.
 */
export function tableMinWidth<T>(columns: DataColumn<T>[], expandable: boolean): number {
  return columns.reduce((n, c) => n + (c.width ?? ((c.kind ?? "flex") === "flex" ? FLEX_MIN : 120)), 0) + (expandable ? EXPAND_COL : 0);
}

function prepareColumns<T extends object>(columns: DataColumn<T>[]): { cols: TableColumnType<T>[]; minWidth: number } {
  let minWidth = 0;
  const cols = columns.map((c): TableColumnType<T> => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { kind = "flex", width, mono, render, className, card, ...rest } = c;
    const cls = (extra: string) => [className, extra, mono && kind !== "ellipsis" ? "num" : ""].filter(Boolean).join(" ");
    if (kind === "flex") {
      const min = width ?? FLEX_MIN;
      minWidth += min;
      return { ...rest, render, className: cls("col-flex"), onCell: (r, i) => ({ ...(rest.onCell?.(r, i) ?? {}), style: { minWidth: min } }) };
    }
    const w = width ?? 120;
    minWidth += w;
    if (kind === "fixed") return { ...rest, render, width: w, className: cls("col-fixed") };
    // An actions column always has a header name (visually hidden when the page gave none).
    if (kind === "actions") return { ...rest, title: rest.title || <span className="sr-only">操作</span>, render, width: w, fixed: "right", className: cls("col-actions") };
    return {
      ...rest,
      width: w,
      ellipsis: { showTitle: false },
      className: cls("col-ellipsis"),
      render: (value, record, index) => {
        const node = render ? render(value, record, index) : value;
        return typeof node === "string" || typeof node === "number" ? <EllipsisText text={node} mono={mono} /> : (node as ReactNode);
      },
    };
  });
  return { cols, minWidth };
}

/**
 * Whether the scroll container `selector` (inside `ref`; omit it to measure the
 * ref itself) scrolls sideways and whether it is at its end, for the hint.
 */
export function useScrollHint(ref: { current: HTMLElement | null }, selector?: string) {
  const [state, setState] = useState({ overflow: false, atEnd: false });
  useEffect(() => {
    const root = ref.current;
    const el = selector ? root?.querySelector<HTMLElement>(selector) : root;
    if (!el) return;
    const measure = () => {
      const overflow = el.scrollWidth > el.clientWidth + 2;
      const atEnd = el.scrollLeft + el.clientWidth >= el.scrollWidth - 2;
      setState((o) => (o.overflow === overflow && o.atEnd === atEnd ? o : { overflow, atEnd }));
    };
    measure();
    el.addEventListener("scroll", measure, { passive: true });
    window.addEventListener("resize", measure);
    const ro = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(measure);
    ro?.observe(el);
    return () => {
      el.removeEventListener("scroll", measure);
      window.removeEventListener("resize", measure);
      ro?.disconnect();
    };
  });
  return state;
}

function ScrollHint({ overflow, atEnd }: { overflow: boolean; atEnd: boolean }) {
  if (!overflow) return null;
  return (
    <div className={atEnd ? "scroll-hint at-end" : "scroll-hint"} role="note">
      {atEnd ? "已到最右" : "还有更多列，可左右滚动 →"}
    </div>
  );
}

/**
 * The panel's table: antd Table with explicit column width classes (see
 * ColKind), an expandable row for secondary fields, pagination past
 * `pageSize` rows, and a visible hint when it scrolls inside its box.
 * Replaces `scroll={TABLE_SCROLL}`: the table is as wide as the sum of its
 * column widths (at least its container) instead of "max-content".
 */
export function DataTable<T extends object>({
  columns,
  secondary,
  pageSize = 20,
  pagination,
  expandable,
  stack = true,
  ...rest
}: Omit<TableProps<T>, "columns" | "scroll"> & {
  columns: DataColumn<T>[];
  /** Secondary fields, shown in an expandable row. */
  secondary?: (record: T) => ReactNode;
  pageSize?: number;
  /**
   * Below the tablet breakpoint (phone width) show the rows as stacked cards
   * (label + value, actions in the card's corner, no sideways scrolling, no
   * pinned column). Default true; `false` keeps the scrolling table (wide
   * matrix-like tables).
   */
  stack?: boolean;
}) {
  const wrap = useRef<HTMLDivElement>(null);
  const { cols, minWidth } = useMemo(() => prepareColumns(columns), [columns]);
  const hint = useScrollHint(wrap, ".ant-table-content");
  const phone = useMediaQuery(STACK_QUERY);
  const rows = (rest.dataSource ?? []).length;
  if (stack && phone) {
    return <DataCards<T> columns={columns} prepared={cols} secondary={secondary} pageSize={pageSize} pagination={pagination} expandable={expandable} {...rest} />;
  }
  return (
    <div className="data-table-wrap" ref={wrap} data-overflow={hint.overflow ? "true" : "false"}>
      <Table<T>
        size="middle"
        {...rest}
        className={["data-table", rest.className ?? ""].filter(Boolean).join(" ")}
        columns={cols}
        scroll={{ x: minWidth + (secondary || expandable?.expandedRowRender ? EXPAND_COL : 0) }}
        pagination={pagination ?? (rows > pageSize ? { pageSize, showSizeChanger: true, hideOnSinglePage: true } : false)}
        expandable={secondary ? { expandedRowRender: (r) => <div className="row-secondary">{secondary(r)}</div>, ...expandable } : expandable}
      />
      <ScrollHint {...hint} />
    </div>
  );
}

/** Media query of the stacked (card) table layout: below the tablet breakpoint. */
export const STACK_QUERY = `(max-width: ${BREAKPOINTS.tablet - 1}px)`;

/** Whether a media query matches now; follows changes. False where matchMedia is missing. */
export function useMediaQuery(query: string): boolean {
  const get = () => (typeof window !== "undefined" && typeof window.matchMedia === "function" ? !!window.matchMedia(query)?.matches : false);
  const [match, setMatch] = useState(get);
  useEffect(() => {
    if (typeof window.matchMedia !== "function") return;
    const mq = window.matchMedia(query);
    if (!mq) return;
    const on = () => setMatch(!!mq.matches);
    on();
    mq.addEventListener?.("change", on);
    return () => mq.removeEventListener?.("change", on);
  }, [query]);
  return match;
}

function cellValue<T>(record: T, dataIndex: unknown): unknown {
  if (dataIndex === undefined || dataIndex === null) return undefined;
  const path = Array.isArray(dataIndex) ? dataIndex : [dataIndex];
  let v: unknown = record;
  for (const k of path) v = v == null ? undefined : (v as Record<string, unknown>)[k as string];
  return v;
}

function titleText(t: unknown): ReactNode {
  return typeof t === "function" ? null : (t as ReactNode);
}

/**
 * DataTable's stacked mode (phone width): one card per row. The column with
 * `card: "title"` is the heading, the actions column sits in the card's top
 * right, `key` columns are label + value rows, `detail` columns and
 * `secondary` / `expandable` go under a 「详情」 toggle. Same pagination,
 * row attributes (onRow, rowClassName) and expansion state as the table.
 */
function DataCards<T extends object>({
  columns,
  prepared,
  secondary,
  pageSize,
  pagination,
  expandable,
  dataSource,
  rowKey,
  onRow,
  rowClassName,
  locale,
  loading,
  className,
  ...rest
}: Omit<TableProps<T>, "columns" | "scroll"> & {
  columns: DataColumn<T>[];
  prepared: TableColumnType<T>[];
  secondary?: (record: T) => ReactNode;
  pageSize: number;
}) {
  const data = (dataSource ?? []) as readonly T[];
  const pg = pagination === false ? null : pagination ?? (data.length > pageSize ? { pageSize, showSizeChanger: true, hideOnSinglePage: true } : null);
  const [ownPage, setOwnPage] = useState(1);
  const [ownSize, setOwnSize] = useState(pg?.pageSize ?? pageSize);
  const [ownOpen, setOwnOpen] = useState<readonly Key[]>(expandable?.defaultExpandedRowKeys ?? []);
  const size = pg?.pageSize ?? ownSize;
  const pages = Math.max(1, Math.ceil(data.length / size));
  const current = pg ? Math.min(Math.max(1, pg.current ?? ownPage), pages) : 1;
  const shown = pg ? data.slice((current - 1) * size, current * size) : data;
  const open = expandable?.expandedRowKeys ?? ownOpen;
  const keyOf = (r: T, i: number): Key =>
    typeof rowKey === "function" ? (rowKey as (r: T, i?: number) => Key)(r, i) : ((r as Record<string, unknown>)[(rowKey as string) ?? "key"] as Key) ?? i;
  const toggle = (r: T, k: Key) => {
    const was = open.includes(k);
    const next = was ? open.filter((x) => x !== k) : [...open, k];
    if (!expandable?.expandedRowKeys) setOwnOpen(next);
    expandable?.onExpandedRowsChange?.(next);
    expandable?.onExpand?.(!was, r);
  };
  const render = (c: TableColumnType<T>, r: T, i: number): ReactNode => {
    const v = cellValue(r, (c as { dataIndex?: unknown }).dataIndex);
    const out = c.render ? c.render(v, r, i) : v;
    return (out ?? null) as ReactNode;
  };
  // Without an explicit "title" column, the first column that declares no place is the card's heading.
  const implicitTitle = columns.some((c) => c.card === "title") ? -1 : columns.findIndex((c) => c.kind !== "actions" && c.card === undefined);
  const cols = columns.map((c, i) => ({
    def: c,
    col: prepared[i],
    role: (c.kind === "actions" ? "actions" : i === implicitTitle ? "title" : (c.card ?? "key")) as CardRole | "actions",
  }));
  const titleCol = cols.find((c) => c.role === "title");
  const actionCols = cols.filter((c) => c.role === "actions");
  const keyCols = cols.filter((c) => c.role === "key");
  const detailCols = cols.filter((c) => c.role === "detail");
  const expandRender = secondary ? (r: T) => <div className="row-secondary">{secondary(r)}</div> : expandable?.expandedRowRender;
  const field = (c: (typeof cols)[number], r: T, i: number, j: number) => (
    <div className="data-card-field" key={j}>
      <dt>{titleText(c.def.title)}</dt>
      <dd>{render(c.col, r, i)}</dd>
    </div>
  );
  if (loading && data.length === 0) {
    return (
      <div className="data-table-wrap data-cards-wrap" data-stacked="true">
        <Skeleton active paragraph={{ rows: 3 }} />
      </div>
    );
  }
  return (
    <div className="data-table-wrap data-cards-wrap" data-stacked="true" data-overflow="false" {...pickData(rest)}>
      {data.length === 0 ? (
        <div className="data-cards-empty">{(locale?.emptyText as ReactNode) ?? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无数据" />}</div>
      ) : (
        <ul className={["data-cards", className ?? ""].filter(Boolean).join(" ")}>
          {shown.map((r, i) => {
            const k = keyOf(r, i);
            const attrs = (onRow?.(r, i) ?? {}) as HTMLAttributes<HTMLElement> & Record<string, unknown>;
            const extraCls = typeof rowClassName === "function" ? rowClassName(r, i, 0) : rowClassName ?? "";
            const canExpand = !!expandRender && (expandable?.rowExpandable ? expandable.rowExpandable(r) : true);
            const hasMore = canExpand || detailCols.length > 0;
            const isOpen = open.includes(k);
            const moreId = `card-more-${String(k)}`;
            return (
              <li {...attrs} key={k} data-row-key={String(k)} className={["data-card", extraCls, attrs.className ?? ""].filter(Boolean).join(" ")}>
                <div className="data-card-head">
                  <div className="data-card-title">{titleCol ? render(titleCol.col, r, i) : null}</div>
                  {actionCols.length > 0 ? (
                    <div className="data-card-actions" data-card-actions="">
                      {actionCols.map((c, j) => (
                        <span key={j}>{render(c.col, r, i)}</span>
                      ))}
                    </div>
                  ) : null}
                </div>
                {keyCols.length > 0 ? <dl className="data-card-fields">{keyCols.map((c, j) => field(c, r, i, j))}</dl> : null}
                {hasMore ? (
                  <>
                    <button type="button" className="data-card-toggle explain-toggle" aria-expanded={isOpen} aria-controls={moreId} onClick={() => toggle(r, k)}>
                      {isOpen ? "收起详情" : "详情"}
                    </button>
                    <div id={moreId} className="data-card-more" hidden={!isOpen}>
                      {isOpen ? (
                        <>
                          {detailCols.length > 0 ? <dl className="data-card-fields">{detailCols.map((c, j) => field(c, r, i, j))}</dl> : null}
                          {canExpand && expandRender ? expandRender(r, i, 0, true) : null}
                        </>
                      ) : null}
                    </div>
                  </>
                ) : null}
              </li>
            );
          })}
        </ul>
      )}
      {pg && !(pg.hideOnSinglePage && pages <= 1) ? (
        <Pagination
          className="data-cards-pagination"
          size="small"
          current={current}
          pageSize={size}
          total={data.length}
          showSizeChanger={pg.showSizeChanger}
          pageSizeOptions={pg.pageSizeOptions}
          showTotal={pg.showTotal}
          onChange={(p, s) => {
            setOwnPage(s !== size ? 1 : p);
            setOwnSize(s);
            pg.onChange?.(p, s);
          }}
        />
      ) : null}
    </div>
  );
}

/** data-* attributes passed to a DataTable (e.g. data-testid) go onto the card list's wrapper. */
function pickData(o: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(o).filter(([k]) => k.startsWith("data-") || k.startsWith("aria-")));
}

/**
 * Wrapper for wide grids (unlock matrix, coverage table): the grid scrolls
 * inside this box, its first column stays frozen (opaque), and a hint says
 * there is more to the right. Put a `<table>` inside; cells hold <GridCell>.
 * The box is focusable so the keyboard can scroll it.
 */
export function WideGrid({ children, label }: { children: ReactNode; label: string }) {
  const box = useRef<HTMLDivElement>(null);
  const hint = useScrollHint(box);
  return (
    <div className="wide-grid" data-overflow={hint.overflow ? "true" : "false"}>
      <div className="wide-grid-scroll" ref={box} tabIndex={0} role="region" aria-label={label}>
        {children}
      </div>
      <ScrollHint {...hint} />
    </div>
  );
}

/**
 * A compact grid cell: the result on one line (chips never wrap), an optional
 * one-line note under it, cut with "…" and readable on hover/focus.
 */
export function GridCell({ children, note }: { children: ReactNode; note?: string | null }) {
  return (
    <div className="grid-cell">
      <div className="grid-cell-main">{children}</div>
      {note ? <EllipsisText className="grid-cell-note" text={note} /> : null}
    </div>
  );
}

// ================================================================ regions ===

const REGION_NAMES: Record<string, string> = {
  hk: "香港",
  tw: "台湾",
  mo: "澳门",
  cn: "中国大陆",
  jp: "日本",
  kr: "韩国",
  sg: "新加坡",
  my: "马来西亚",
  th: "泰国",
  vn: "越南",
  ph: "菲律宾",
  id: "印度尼西亚",
  in: "印度",
  au: "澳大利亚",
  us: "美国",
  ca: "加拿大",
  gb: "英国",
  uk: "英国",
  de: "德国",
  fr: "法国",
  nl: "荷兰",
  tr: "土耳其",
  ru: "俄罗斯",
  br: "巴西",
};

/** "hk" → "香港 · HK"; unknown codes stay as typed; empty → "未设地区". */
export function regionLabel(code: string | undefined | null): string {
  const c = (code ?? "").trim();
  if (!c) return "未设地区";
  const name = REGION_NAMES[c.toLowerCase()];
  return name ? `${name} · ${c.toUpperCase()}` : c.toUpperCase();
}

export const REGION_CODES = Object.keys(REGION_NAMES).filter((c) => c !== "uk");

/** The fields a group label needs (RegionGroup, RegionGroupView, unlock rows …). */
export interface GroupNameLike {
  id: string;
  name: string;
  region?: string;
}

const groupNameKey = (name: string) => name.trim().toLocaleLowerCase();

/**
 * Display name of a region group that stays unambiguous: the plain name
 * when no other group in `all` has the same name (trimmed, case-insensitive),
 * otherwise the name with its region and its stable ID, e.g.
 * "香港（香港 · HK · hk-home）". Pickers, lists and messages all use it so
 * two groups called the same can always be told apart.
 */
export function groupLabel(g: GroupNameLike, all: readonly GroupNameLike[] | null | undefined): string {
  const name = g.name?.trim() || g.id;
  if (!all || !isDuplicateGroupName(g, all)) return name;
  return `${name}（${regionLabel(g.region)} · ${g.id}）`;
}

/** Another group in `all` has the same display name. */
export function isDuplicateGroupName(g: GroupNameLike, all: readonly GroupNameLike[]): boolean {
  const k = groupNameKey(g.name?.trim() || g.id);
  return all.some((o) => o.id !== g.id && groupNameKey(o.name?.trim() || o.id) === k);
}
