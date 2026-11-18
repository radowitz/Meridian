// 解锁: one section per region (Global first, then the regions that have
// exits). Each section is a service × exit table; a global service is
// probed on every exit, a regional one only on exits of its region (the
// panel's planner enforces it, GET /api/unlock/matrix lays it out). AI
// services are not probed. Each row shows where its rules send it now
// (当前) apart from the recommendation. After the recommendation each row
// offers 确认 (adopt it) and 手动 (a region group of the row's scope, or
// pin one of its exits); all save through POST /api/unlock/adopt and take
// the rules' automatic apply, whose outcome RulesApplyLine shows. A save
// refreshes the matrix and the shared topology, so the Rules page shows the
// new target.

import { App as AntApp, Button, Select, Tooltip } from "antd";
import { useEffect, useRef, useState } from "react";
import * as api from "./api";
import { useStatus, useTopologyDoc } from "./state";
import "./layout_c.css";
import type { RulesFastApply, UnlockMatrixView, UnlockCell, UnlockCellState, UnlockCurrent, UnlockMatrixRegion, UnlockMatrixService } from "./types";
import { ApiErrorAlert, DataView, EmptyState, Page, RulesApplyLine, Section, WideGrid, useAction, useApi, useRulesApplied } from "./ui";

export const CELL_LABEL: Record<UnlockCellState, string> = {
  unlocked: "解锁",
  local: "仅本地",
  blocked: "不可用",
  unverified: "未测到",
  untested: "未测",
};

const CELL_ORDER: Record<UnlockCellState, number> = { unlocked: 0, local: 1, blocked: 2, unverified: 3, untested: 4 };

/** The manual picker's choices: the row's exits (its probe scope), unlocked first, each with its result word. */
export function pickOptions(region: UnlockMatrixRegion, s: UnlockMatrixService) {
  const name = new Map(region.exits.map((e) => [e.id, e.name || e.id]));
  return s.cells
    .map((c, i) => ({ c, i }))
    .sort((a, b) => CELL_ORDER[a.c.state] - CELL_ORDER[b.c.state] || a.i - b.i)
    .map(({ c }) => ({ value: c.exit_id, label: `${name.get(c.exit_id) ?? c.exit_id} · ${CELL_LABEL[c.state]}`, state: c.state }));
}

/** The manual picker's two groups: 出口组 (name · preferred exit) and 具体节点 (pickOptions). Values: "g:<id>" / "e:<id>". */
export function pickGroups(region: UnlockMatrixRegion, s: UnlockMatrixService) {
  const groups = (s.groups ?? []).map((g) => ({ value: `g:${g.id}`, label: g.preferred_name ? `${g.name} · ${g.preferred_name}` : g.name, state: "" }));
  const exits = pickOptions(region, s).map((o) => ({ ...o, value: `e:${o.value}` }));
  return [
    ...(groups.length ? [{ label: "出口组", options: groups }] : []),
    { label: "具体节点", options: exits },
  ];
}

/** The service's actual direction: "<组名> · <首选出口>" or "<节点>（钉死）". */
export function currentLabel(c: UnlockCurrent | null | undefined): string {
  if (!c) return "";
  if (c.mixed?.length) return c.mixed.map((m) => currentLabel(m)).join(" / ");
  if (c.pinned) return `${c.exit_name || c.exit}（钉死）`;
  const g = c.group_name || c.group || "";
  return c.exit_name || c.exit ? `${g} · ${c.exit_name || c.exit}` : g;
}

function Cell({ c }: { c: UnlockCell }) {
  const label = CELL_LABEL[c.state];
  const region = c.region ? c.region.toUpperCase() : "";
  const body = (
    <span className={`ucell ucell-${c.state}`} data-state={c.state} data-testid={`cell-${c.exit_id}`} tabIndex={c.reason ? 0 : undefined} aria-label={c.reason ? `${label}：${c.reason}` : undefined}>
      {label}
      {region && c.state !== "untested" ? <span className="ucell-region">{region}</span> : null}
    </span>
  );
  return c.reason ? <Tooltip title={c.reason}>{body}</Tooltip> : body;
}

/** A pending two-step save: the service, the exit (and whether picked by hand) and how many other rules move. */
export interface PendingSave {
  id: string;
  exit: string;
  manual: boolean;
  others: number;
}

function RecCell({
  region,
  s,
  canAdopt,
  adopting,
  confirm,
  picking,
  onAdopt,
  onManual,
  onPick,
  onCancel,
}: {
  region: UnlockMatrixRegion;
  s: UnlockMatrixService;
  canAdopt: boolean;
  adopting: string;
  confirm: PendingSave | null;
  picking: { id: string; region: string; exit?: string } | null;
  onAdopt: (s: UnlockMatrixService) => void;
  onManual: (region: UnlockMatrixRegion, s: UnlockMatrixService, pick: string) => void;
  onPick: (p: { id: string; region: string; exit?: string } | null) => void;
  onCancel: () => void;
}) {
  if (s.rules.length === 0) return s.recommend ? <span>{s.recommend.exit_name || s.recommend.exit_id}</span> : null;
  const pickName = (v: string) =>
    v.startsWith("g:") ? s.groups?.find((g) => `g:${g.id}` === v)?.name || v.slice(2) : region.exits.find((e) => `e:${e.id}` === v)?.name || v.slice(2);
  const pending = confirm?.id === s.id ? confirm : null;
  const open = picking?.id === s.id && picking.region === region.code;
  if (open) {
    const chosen = picking?.exit;
    return (
      <span className="unlock-pick" data-testid={`manual-${region.code}-${s.id}`}>
        <Select
          size="small"
          className="unlock-pick-select"
          aria-label={`${s.name} 出口`}
          value={chosen}
          onChange={(v: string) => onPick({ id: s.id, region: region.code, exit: v })}
          options={pickGroups(region, s).map((grp) => ({
            label: grp.label,
            title: grp.label,
            options: grp.options.map((o) => ({ value: o.value, label: <span className={o.state ? `ucell-${o.state}` : undefined}>{o.label}</span>, title: o.label })),
          }))}
          popupMatchSelectWidth={false}
        />
        {pending?.manual && pending.exit === chosen ? <span className="unlock-impact">同时影响 {pending.others} 条规则</span> : null}
        <Button
          size="small"
          type="primary"
          disabled={!canAdopt || !chosen}
          loading={adopting === s.id}
          onClick={() => chosen && onManual(region, s, chosen)}
          aria-label={`保存 ${s.name} → ${chosen ? pickName(chosen) : ""}`}
        >
          保存
        </Button>
        <Button size="small" type="text" onClick={() => onPick(null)}>
          取消
        </Button>
      </span>
    );
  }
  const manual = (
    <Button size="small" disabled={!canAdopt} onClick={() => onPick({ id: s.id, region: region.code })} aria-label={`手动 ${s.name}`}>
      手动
    </Button>
  );
  if (!s.recommend) return <span className="unlock-rec-inner">{manual}</span>;
  const target = s.recommend.exit_name || s.recommend.exit_id;
  return (
    <span className="unlock-rec-inner">
      <span>{target}</span>
      {s.recommend.adopted ? (
        <span className="muted">在用</span>
      ) : pending && !pending.manual ? (
        <span className="unlock-confirm" data-testid={`adopt-confirm-${s.id}`}>
          <span className="unlock-impact">同时影响 {pending.others} 条规则</span>
          <Button size="small" type="primary" disabled={!canAdopt} loading={adopting === s.id} onClick={() => onAdopt(s)} aria-label={`确认采用 ${s.name} → ${target}`}>
            确认
          </Button>
          <Button size="small" type="text" onClick={onCancel}>
            取消
          </Button>
        </span>
      ) : (
        <Button size="small" disabled={!canAdopt} loading={adopting === s.id} onClick={() => onAdopt(s)} aria-label={`确认 ${s.name} → ${target}`}>
          确认
        </Button>
      )}
      {pending && !pending.manual ? null : manual}
    </span>
  );
}

function RegionTable({
  region,
  ...rest
}: { region: UnlockMatrixRegion } & Omit<Parameters<typeof RecCell>[0], "region" | "s">) {
  return (
    <WideGrid label={`${region.name}：服务 × 出口`}>
      <table className="unlock-table" data-testid={`unlock-table-${region.code}`}>
        <thead>
          <tr>
            <th scope="col">服务</th>
            {region.exits.map((e) => (
              <th scope="col" key={e.id}>
                {e.name || e.id}
              </th>
            ))}
            <th scope="col">当前</th>
            <th scope="col">推荐</th>
          </tr>
        </thead>
        <tbody>
          {region.services.map((s) => (
            <tr key={s.id} data-testid={`row-${region.code}-${s.id}`}>
              <th scope="row">{s.name}</th>
              {s.cells.map((c) => (
                <td key={c.exit_id}>
                  <Cell c={c} />
                </td>
              ))}
              <td className="unlock-current" data-testid={`current-${region.code}-${s.id}`}>
                {currentLabel(s.current)}
              </td>
              <td className="unlock-rec">
                <RecCell region={region} s={s} {...rest} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </WideGrid>
  );
}

/** How long the page waits after one matrix answer before asking again while a probe runs. */
export const UNLOCK_POLL_MS = 2000;

export default function UnlockPage() {
  // Every matrix read (first load, poll, refresh after a save / stop / new
  // probe) takes a generation; only the newest read's answer is shown, so a
  // slow older answer (a probe still "running") never overwrites a newer one
  // or restarts the polling.
  const gen = useRef(0);
  const latest = useRef<UnlockMatrixView | undefined>(undefined);
  const matrix = useApi(async () => {
    const my = ++gen.current;
    const r = await api.getUnlockMatrix();
    if (my !== gen.current && latest.current) return latest.current;
    latest.current = r;
    return r;
  }, []);
  const { status, refresh } = useStatus();
  const { message } = AntApp.useApp();
  const runAct = useAction();
  const adoptAct = useAction();
  const rulesApplied = useRulesApplied();
  const doc = useTopologyDoc();
  const [started, setStarted] = useState("");
  const [applied, setApplied] = useState<{ fa?: RulesFastApply; req?: boolean } | null>(null);

  const running = matrix.data?.running || started;
  const available = (matrix.data?.available ?? false) && (status ? status.probe_available : true);

  // A fresh read outside the polling; its answer is shown only when no
  // newer read started meanwhile.
  const reloadMatrix = async () => {
    const my = ++gen.current;
    try {
      const r = await api.getUnlockMatrix();
      if (my !== gen.current) return;
      latest.current = r;
      matrix.setData(r);
    } catch {
      /* keep the last state */
    }
  };

  // While a probe runs, the table fills in: one read at a time, the next
  // one scheduled after the answer; unmount or the end of the probe cancels
  // the read in flight.
  useEffect(() => {
    if (!running) return;
    const ctl = new AbortController();
    let timer: number | undefined;
    const tick = async () => {
      const my = ++gen.current;
      try {
        const r = await api.getUnlockMatrix(ctl.signal);
        if (ctl.signal.aborted) return;
        // A newer read (a reload after a save / stop / new probe) superseded
        // this answer: drop it, but keep polling while the probe still runs
        // (the effect is torn down, aborting this tick, once it stops).
        if (my === gen.current) {
          latest.current = r;
          matrix.setData(r);
          if (!r.running) {
            setStarted("");
            refresh();
            return;
          }
        }
      } catch {
        /* keep the last state */
      }
      if (!ctl.signal.aborted) timer = window.setTimeout(tick, UNLOCK_POLL_MS);
    };
    timer = window.setTimeout(tick, UNLOCK_POLL_MS);
    return () => {
      ctl.abort();
      if (timer !== undefined) window.clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [running]);

  const probe = (scope: string) =>
    void runAct.run(async () => {
      const r = await api.runUnlock({ scope });
      gen.current++; // answers read before this probe started are stale
      setStarted(r.job.id);
    }, scope);

  // A save reorders the whole region group: when other rules use it, the
  // first click asks the server what moves and the second one saves.
  const [confirm, setConfirm] = useState<PendingSave | null>(null);
  const [picking, setPicking] = useState<{ id: string; region: string; exit?: string } | null>(null);
  const save = (s: UnlockMatrixService, exit: string, exitName: string, manual: boolean, identity?: string, group?: string) =>
    void adoptAct.run(
      async () => {
        const opts: api.ManualPick | undefined = manual ? { manual: true, identity: identity ?? "", ...(group ? { group } : {}) } : undefined;
        const key = group ? `g:${group}` : manual ? `e:${exit}` : exit;
        if (!(confirm?.id === s.id && confirm.exit === key && confirm.manual === manual)) {
          const p = await api.previewAdoptUnlock(s.id, exit, opts);
          if (p.other_rules > 0) {
            setConfirm({ id: s.id, exit: key, manual, others: p.other_rules });
            return;
          }
        }
        setConfirm(null);
        const r = await api.adoptUnlock(s.id, exit, opts);
        setPicking(null);
        setApplied({ fa: r.fast_apply, req: r.apply_required });
        rulesApplied(r);
        message.success(`${s.name} → ${exitName}`);
        void reloadMatrix();
        // The Rules page reads the shared topology: take the saved targets
        // (and, for 确认, the group's selection) without dropping local edits.
        try {
          const fresh = await api.getTopology();
          const ids = new Set(r.rules ?? []);
          doc.applyServerChange((t) => ({
            ...t,
            rules: t.rules.map((x) => {
              const y = ids.has(x.id) ? fresh.rules.find((f) => f.id === x.id) : undefined;
              return y ? { ...x, target_group: y.target_group, target_exit: y.target_exit } : x;
            }),
            region_groups: t.region_groups?.map((g) => (g.id === r.group ? (fresh.region_groups ?? []).find((f) => f.id === g.id) ?? g : g)),
          }));
        } catch {
          /* the next reload shows it */
        }
      },
      s.id,
      (e) => {
        // The results or the exit changed meanwhile: show the current table.
        if (e.status === 409) {
          setConfirm(null);
          void reloadMatrix();
        }
      },
    );
  const adopt = (s: UnlockMatrixService) => save(s, s.recommend!.exit_id, s.recommend!.exit_name || s.recommend!.exit_id, false);
  const manual = (region: UnlockMatrixRegion, s: UnlockMatrixService, pick: string) => {
    if (pick.startsWith("g:")) {
      const g = s.groups?.find((x) => `g:${x.id}` === pick);
      if (g) save(s, "", g.name || g.id, true, g.identity, g.id);
      return;
    }
    const exit = pick.slice(2);
    const e = region.exits.find((x) => x.id === exit);
    save(s, exit, e?.name || exit, true, e?.identity);
  };
  const pick = (p: { id: string; region: string; exit?: string } | null) => {
    setPicking(p);
    setConfirm(null);
  };

  const busy = !!running || !available;

  return (
    <Page
      title="解锁"
      extra={
        running ? (
          <Button
            danger
            onClick={() =>
              void runAct.run(async () => {
                await api.cancelUnlockJob(running);
                setStarted("");
                void reloadMatrix();
              }, "cancel")
            }
          >
            停止
          </Button>
        ) : (
          <Button type="primary" disabled={busy} loading={runAct.busy === "all"} onClick={() => probe("all")}>
            全部探测
          </Button>
        )
      }
    >
      <ApiErrorAlert error={runAct.error} onClose={runAct.clear} />
      <ApiErrorAlert error={adoptAct.error} onClose={adoptAct.clear} />
      {applied ? (
        <div className="status-line">
          <RulesApplyLine fa={applied.fa} applyRequired={applied.req} />
        </div>
      ) : null}
      <DataView state={matrix} rows={6}>
        {(m) =>
          m.regions.length === 0 ? (
            <EmptyState title="还没有出口" />
          ) : (
            <>
              {m.regions.map((r) => (
                <Section
                  key={r.code}
                  id={`unlock-${r.code}`}
                  title={r.name}
                  extra={
                    <Button size="small" disabled={busy} loading={runAct.busy === r.code} onClick={() => probe(r.code)} aria-label={`探测${r.name}`}>
                      探测
                    </Button>
                  }
                >
                  <RegionTable
                    region={r}
                    canAdopt={!running && !adoptAct.busy}
                    adopting={adoptAct.busy || ""}
                    onAdopt={adopt}
                    onManual={manual}
                    onPick={pick}
                    picking={picking}
                    confirm={confirm}
                    onCancel={() => setConfirm(null)}
                  />
                </Section>
              ))}
            </>
          )
        }
      </DataView>
    </Page>
  );
}
