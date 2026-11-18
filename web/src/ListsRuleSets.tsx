// 名单 → 规则集: every subscribed rule-set with its download state, a
// per-set update and an "update all" job (POST /api/rule-sets/update-all,
// polled until done). Editing stays on the rules page.

import { Button, Space, Typography } from "antd";
import { useEffect, useState } from "react";
import * as api from "./api";
import type { ApiError } from "./api";
import { href } from "./state";
import type { RuleSetBulkJob, RuleSetView } from "./types";
import { ApiErrorAlert, DataTable, Help, Link, Section, StatusTag, TimeText, useAction, useApi, type StatusKind } from "./ui";

/** How often a running "update all" job is re-read. */
export const RS_POLL_MS = 2000;

export function entryCount(v: RuleSetView): number | undefined {
  const c = v.status.counts;
  if (!c) return undefined;
  return Object.values(c).reduce((a, b) => a + b, 0);
}

/** Stale: the last attempt failed, or the active version is older than 2× the interval. */
export function isStale(v: RuleSetView, now = Date.now()): boolean {
  const s = v.status;
  if (s.last_error) return true;
  if (!s.fetched_at) return false;
  const iv = (v.rule_set.interval_sec || 86400) * 1000;
  return now - Date.parse(s.fetched_at) > 2 * iv;
}

function stateTag(v: RuleSetView): { kind: StatusKind; label: string } {
  switch (v.status.state) {
    case "fetching":
      return { kind: "running", label: "下载中" };
    case "held":
      return { kind: "attention", label: "新版本待确认" };
    case "failed":
      return { kind: "failed", label: "失败" };
    case "never":
      return { kind: "pending", label: "未下载" };
    default:
      return v.status.last_error ? { kind: "attention", label: "失败，用旧版" } : { kind: "ok", label: "正常" };
  }
}

/** First candidate error, without the other candidates. */
export function shortError(e: string): string {
  const first = e.split("；")[0];
  return first.length > 80 ? first.slice(0, 79) + "…" : first;
}

export default function ListsRuleSets() {
  const list = useApi(() => api.listRuleSets(), []);
  const act = useAction();
  const [job, setJob] = useState<RuleSetBulkJob | null>(null);
  const running = job?.state === "running";

  // Pick up a job that is already running when the page opens.
  useEffect(() => {
    const ctl = new AbortController();
    api
      .getRuleSetsUpdateAll(ctl.signal)
      .then((r) => !ctl.signal.aborted && r.job?.state === "running" && setJob(r.job))
      .catch(() => undefined);
    return () => ctl.abort();
  }, []);

  useEffect(() => {
    if (!running) return;
    const ctl = new AbortController();
    let t: number | undefined;
    const tick = async () => {
      try {
        const r = await api.getRuleSetsUpdateAll(ctl.signal);
        if (ctl.signal.aborted) return;
        if (r.job) setJob(r.job);
        void list.reload();
        if (r.job && r.job.state !== "running") return;
      } catch {
        /* keep the last state */
      }
      if (!ctl.signal.aborted) t = window.setTimeout(tick, RS_POLL_MS);
    };
    t = window.setTimeout(tick, RS_POLL_MS);
    return () => {
      ctl.abort();
      if (t !== undefined) window.clearTimeout(t);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [job?.id, running]);

  const updateAll = () =>
    act.run(async () => {
      try {
        const r = await api.updateAllRuleSets();
        setJob(r.job);
      } catch (e) {
        const ae = e as ApiError;
        const j = (ae.body as { job?: RuleSetBulkJob } | undefined)?.job;
        if (ae.code === "update_running" && j) {
          setJob(j);
          return;
        }
        throw e;
      }
    }, "rs-all");

  const updateOne = (id: string) =>
    act.run(async () => {
      const r = await api.fetchRuleSet(id);
      list.setData((d) => (d ? { ...d, rule_sets: d.rule_sets.map((x) => (x.rule_set.id === id ? r : x)) } : d));
      window.setTimeout(() => void list.reload(), RS_POLL_MS);
    }, `rs:${id}`);

  const rows = list.data?.rule_sets ?? [];
  if (list.error?.code === "not_found" || (!list.loading && !list.error && rows.length === 0)) return null;

  return (
    <Section
      title="规则集"
      id="rule-sets"
      extra={
        <Button size="small" disabled={rows.length === 0 || running} loading={act.busy === "rs-all" || running} onClick={() => void updateAll()}>
          {running && job ? `全部更新 ${job.done}/${job.total}` : "全部更新"}
        </Button>
      }
    >
      {act.error ? <ApiErrorAlert error={act.error} onClose={act.clear} /> : null}
      {list.error ? <ApiErrorAlert error={list.error} /> : null}
      {job && job.state === "done" && job.failed.length > 0 ? (
        <Typography.Paragraph type="warning" data-testid="rs-bulk-failed">
          {`${job.failed.length} 个失败`}
        </Typography.Paragraph>
      ) : null}
      <DataTable
        size="small"
        rowKey={(r) => r.rule_set.id}
        pageSize={100}
        dataSource={rows}
        loading={list.loading && !list.data}
        columns={[
          {
            title: "名称",
            kind: "flex",
            width: 200,
            render: (_, r) => (
              <Space size={6} wrap>
                <span>{r.rule_set.name || r.rule_set.id}</span>
                {isStale(r) ? (
                  <StatusTag kind="attention" data-testid={`rs-stale-${r.rule_set.id}`}>
                    过期
                  </StatusTag>
                ) : null}
              </Space>
            ),
          },
          { title: "条数", kind: "fixed", width: 80, render: (_, r) => entryCount(r)?.toLocaleString() ?? "—" },
          { title: "更新于", kind: "fixed", width: 130, render: (_, r) => <TimeText value={r.status.fetched_at} /> },
          {
            title: "状态",
            kind: "fixed",
            width: 200,
            render: (_, r) => {
              const s = stateTag(r);
              return (
                <Space direction="vertical" size={0}>
                  <StatusTag kind={s.kind} title={r.status.last_error}>
                    {s.label}
                  </StatusTag>
                  {r.status.last_error ? (
                    <Typography.Text type="secondary" className="mono-small">
                      {shortError(r.status.last_error)}
                    </Typography.Text>
                  ) : null}
                </Space>
              );
            },
          },
          {
            title: "使用",
            kind: "flex",
            width: 140,
            render: (_, r) =>
              r.used_by.length === 0 ? (
                <Typography.Text type="secondary">—</Typography.Text>
              ) : (
                <Space size={4} wrap>
                  {r.used_by.map((u) => (
                    <Link key={u.rule_id} to={href("rules")}>
                      {`#${u.position} ${u.name}`}
                    </Link>
                  ))}
                </Space>
              ),
          },
          {
            title: "操作",
            kind: "fixed",
            width: 90,
            render: (_, r) => (
              <Button
                size="small"
                type="link"
                disabled={r.status.state === "fetching" || running}
                loading={act.busy === `rs:${r.rule_set.id}`}
                onClick={() => void updateOne(r.rule_set.id)}
              >
                立即更新
              </Button>
            ),
          },
        ]}
      />
      <Help title="规则集">
        规则集按各自的间隔自动下载（默认 24 小时）。下载失败时继续使用上一版，并在 5 分钟、15 分钟、1 小时后重试，之后回到正常间隔。最后一次下载失败，或版本超过两个间隔没有更新，标为「过期」。增删和编辑在分流规则页。
      </Help>
    </Section>
  );
}
