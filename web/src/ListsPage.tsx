import {
  Help,
  Note,
} from "./ui";
// 名单: where geosite / China IP lists are downloaded from, a manual update,
// and per-list results (actual source, fallback, kept previous version).
// There is no scheduler: lists change only when someone starts an update.
// The resolution settings that used to be the last section of this page
// have their own page (#/dns); the section stays as a short pointer, and
// `#/lists/dns` / `#/lists?section=dns` scroll to it.

import { CloudDownloadOutlined } from "@ant-design/icons";
import { Alert, App as AntApp, Button, Space, Tooltip, Typography } from "antd";
import { useEffect, useMemo, useState } from "react";
import * as api from "./api";
import type { ApiError } from "./api";
import { href, useRouter, useStatus, useTopologyDoc } from "./state";
import type { ListAttempt, ListKind, ListResult, ListsJob, ListsPolicy, ListsReport, ListsView } from "./types";
import {
  DataTable,
  ApiErrorAlert,
  DataView,
  Facts,
  Link,
  LinkButton,
  Mono,
  Page,
  Section,
  StatusTag,
  TimeText,
  useAction,
  useApi,
  type StatusKind,
} from "./ui";

const SOURCE_LABEL: Record<string, string> = { domestic: "国内源", overseas: "海外源", derived: "由 geosite 派生" };

function hostOf(url: string) {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

const POLICY: Record<ListsPolicy, { title: string; desc: (v: ListsView) => string }> = {
  domestic: {
    title: "国内源",
    desc: (v) => `只从 ${hostOf(v.sources.find((s) => s.name === "domestic")?.geosite_base ?? "")}（GitHub 内容的国内可达镜像）下载，失败就保留上一版。`,
  },
  overseas: {
    title: "海外源",
    desc: (v) => `只从 ${hostOf(v.sources.find((s) => s.name === "overseas")?.geosite_base ?? "")} 下载；国内直连常超时。`,
  },
  automatic: {
    title: "全自动",
    desc: () => "每个名单先试国内源，失败再试海外源；两个都失败就保留上一版。",
  },
};

const KIND_LABEL: Record<string, string> = { geosite: "geosite", keyword: "关键词", chnroute: "China IP" };

function listName(l: string) {
  if (l.startsWith("geosite:")) return l.slice(8);
  if (l.startsWith("keyword:")) return l.slice(8);
  if (l === "chnroute4") return "China IPv4";
  if (l === "chnroute6") return "China IPv6";
  return l;
}

function resultStatus(r: ListResult): { kind: StatusKind; label: string } {
  if (r.updated) {
    const fellBack = (r.attempts ?? []).some((a) => !a.ok);
    return fellBack ? { kind: "ok", label: "已更新（换源后）" } : { kind: "ok", label: "已更新" };
  }
  if (r.kept && r.current) return { kind: "attention", label: "失败，保留上一版" };
  return { kind: "failed", label: "失败，没有可用版本" };
}

function Attempts({ attempts }: { attempts: ListAttempt[] | undefined }) {
  if (!attempts || attempts.length === 0) return <Typography.Text type="secondary">—</Typography.Text>;
  return (
    <Space direction="vertical" size={2}>
      {attempts.map((a, i) => (
        <Tooltip key={i} title={<span className="mono-small">{a.url}</span>}>
          <Space size={4}>
            <StatusTag kind={a.ok ? "ok" : "failed"}>{`${SOURCE_LABEL[a.source] ?? a.source} ${a.ok ? "成功" : "失败"}`}</StatusTag>
            <Typography.Text type="secondary">{(a.duration_ms / 1000).toFixed(1)} s</Typography.Text>
            {a.error ? <Typography.Text type="danger">{a.error}</Typography.Text> : null}
          </Space>
        </Tooltip>
      ))}
    </Space>
  );
}

function ReportTable({ report }: { report: ListsReport }) {
  return (
    <DataTable
      size="small"
      rowKey="list"
      pageSize={50}
      dataSource={report.lists ?? []}
      secondary={(r) => (
        <Facts
          items={[
            [
              "生效来源",
              (() => {
                const src = r.updated ? r.source : r.current?.source;
                const url = r.updated ? r.url : r.current?.url;
                return src ? (
                  <span key="s">
                    {SOURCE_LABEL[src] ?? src} <Mono>{url}</Mono>
                  </span>
                ) : (
                  "—"
                );
              })(),
            ],
            ["版本时间", <TimeText key="t" value={r.current?.updated_at} />],
            ["条数", (r.current?.count ?? r.count ?? "—").toLocaleString()],
            ["文件", String(r.current?.files ?? r.files ?? "—")],
            [
              "丢弃",
              r.dropped && Object.keys(r.dropped).length > 0
                ? `${Object.entries(r.dropped)
                    .map(([k, n]) => `${k} ${n}`)
                    .join("，")}（domain-set 表达不了 keyword: 和 regexp: 条目，丢弃并计数）`
                : "—",
            ],
          ]}
        />
      )}
      columns={[
        {
          title: "名单",
          kind: "flex",
          width: 170,
          render: (_, r) => (
            <Space size={4} wrap>
              <span className="muted">{KIND_LABEL[r.kind] ?? r.kind}</span>
              <Mono>{listName(r.list)}</Mono>
            </Space>
          ),
        },
        {
          title: "结果",
          kind: "fixed",
          width: 140,
          render: (_, r) => {
            const s = resultStatus(r);
            return <StatusTag kind={s.kind} title={r.error}>{s.label}</StatusTag>;
          },
        },
        { title: "尝试", kind: "flex", width: 200, render: (_, r) => <Attempts attempts={r.attempts} /> },
      ]}
    />
  );
}

function JobView({ job }: { job: ListsJob }) {
  const rep = job.report;
  const head: { kind: StatusKind; label: string } =
    job.state === "running"
      ? { kind: "running", label: "更新中" }
      : job.state === "failed"
        ? { kind: "failed", label: "没有执行" }
        : rep?.ok
          ? { kind: "ok", label: "全部更新" }
          : rep?.partial
            ? { kind: "attention", label: "部分更新" }
            : { kind: "failed", label: "全部失败" };
  const kept = (rep?.lists ?? []).filter((l) => !l.updated && l.kept && l.current).length;
  return (
    <Space direction="vertical" size={12} style={{ width: "100%" }} data-testid="lists-job">
      <Facts
        items={[
          ["状态", <StatusTag kind={head.kind}>{head.label}</StatusTag>],
          ["来源策略", POLICY[job.policy]?.title ?? job.policy],
          ["时间", <TimeText value={job.finished_at || job.started_at} />],
        ]}
      />
      {job.state === "failed" ? (
        <Alert type="error" showIcon message="宿主没有执行这次更新，名单都没有改动" description={job.error} />
      ) : null}
      {job.state === "done" && job.error ? <Alert type="warning" showIcon message={job.error} /> : null}
      {kept > 0 ? (
        <Alert type="warning" showIcon message={`${kept} 个名单下载或校验失败，网关上继续使用上一版。`} />
      ) : null}
      {rep?.error ? <Alert type="error" showIcon message={rep.error} /> : null}
      {(rep?.warnings ?? []).map((w) => (
        <Alert key={w} type="warning" showIcon message={w} />
      ))}
      {rep ? <ReportTable report={rep} /> : null}
    </Space>
  );
}

/** How often the host lists status is re-read while a SmartDNS reload is pending. */
export const RELOAD_POLL_MS = 3000;

export default function ListsPage() {
  const view = useApi(() => api.getLists(), []);
  const doc = useTopologyDoc();
  const { message } = AntApp.useApp();
  const act = useAction();
  const [job, setJob] = useState<ListsJob | null>(null);
  const hostStatus = useApi(() => api.getListsStatus(), []);
  const { status, refresh: refreshStatus } = useStatus();
  const { route } = useRouter();
  const v = view.data;
  const wantsDNS = route.params[0] === "dns" || route.query.get("section") === "dns";

  // The old way in to the resolution settings: bring its pointer into view.
  useEffect(() => {
    if (!wantsDNS) return;
    const t = window.setTimeout(() => document.getElementById("dns")?.scrollIntoView?.({ behavior: "smooth" }), 200);
    return () => window.clearTimeout(t);
  }, [wantsDNS, !!v]);

  useEffect(() => {
    if (v?.job) setJob((j) => (j && j.id === v.job!.id && j.state !== "running" ? j : v.job));
  }, [v?.job]);

  // SmartDNS reloads the lists ≥10 s after publish: while a reload is pending
  // (or due), keep re-reading the host status until the final result lands.
  const reloadState = hostStatus.data?.status.dns_reload;
  const reloadPending = !!reloadState && (reloadState.pending || (!!reloadState.due_at && Date.parse(reloadState.due_at) > Date.now()));
  useEffect(() => {
    if (!reloadPending) return;
    let t: number | undefined;
    const start = () => {
      if (t === undefined && document.visibilityState !== "hidden") t = window.setInterval(() => void hostStatus.reload(), RELOAD_POLL_MS);
    };
    const stop = () => {
      if (t !== undefined) window.clearInterval(t);
      t = undefined;
    };
    const onVis = () => (document.visibilityState === "hidden" ? stop() : (start(), void hostStatus.reload()));
    start();
    document.addEventListener("visibilitychange", onVis);
    return () => {
      stop();
      document.removeEventListener("visibilitychange", onVis);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reloadPending]);

  // Poll the job while it runs: one read at a time, the next one after the
  // answer; leaving the page or the end of the job cancels the read in
  // flight, so a late "running" answer cannot overwrite the finished job.
  useEffect(() => {
    if (job?.state !== "running") return;
    const ctl = new AbortController();
    let t: number | undefined;
    const tick = async () => {
      try {
        const r = await api.getListsJob(ctl.signal);
        if (ctl.signal.aborted) return;
        if (r.job) setJob(r.job);
        if (r.job && r.job.state !== "running") {
          void hostStatus.reload();
          refreshStatus();
          return;
        }
      } catch {
        /* keep the last state */
      }
      if (!ctl.signal.aborted) t = window.setTimeout(tick, 2000);
    };
    t = window.setTimeout(tick, 2000);
    return () => {
      ctl.abort();
      if (t !== undefined) window.clearTimeout(t);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [job?.id, job?.state]);

  const setPolicy = (p: ListsPolicy) =>
    act.run(async () => {
      const r = await api.setListsPolicy(p);
      view.setData(r);
      // list_source lives in the topology settings: keep the editors' copy in step.
      doc.applyServerChange((t) => ({ ...t, settings: { ...t.settings, list_source: p } }));
      message.success(`来源改为「${POLICY[p].title}」，下次更新起生效`);
    }, `policy:${p}`);

  const update = (lists?: ListKind[]) =>
    act.run(async () => {
      try {
        const r = await api.updateLists(lists ? { lists } : {});
        setJob(r.job);
        refreshStatus();
      } catch (e) {
        const ae = e as ApiError;
        if (ae.code === "update_running" && (ae.body as { job?: ListsJob }).job) setJob((ae.body as { job: ListsJob }).job);
        throw e;
      }
    }, "update");

  const published = hostStatus.data?.status.published;
  const configured = useMemo(() => {
    if (!v) return [];
    return [
      ...(v.lists.geosite ?? []).map((n) => ({ key: `geosite:${n}`, kind: "geosite", name: n })),
      ...(v.lists.keywords ?? []).map((k) => ({ key: `keyword:${k.id}`, kind: "keyword", name: `${k.id}（${k.keyword}）` })),
      ...(v.lists.chnroute ?? []).map((n) => ({ key: n, kind: "chnroute", name: listName(n) })),
    ];
  }, [v]);

  const running = job?.state === "running";
  // host_available only says a lists action is configured; /api/status
  // says whether the agent answers right now.
  const hostDown = v ? !v.host_available || (status ? !status.lists_available : false) : false;

  return (
    <Page
      title="名单"

      extra={
        <Button type="primary" icon={<CloudDownloadOutlined />} disabled={!v || hostDown || running} loading={act.busy === "update"} onClick={() => void update()}>
          立即更新
        </Button>
      }
      menu={[
        { key: "geosite", label: "只更新 geosite 和关键词", disabled: !v || hostDown || running, onClick: () => void update(["geosite"]) },
        { key: "chnroute", label: "只更新 China IP", disabled: !v || hostDown || running, onClick: () => void update(["chnroute"]) },
      ]}
    >
      {act.error ? <ApiErrorAlert error={act.error} onClose={act.clear} /> : null}
      <DataView state={view} rows={6}>
        {(v) => (
          <>
            {hostDown ? (
              <Alert
                type="warning"
                showIcon
                style={{ marginBottom: 16 }}
                message="宿主执行通道不可用，现在不能更新名单"
                description={
                  <>
                    下载、校验和发布都由网关上的 meridian-host 执行。面板现在连不上它（例如面板不在网关上运行，或 meridian-host 没有启动），所以只能修改来源策略。
                    {status?.agent.error ? <div className="muted">{status.agent.error}</div> : null}
                  </>
                }
              />
            ) : null}
            <Section title="下载来源">
              <div className="option-cards" role="radiogroup" aria-label="下载来源">
                {(v.policies ?? (["automatic", "domestic", "overseas"] as ListsPolicy[])).map((p) => (
                  <button
                    key={p}
                    type="button"
                    role="radio"
                    aria-checked={v.policy === p}
                    className={`option-card${v.policy === p ? " selected" : ""}`}
                    disabled={!!act.busy || running}
                    onClick={() => v.policy !== p && void setPolicy(p)}
                  >
                    <div className="option-card-title">
                      {POLICY[p]?.title ?? p}
                      {v.policy === p ? <span className="muted">{v.saved ? "当前" : "当前（默认）"}</span> : null}
                    </div>
                    <div className="option-card-desc">{POLICY[p]?.desc(v)}</div>
                  </button>
                ))}
              </div>
              <Note>
                镜像是第三方。下载后的检查只能证明名单「形状对」（不是错误页、没被截断、数量没骤减），证明不了内容是真的；报告里写的是来源，不是「已验证」。
              </Note>
            </Section>

            <Section title="最近一次更新">
              {job ? (
                <JobView job={job} />
              ) : (
                <Typography.Text type="secondary">
                  还没有更新记录。
                </Typography.Text>
              )}
            </Section>

            <Section title="名单与网关上的版本">
              {hostStatus.error ? (
                <Note>
                  {hostStatus.error.code === "host_unavailable"
                    ? "读不到网关上的版本：宿主执行通道不可用。"
                    : `读不到网关上的版本：${hostStatus.error.message}`}
                </Note>
              ) : null}
              {hostStatus.data?.status.dns_reload?.last?.ok === false ? (
                <Alert type="error" showIcon data-testid="lists-dns-reload-failed" message={`SmartDNS 未读入新名单：${hostStatus.data.status.dns_reload.last.error ?? ""}`} />
              ) : null}
              <DataTable
                size="small"
                rowKey="key"
                pageSize={50}
                dataSource={configured}
                loading={hostStatus.loading && !hostStatus.data && !hostStatus.error}
                columns={[
                  { title: "名单", kind: "flex", width: 220, render: (_, r) => <Space size={4} wrap><span className="muted">{KIND_LABEL[r.kind]}</span><Mono>{r.name}</Mono></Space> },
                  {
                    title: "网关上的版本",
                    kind: "flex",
                    width: 260,
                    render: (_, r) => {
                      const p = published?.[r.key];
                      if (!published) return <Typography.Text type="secondary">未知</Typography.Text>;
                      return p ? (
                        <Space size={6} wrap>
                          <span>{SOURCE_LABEL[p.source] ?? p.source}</span>
                          <TimeText value={p.updated_at} />
                          <Typography.Text type="secondary">{p.count.toLocaleString()} 条</Typography.Text>
                        </Space>
                      ) : (
                        <StatusTag kind="attention">没有</StatusTag>
                      );
                    },
                  },
                ]}
              />
              <Help title="名单包含哪些分类">
                名单来自分流规则里引用的 geosite 分类和关键词，以及固定的 China IP 两族。GeoIP、ASN 规则目前不写进数据面，不需要下载。
              </Help>
            </Section>
          </>
        )}
      </DataView>
      <Section title="解析配置" id="dns">
        <Typography.Paragraph data-testid="lists-dns-pointer">
          已移到 <Link to={href("dns")}>解析设置</Link>
        </Typography.Paragraph>
        <LinkButton to={href("dns")}>打开解析设置</LinkButton>
      </Section>
    </Page>
  );
}
