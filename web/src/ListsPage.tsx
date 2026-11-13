// 名单: where geosite / China IP lists are downloaded from, a manual update,
// and per-list results (actual source, fallback, kept previous version).
// There is no scheduler: lists change only when someone starts an update.

import { CloudDownloadOutlined, DownOutlined } from "@ant-design/icons";
import { Alert, App as AntApp, Dropdown, Space, Table, Tag, Tooltip, Typography } from "antd";
import { useEffect, useMemo, useState } from "react";
import * as api from "./api";
import type { ApiError } from "./api";
import { useStatus, useTopologyDoc } from "./state";
import type { ListAttempt, ListKind, ListResult, ListsJob, ListsPolicy, ListsReport, ListsView } from "./types";
import {
  TABLE_SCROLL,
  ApiErrorAlert,
  DataView,
  Facts,
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
    <Table
      size="small"
      rowKey="list"
      pagination={false}
      dataSource={report.lists ?? []}
      scroll={TABLE_SCROLL}
      columns={[
        {
          title: "名单",
          className: "cell-name",
          render: (_, r) => (
            <Space size={4}>
              <Tag>{KIND_LABEL[r.kind] ?? r.kind}</Tag>
              <Mono>{listName(r.list)}</Mono>
            </Space>
          ),
        },
        {
          title: "结果",
          render: (_, r) => {
            const s = resultStatus(r);
            return <StatusTag kind={s.kind} title={r.error}>{s.label}</StatusTag>;
          },
        },
        {
          title: "生效来源",
          className: "nowrap",
          render: (_, r) => {
            const src = r.updated ? r.source : r.current?.source;
            const url = r.updated ? r.url : r.current?.url;
            return src ? (
              <Tooltip title={<span className="mono-small">{url}</span>}>
                <span>{SOURCE_LABEL[src] ?? src}</span>
              </Tooltip>
            ) : (
              <Typography.Text type="secondary">—</Typography.Text>
            );
          },
        },
        { title: "版本时间", render: (_, r) => <TimeText value={r.current?.updated_at} /> },
        { title: "条数", align: "right", render: (_, r) => (r.current?.count ?? r.count ?? "—").toLocaleString() },
        { title: "文件", align: "right", render: (_, r) => r.current?.files ?? r.files ?? "—" },
        {
          title: "丢弃",
          render: (_, r) =>
            r.dropped && Object.keys(r.dropped).length > 0 ? (
              <Tooltip title="domain-set 表达不了 keyword: 和 regexp: 条目，丢弃并计数">
                <span>
                  {Object.entries(r.dropped)
                    .map(([k, n]) => `${k} ${n}`)
                    .join("，")}
                </span>
              </Tooltip>
            ) : (
              <Typography.Text type="secondary">—</Typography.Text>
            ),
        },
        { title: "尝试", render: (_, r) => <Attempts attempts={r.attempts} /> },
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
          ["名单", job.lists.map((l) => (l === "chnroute" ? "China IP" : l)).join("、")],
          ["开始", <TimeText value={job.started_at} />],
          ["结束", job.finished_at ? <TimeText value={job.finished_at} /> : "—"],
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
      {rep?.dns_changed ? (
        <Alert
          type={rep.dns_restart && rep.dns_restart !== "ok" ? "warning" : "info"}
          showIcon
          message={`geosite / 关键词文件有变化，SmartDNS 需要重启才会读入${rep.dns_restart ? `：${rep.dns_restart}` : ""}`}
        />
      ) : null}
      {(rep?.warnings ?? []).map((w) => (
        <Alert key={w} type="warning" showIcon message={w} />
      ))}
      {rep ? <ReportTable report={rep} /> : null}
    </Space>
  );
}

export default function ListsPage() {
  const view = useApi(() => api.getLists(), []);
  const doc = useTopologyDoc();
  const { message } = AntApp.useApp();
  const act = useAction();
  const [job, setJob] = useState<ListsJob | null>(null);
  const hostStatus = useApi(() => api.getListsStatus(), []);
  const { status, refresh: refreshStatus } = useStatus();
  const v = view.data;

  useEffect(() => {
    if (v?.job) setJob((j) => (j && j.id === v.job!.id && j.state !== "running" ? j : v.job));
  }, [v?.job]);

  // Poll the job while it runs.
  useEffect(() => {
    if (job?.state !== "running") return;
    const t = window.setInterval(async () => {
      try {
        const r = await api.getListsJob();
        if (r.job) setJob(r.job);
        if (r.job && r.job.state !== "running") {
          void hostStatus.reload();
          refreshStatus();
        }
      } catch {
        /* keep the last state */
      }
    }, 2000);
    return () => window.clearInterval(t);
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
      description="分流用到的 geosite 域名名单和 China IP 名单从哪里下载，以及最近一次更新的结果。没有定时任务：只在你点「立即更新」时下载。"
      extra={
        <Dropdown.Button
          type="primary"
          icon={<DownOutlined />}
          disabled={!v || hostDown || running}
          loading={act.busy === "update"}
          onClick={() => void update()}
          menu={{
            items: [
              { key: "geosite", label: "只更新 geosite 和关键词" },
              { key: "chnroute", label: "只更新 China IP" },
            ],
            onClick: ({ key }) => void update([key as ListKind]),
          }}
        >
          <CloudDownloadOutlined /> 立即更新
        </Dropdown.Button>
      }
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
                      {v.policy === p ? <Tag color="blue">{v.saved ? "当前" : "当前（默认）"}</Tag> : null}
                    </div>
                    <div className="option-card-desc">{POLICY[p]?.desc(v)}</div>
                  </button>
                ))}
              </div>
              <Typography.Paragraph type="secondary" style={{ marginTop: 12, marginBottom: 0 }}>
                镜像是第三方。下载后的检查只能证明名单「形状对」（不是错误页、没被截断、数量没骤减），证明不了内容是真的；报告里写的是来源，不是「已验证」。
              </Typography.Paragraph>
            </Section>

            <Section title="最近一次更新">
              {job ? (
                <JobView job={job} />
              ) : (
                <Typography.Text type="secondary">
                  {hostDown ? "还没有更新记录。" : "还没有从面板更新过。点「立即更新」下载并发布到网关。"}
                </Typography.Text>
              )}
            </Section>

            <Section title="名单与网关上的版本">
              {hostStatus.error ? (
                <Typography.Paragraph type="secondary">
                  {hostStatus.error.code === "host_unavailable"
                    ? "读不到网关上的版本：宿主执行通道不可用。"
                    : `读不到网关上的版本：${hostStatus.error.message}`}
                </Typography.Paragraph>
              ) : null}
              <Table
                size="small"
                rowKey="key"
                pagination={false}
                dataSource={configured}
                scroll={TABLE_SCROLL}
                loading={hostStatus.loading && !hostStatus.data && !hostStatus.error}
                columns={[
                  { title: "名单", className: "cell-name", render: (_, r) => <Space size={4}><Tag>{KIND_LABEL[r.kind]}</Tag><Mono>{r.name}</Mono></Space> },
                  {
                    title: "网关上的版本",
                    className: "nowrap",
                    render: (_, r) => {
                      const p = published?.[r.key];
                      if (!published) return <Typography.Text type="secondary">未知</Typography.Text>;
                      return p ? (
                        <Space size={6}>
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
              <Typography.Paragraph type="secondary" style={{ marginTop: 12, marginBottom: 0 }}>
                名单来自分流规则里引用的 geosite 分类和关键词，以及固定的 China IP 两族。GeoIP、ASN 规则目前不写进数据面，不需要下载。
              </Typography.Paragraph>
            </Section>
          </>
        )}
      </DataView>
    </Page>
  );
}
