// 解锁 → 服务组自动路由: where each unlock decision is made (a rule aimed
// at a region group, or a service group with probes), by region. Per
// candidate exit it shows the measured evidence (with its time, and
// whether it expired), the exit the panel computes as in use (推算: it
// reaches the gateway only through the install), the reason and time of
// the last switch, and warnings. Service groups can be switched between
// fixed and automatic selection and given probes here; nothing creates or
// changes a rule.

import { Alert, Button, Select, Space, Table, Tag, Tooltip, Typography } from "antd";
import { useMemo, useState } from "react";
import * as api from "./api";
import { href } from "./state";
import type { CoverageItem, ProbeCatalogEntry, UnlockOwner, UnlockSchedule } from "./types";
import { ApiErrorAlert, Link, StatusTag, TABLE_SCROLL, TimeText, useAction } from "./ui";

export const SECTION_LABEL: Record<string, string> = {
  international: "国际流媒体",
  ai: "AI",
  hk: "香港",
  tw: "台湾",
  jp: "日本",
  sg: "新加坡",
  us: "美国",
};

const EVIDENCE: Record<string, { label: string; color: string }> = {
  ok: { label: "实测可用", color: "green" },
  failed: { label: "实测不可用", color: "red" },
  expired: { label: "结果已过期", color: "default" },
  "": { label: "未测", color: "default" },
};

const SWITCH_REASON: Record<string, string> = {
  preferred_failed: "默认出口连续两次定时失败，换到有证据的候选",
  backup_failed: "在用的候选连续两次定时失败，换到下一个",
  recovered: "默认出口恢复并连续成功满 30 分钟，切回",
  all_failed: "没有候选有有效的解锁证据，留在默认出口",
  group_changed: "地区组顺序或选中成员改变",
};

function regionLabel(r?: string) {
  return r ? SECTION_LABEL[r] ?? r.toUpperCase() : "未分地区";
}

function OwnerCard({ o, catalog, onChanged }: { o: UnlockOwner; catalog: ProbeCatalogEntry[]; onChanged: () => void }) {
  const act = useAction();
  const [probes, setProbes] = useState<string[]>(o.probes);
  const name = (id: string) => catalog.find((c) => c.service === id)?.name ?? id;
  const isSG = o.kind === "service_group" && !!o.service_group;
  const save = (body: { select?: "" | "auto"; probes?: string[] }) =>
    act.run(async () => {
      await api.setServiceSelect(o.service_group!, body);
      onChanged();
    }, "save");
  return (
    <div className="routing-owner" data-testid={`owner-${o.key}`} style={{ marginBottom: 16 }}>
      <Space size={6} wrap style={{ marginBottom: 6 }}>
        <Typography.Text strong>{o.name}</Typography.Text>
        <Tag>{o.kind === "service_group" ? "服务组" : "规则"}</Tag>
        {o.mode === "auto" ? <Tag color="blue">自动选择</Tag> : <Tag>固定 · {o.pin_reason ?? "只记录"}</Tag>}
        {o.group ? (
          <span className="muted">
            候选：<Link to={href("exits", o.group)}>{o.group_name || o.group}</Link>
          </span>
        ) : null}
        <span className="muted">检测：{o.probes.map(name).join("、") || "—"}</span>
        {isSG ? <span className="muted">{o.rules} 条规则经过它</span> : null}
      </Space>
      {o.warnings.map((w) => (
        <Alert key={w} type="warning" showIcon style={{ marginBottom: 6 }} message={w} data-testid="owner-warning" />
      ))}
      <Table
        size="small"
        rowKey="exit_id"
        pagination={false}
        scroll={TABLE_SCROLL}
        dataSource={o.candidates}
        columns={[
          {
            title: "候选出口",
            className: "nowrap",
            render: (_, c) => (
              <Space size={4}>
                {c.name}
                {c.tcp_only ? <Tag>仅 TCP</Tag> : null}
                {c.default ? <Tag>默认</Tag> : null}
              </Space>
            ),
          },
          { title: "地区", className: "nowrap", render: (_, c) => (c.region ? c.region.toUpperCase() : "—") },
          {
            title: "实测证据",
            className: "nowrap",
            render: (_, c) => (
              <Space size={4}>
                <Tag color={EVIDENCE[c.evidence]?.color}>{EVIDENCE[c.evidence]?.label ?? c.evidence}</Tag>
                {c.seen_at ? <TimeText value={c.seen_at} /> : null}
              </Space>
            ),
          },
          {
            title: "在用（面板推算）",
            className: "nowrap",
            render: (_, c) =>
              c.active ? (
                <Tooltip title="面板按检测结果算出的出口；经安装才进入网关，网关没有回报确认">
                  <StatusTag kind={o.unavailable ? "attention" : "ok"}>推算在用</StatusTag>
                </Tooltip>
              ) : null,
          },
        ]}
      />
      <Space size={8} wrap style={{ marginTop: 6 }}>
        {o.switched_at ? (
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            上次切换 <TimeText value={o.switched_at} />：{SWITCH_REASON[o.switch_reason ?? ""] ?? o.switch_reason}
          </Typography.Text>
        ) : (
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            没有切换过
          </Typography.Text>
        )}
        {o.mode === "auto" && o.sched_fails > 0 ? <Tag>{o.sched_fails} 次定时失败</Tag> : null}
      </Space>
      {isSG ? (
        <Space size={8} wrap style={{ marginTop: 8 }}>
          <Select
            mode="multiple"
            style={{ minWidth: 260 }}
            value={probes}
            onChange={setProbes}
            aria-label={`${o.name} 的检测项`}
            options={catalog.filter((c) => c.probeable !== false).map((c) => ({ value: c.service, label: c.name }))}
          />
          <Button size="small" loading={act.busy === "save"} onClick={() => void save({ probes })}>
            保存检测项
          </Button>
          <Button size="small" type={o.mode === "auto" ? "default" : "primary"} loading={act.busy === "save"} onClick={() => void save({ select: o.mode === "auto" ? "" : "auto" })}>
            {o.mode === "auto" ? "改为固定" : "改为自动"}
          </Button>
        </Space>
      ) : null}
      <ApiErrorAlert error={act.error} onClose={act.clear} style={{ marginTop: 8 }} />
    </div>
  );
}

/** The routing section body. Owners come from GET /api/unlock (absent on older panels). */
export function RoutingPanel({
  owners,
  schedule,
  catalog,
  pending,
  onChanged,
}: {
  owners: UnlockOwner[];
  schedule?: UnlockSchedule;
  catalog: ProbeCatalogEntry[];
  pending: boolean;
  onChanged: () => void;
}) {
  const byRegion = useMemo(() => {
    const m = new Map<string, UnlockOwner[]>();
    for (const o of owners) m.set(o.region ?? "", [...(m.get(o.region ?? "") ?? []), o]);
    return [...m.entries()];
  }, [owners]);
  return (
    <div data-testid="unlock-routing">
      <Typography.Paragraph type="secondary">
        「实测证据」是探测结果（带收到时间，超过有效期即不再算证据）；「在用」是面板据此推算的出口，
        {pending ? "还没有安装到网关" : "经安装进入网关"}，网关不回报确认。同一个服务只由一处决定出口：内置规则或服务组。
        分流哪些域名由规则和规则集合决定，检测访问的是适配器固定的几个主机，两者不是一回事。
        {schedule
          ? ` 每 ${Math.round(schedule.interval_sec / 3600)} 小时定时一轮，同时 ${schedule.exit_concurrency} 个出口，每个出口每轮最多 ${schedule.exit_request_budget} 个请求，结果有效 ${Math.round(schedule.result_ttl_sec / 3600)} 小时。`
          : ""}
        这套自动选择没有在真实平台和真实网关上验证过。
      </Typography.Paragraph>
      {owners.length === 0 ? (
        <Typography.Text type="secondary">没有挂了检测项的规则或服务组。到规则页的服务组里选择检测项，或在这里改服务组。</Typography.Text>
      ) : (
        byRegion.map(([region, list]) => (
          <div key={region || "none"}>
            <Typography.Title level={5}>{regionLabel(region)}</Typography.Title>
            {list.map((o) => (
              <OwnerCard key={o.key} o={o} catalog={catalog} onChanged={onChanged} />
            ))}
          </div>
        ))
      )}
    </div>
  );
}

/** The coverage table (catalog API): every item of the cited scripts' region lists. */
export function CoverageTable({ items, reasons }: { items: CoverageItem[]; reasons: Record<string, string> }) {
  const [section, setSection] = useState<string>();
  const shown = items.filter((i) => !section || i.section === section);
  return (
    <div data-testid="coverage-table">
      <Space style={{ marginBottom: 8 }} wrap>
        <Select
          allowClear
          placeholder="地区"
          style={{ width: 160 }}
          value={section}
          onChange={setSection}
          aria-label="按地区筛选覆盖表"
          options={Object.entries(SECTION_LABEL).map(([value, label]) => ({ value, label }))}
        />
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          清单按引用脚本的地区分节整理，待对照源码复核。
        </Typography.Text>
      </Space>
      <Table
        size="small"
        rowKey={(i) => i.section + "|" + i.name}
        pagination={{ pageSize: 20, hideOnSinglePage: true }}
        dataSource={shown}
        scroll={TABLE_SCROLL}
        columns={[
          { title: "地区", className: "nowrap", render: (_, i) => SECTION_LABEL[i.section] ?? i.section },
          { title: "项目", dataIndex: "name", className: "cell-name" },
          { title: "脚本", className: "nowrap", render: (_, i) => i.scripts.join("、") },
          {
            title: "结果",
            render: (_, i) =>
              i.adapter ? (
                <Tag color="green">已实现 {i.adapter}{i.part ? `（参考 ${i.part}）` : ""}</Tag>
              ) : (
                <Tooltip title={reasons[i.reason ?? ""]}>
                  <Tag>未实现 · {i.reason}</Tag>
                </Tooltip>
              ),
          },
          { title: "说明", className: "cell-text", render: (_, i) => i.note ?? (i.adapter ? "" : reasons[i.reason ?? ""]) },
        ]}
      />
    </div>
  );
}
