// 防泄露: what was really checked, and by whom. Four groups with their real
// execution semantics: generated-configuration checks (the panel reads the
// compiled text — that proves nothing about leaks), isolated Linux
// integration items (the panel never runs them: always 未执行), human
// sign-off items (always 待人工签收) and known limitations. Nothing in the
// integration or human groups can ever render as passed.

import { Alert, Table, Typography } from "antd";
import type { ReactNode } from "react";
import * as api from "./api";
import { useStatus } from "./state";
import type { LeakItem } from "./types";
import { DataView, Page, Section, StatusTag, useApi, type StatusKind } from "./ui";

type Scope = "automated" | "integration" | "human" | "limitation";

const SCOPES: { key: Scope; title: string; note: ReactNode }[] = [
  {
    key: "automated",
    title: "生成配置核对",
    note: "面板读的是编译出来的配置文本。「配置包含」只说明规则写进了配置文件，不说明它已经加载到网关，更不能证明没有泄露。",
  },
  {
    key: "integration",
    title: "隔离 Linux 集成测试",
    note: "netns 测试和 deploy/ 下的验证脚本要在一台 Linux 上实际运行并把日志存档。面板不运行它们，也不读存档，所以这里永远显示「未执行」——跑过与否看存档记录。",
  },
  {
    key: "human",
    title: "实机人工签收",
    note: "真实测试机、路由器、断隧道和抓包。只有人能签收；签收时把截图、命令输出和抓包存档。面板永远不会把这些标成通过。",
  },
  {
    key: "limitation",
    title: "已知限制",
    note: "设计边界：不算失败，也不能写成已解决。",
  },
];

/**
 * Status per scope. Only the automated group can show a "configuration
 * contains" result; integration and human items are pinned to their
 * scope's status whatever the item says, so a mistaken "pass" from the API
 * can never look like a passed leak test.
 */
export function leakStatus(it: LeakItem): { kind: StatusKind; label: string } {
  const scope = (it.scope || "automated") as Scope;
  if (scope === "integration") return { kind: "neutral", label: "未执行" };
  if (scope === "human") return { kind: "signoff", label: "待人工签收" };
  if (scope === "limitation") return { kind: "attention", label: "已知限制" };
  switch (it.status) {
    case "pass":
      return { kind: "unverified", label: "配置包含" };
    case "fail":
      return { kind: "failed", label: "配置缺失" };
    case "skip":
      return { kind: "neutral", label: "不适用" };
    case "known_limitation":
      return { kind: "attention", label: "已知限制" };
    default:
      return { kind: "neutral", label: "未执行" };
  }
}

export default function LeakPage() {
  const { install } = useStatus();
  const items = useApi(() => api.getLeakcheck(), [install.kind]);

  return (
    <Page title="防泄露" description="哪些检查真的执行过、由谁执行，哪些必须你人工签收，以及已知限制。">
      <Alert
        type="warning"
        showIcon
        style={{ marginBottom: 16 }}
        message="这一页没有任何一项能证明不泄露"
        description={
          <span>
            发布前需要三样证据：网关上 <code>meridian-verify.sh</code> 的输出（缺防火墙表即失败）、隔离 Linux 集成测试的日志，以及测试机上 DNS 泄露、WebRTC、路由器 ULA、断隧道和抓包的人工签收；启用远程接入时还要用真实手机在蜂窝网络下拨入并确认路由器端口转发。
            步骤和存档要求见仓库里的 <code>docs/verification.md</code>，签收记录存档在那里列出的位置。WebRTC host 候选里出现运营商的 IPv6 全局地址是单个 /64 下的已知限制，不算失败。
          </span>
        }
      />
      <DataView state={items} rows={8}>
        {(d) => (
          <>
            {SCOPES.map((sc) => {
              const rows = d.items.filter((it) => (it.scope || "automated") === sc.key);
              if (rows.length === 0) return null;
              const fails = sc.key === "automated" ? rows.filter((r) => r.status === "fail").length : 0;
              return (
                <Section
                  key={sc.key}
                  title={`${sc.title}（${rows.length}）`}
                  extra={fails > 0 ? <StatusTag kind="failed">{fails} 项配置缺失</StatusTag> : null}
                >
                  <Typography.Paragraph type="secondary">{sc.note}</Typography.Paragraph>
                  <Table<LeakItem>
                    rowKey="id"
                    size="small"
                    pagination={false}
                    dataSource={rows}
                    data-testid={`leak-${sc.key}`}
                    onRow={(it) => ({ "data-testid": `leak-item-${it.id}` }) as React.HTMLAttributes<HTMLElement>}
                    columns={[
                      { title: "检查", dataIndex: "title", width: "32%" },
                      {
                        title: "状态",
                        width: 130,
                        render: (_, it) => {
                          const s = leakStatus(it);
                          return <StatusTag kind={s.kind}>{s.label}</StatusTag>;
                        },
                      },
                      { title: "说明", dataIndex: "detail" },
                    ]}
                  />
                </Section>
              );
            })}
          </>
        )}
      </DataView>
      <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
        NAT64 预留的设置已移到「拓扑 → 网关设置」。
      </Typography.Paragraph>
    </Page>
  );
}
