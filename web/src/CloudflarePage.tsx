// Cloudflare: reusable accounts (API token write-only), the token how-to and
// the honest permission check, the Mesh account selection and — on the same
// page — the Mesh deployment (MeshDeploy.tsx).

import { PlusOutlined } from "@ant-design/icons";
import {
  Alert,
  App as AntApp,
  Button,
  Collapse,
  Drawer,
  Form,
  Input,
  Space,
  Table,
  Tag,
  Typography,
} from "antd";
import { useEffect, useState } from "react";
import * as api from "./api";
import type { ApiError } from "./api";
import MeshDeploy, { checkSummary } from "./MeshDeploy";
import { useRouter } from "./state";
import type { CloudflareAccountView, CloudflareRequirements, PermissionCheck } from "./types";
import {
  ApiErrorAlert,
  DataView,
  EmptyState,
  Link,
  Mono,
  Page,
  RefusedDialog,
  Section,
  SecretField,
  StatusTag,
  TimeText,
  refLink,
  showFieldError,
  useAction,
  useApi,
  useConfirmDanger,
  type StatusKind,
} from "./ui";

// ------------------------------------------------------ permission check ---

const PROBE_LABEL: Record<string, string> = {
  token_verify: "令牌有效",
  read_mesh_nodes: "读取 Mesh 节点",
  read_routes: "读取路由",
};

const PROBE_STATUS: Record<string, { kind: StatusKind; label: string }> = {
  pass: { kind: "ok", label: "通过" },
  denied: { kind: "failed", label: "被拒绝" },
  error: { kind: "attention", label: "出错" },
  skipped: { kind: "neutral", label: "未执行" },
};

export function PermissionCheckView({ check }: { check: PermissionCheck | null | undefined }) {
  if (!check) return <Typography.Text type="secondary">还没有检查过这个账户的 token。</Typography.Text>;
  const s = checkSummary(check);
  return (
    <div data-testid="permission-check">
      <Space wrap style={{ marginBottom: 8 }}>
        <StatusTag kind={s.kind}>{s.label}</StatusTag>
        <TimeText value={check.checked_at} />
        {check.token_status ? <Tag>令牌状态 {check.token_status}</Tag> : null}
        {check.token_kind ? <Tag>{check.token_kind === "account" ? "账户令牌" : check.token_kind === "user" ? "用户令牌" : check.token_kind}</Tag> : null}
      </Space>
      {check.detail ? <Typography.Paragraph style={{ marginBottom: 8 }}>{check.detail}</Typography.Paragraph> : null}
      <Table
        size="small"
        pagination={false}
        rowKey="name"
        dataSource={check.checks ?? []}
        columns={[
          { title: "检查", render: (_, p) => PROBE_LABEL[p.name] ?? p.name },
          { title: "接口", render: (_, p) => <Mono>{p.endpoint}</Mono> },
          {
            title: "结果",
            width: 100,
            render: (_, p) => {
              const st = PROBE_STATUS[p.status] ?? { kind: "neutral" as const, label: p.status };
              return <StatusTag kind={st.kind}>{st.label}</StatusTag>;
            },
          },
          { title: "说明", dataIndex: "detail" },
        ]}
      />
      {check.missing && check.missing.length > 0 ? (
        <Alert
          type="error"
          showIcon
          style={{ marginTop: 12 }}
          message="缺少的权限"
          description={
            <ul className="ref-list">
              {check.missing.map((m) => (
                <li key={m}>{m}</li>
              ))}
            </ul>
          }
        />
      ) : null}
      <Alert
        type="warning"
        showIcon
        style={{ marginTop: 12 }}
        message="写权限未确认"
        description={
          <>
            <div>检查只做只读调用，通过也不保证部署成功：缺写权限会在部署的「Cloudflare 节点」阶段失败并自动撤回。</div>
            {check.unconfirmed && check.unconfirmed.length > 0 ? (
              <ul className="ref-list">
                {check.unconfirmed.map((u) => (
                  <li key={u}>{u}</li>
                ))}
              </ul>
            ) : null}
          </>
        }
      />
    </div>
  );
}

// ------------------------------------------------------------ how-to ---

function TokenHowTo({ req }: { req: CloudflareRequirements }) {
  return (
    <div className="howto">
      <Typography.Title level={5}>需要的权限</Typography.Title>
      <Table
        size="small"
        pagination={false}
        rowKey="name"
        dataSource={req.permissions}
        columns={[
          { title: "权限", render: (_, p) => <Mono>{p.name}</Mono> },
          { title: "范围", width: 90, render: (_, p) => (p.scope === "account" ? "账户" : p.scope) },
          { title: "用途", dataIndex: "why" },
        ]}
      />
      <Typography.Title level={5} style={{ marginTop: 16 }}>
        步骤
      </Typography.Title>
      <ol style={{ paddingLeft: 20, marginTop: 0 }}>
        {req.how_to.map((s, i) => (
          <li key={i} style={{ marginBottom: 4 }}>
            {s}
          </li>
        ))}
      </ol>
      <Typography.Title level={5} style={{ marginTop: 16 }}>
        「检查权限」做什么、不做什么
      </Typography.Title>
      <div className="option-cards">
        <div>
          <Typography.Text strong>会做</Typography.Text>
          <ul style={{ paddingLeft: 20 }}>
            {req.check.does.map((s) => (
              <li key={s}>{s}</li>
            ))}
          </ul>
        </div>
        <div>
          <Typography.Text strong>不会做、证明不了</Typography.Text>
          <ul style={{ paddingLeft: 20 }}>
            {req.check.does_not.map((s) => (
              <li key={s}>{s}</li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}

// ------------------------------------------------------------ the form ---

const ACCOUNT_ID_RE = /^[0-9a-fA-F]{32}$/;

function AccountDrawer({
  open,
  account,
  onClose,
  onSaved,
  onRefused,
}: {
  open: boolean;
  account: CloudflareAccountView | null;
  onClose: () => void;
  onSaved: (a: CloudflareAccountView) => void;
  onRefused: (e: ApiError) => void;
}) {
  const [form] = Form.useForm<{ name: string; account_id: string; api_token?: string; notes?: string }>();
  const act = useAction();
  const [fieldHandled, setFieldHandled] = useState(false);
  const fields = ["name", "account_id", "api_token", "notes"];

  async function save() {
    let v: { name: string; account_id: string; api_token?: string; notes?: string };
    try {
      v = await form.validateFields();
    } catch {
      return;
    }
    setFieldHandled(false);
    const onError = (e: ApiError) => {
      if (e.code === "account_locked" || e.code === "in_use") onRefused(e);
      else setFieldHandled(showFieldError(form, e, fields));
    };
    const res = await act.run(
      async () => {
        if (!account) {
          return (await api.createAccount({ name: v.name.trim(), account_id: v.account_id.trim(), api_token: v.api_token ?? "", notes: v.notes ?? "" })).account;
        }
        let out = account;
        const patch: { name?: string; account_id?: string; notes?: string } = {};
        if (v.name.trim() !== account.name) patch.name = v.name.trim();
        if (v.account_id.trim() !== account.account_id) patch.account_id = v.account_id.trim();
        if ((v.notes ?? "") !== (account.notes ?? "")) patch.notes = v.notes ?? "";
        if (Object.keys(patch).length > 0) out = (await api.updateAccount(account.id, patch)).account;
        if (v.api_token) out = (await api.rotateAccountToken(account.id, v.api_token)).account;
        return out;
      },
      "save",
      onError,
    );
    // The token leaves the form whatever happened.
    form.setFieldValue("api_token", undefined);
    if (res) onSaved(res);
  }

  return (
    <Drawer
      title={account ? `编辑 ${account.name}` : "添加 Cloudflare 账户"}
      open={open}
      onClose={onClose}
      width={520}
      destroyOnHidden
      footer={
        <Space>
          <Button onClick={onClose}>取消</Button>
          <Button type="primary" loading={!!act.busy} onClick={() => void save()}>
            {account ? "保存" : "添加"}
          </Button>
        </Space>
      }
    >
      {act.error && !fieldHandled && act.error.code !== "account_locked" ? <ApiErrorAlert error={act.error} /> : null}
      {account?.bound_deployment ? (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          message="这个账户被未撤回完的 Mesh 部署绑定：可以替换 token，不能改 Account ID。"
        />
      ) : null}
      <Form
        form={form}
        layout="vertical"
        autoComplete="off"
        requiredMark="optional"
        initialValues={account ? { name: account.name, account_id: account.account_id, notes: account.notes } : {}}
      >
        <Form.Item name="name" label="名称" rules={[{ required: true, message: "请填写名称" }]}>
          <Input placeholder="例如 个人账户" />
        </Form.Item>
        <Form.Item
          name="account_id"
          label="Account ID"
          extra="32 位十六进制，在 Cloudflare 账户首页右侧。"
          rules={[
            { required: true, message: "请填写 Account ID" },
            { pattern: ACCOUNT_ID_RE, message: "应为 32 位十六进制" },
          ]}
        >
          <Input className="mono" />
        </Form.Item>
        <Form.Item
          name="api_token"
          label="API token"
          extra="只写不读：保存后面板不会再显示它。"
          rules={account ? [] : [{ required: true, message: "请填写 API token" }]}
        >
          <SecretField isSet={account?.token_set} aria-label="API token" />
        </Form.Item>
        <Form.Item name="notes" label="备注">
          <Input.TextArea rows={2} />
        </Form.Item>
      </Form>
    </Drawer>
  );
}

// -------------------------------------------------------------- the page ---

export default function CloudflarePage() {
  const { route } = useRouter();
  const { message } = AntApp.useApp();
  const confirm = useConfirmDanger();
  const accounts = useApi(() => api.listAccounts(), []);
  const req = useApi(() => api.getCloudflareRequirements(), []);
  const act = useAction();
  const [drawer, setDrawer] = useState<{ open: boolean; account: CloudflareAccountView | null }>({ open: false, account: null });
  const [refused, setRefused] = useState<ApiError | null>(null);
  const [expanded, setExpanded] = useState<string[]>([]);
  const [meshKey, setMeshKey] = useState(0);
  const list = accounts.data?.accounts ?? [];
  const meshAccount = accounts.data?.mesh_account ?? null;

  useEffect(() => {
    if (route.query.get("section") === "mesh") {
      const t = window.setTimeout(() => document.getElementById("mesh")?.scrollIntoView?.({ behavior: "smooth" }), 200);
      return () => window.clearTimeout(t);
    }
  }, [route.query]);

  const upsert = (a: CloudflareAccountView) =>
    accounts.setData((d) =>
      d ? { ...d, accounts: d.accounts.some((x) => x.id === a.id) ? d.accounts.map((x) => (x.id === a.id ? a : x)) : [...d.accounts, a] } : d,
    );

  const check = (a: CloudflareAccountView) =>
    act.run(async () => {
      const r = await api.checkAccount(a.id);
      upsert(r.account);
      setExpanded((e) => (e.includes(a.id) ? e : [...e, a.id]));
    }, `check:${a.id}`);

  const selectForMesh = (a: CloudflareAccountView) =>
    act.run(
      async () => {
        await api.setMeshAccount(a.id);
        message.success(`Mesh 改用「${a.name}」`);
        await accounts.reload();
        setMeshKey((k) => k + 1);
      },
      `mesh:${a.id}`,
      (e) => (e.code === "account_locked" ? setRefused(e) : undefined),
    );

  const askDelete = (a: CloudflareAccountView) =>
    confirm({
      title: `删除账户「${a.name}」？`,
      consequence: a.bound_deployment
        ? "它被未撤回完的 Mesh 部署绑定，面板会拒绝删除。"
        : "面板里保存的 token 一并删除；Cloudflare 上的 token 本身不受影响，需要的话去 Cloudflare 控制台吊销。",
      okText: "删除",
      onOk: async () => {
        try {
          await api.deleteAccount(a.id);
          message.success("已删除");
          await accounts.reload();
          setMeshKey((k) => k + 1);
        } catch (e) {
          setRefused(e as ApiError);
        }
      },
    });

  return (
    <Page
      title="Cloudflare"
      description="Mesh 备路用到的 Cloudflare 账户和 API token，以及 Mesh 的部署与撤回。"
      extra={
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setDrawer({ open: true, account: null })}>
          添加账户
        </Button>
      }
    >
      {act.error && act.error.code !== "account_locked" ? <ApiErrorAlert error={act.error} onClose={act.clear} /> : null}
      <Section title="账户">
        <DataView
          state={accounts}
          isEmpty={(d) => d.accounts.length === 0}
          empty={
            <EmptyState
              title="还没有 Cloudflare 账户"
              description="只有用 Mesh 备路时才需要。按下面「如何创建 API token」建一个只有两项权限的 token，再添加账户。"
              action={
                <Button type="primary" onClick={() => setDrawer({ open: true, account: null })}>
                  添加账户
                </Button>
              }
            />
          }
        >
          {(d) => (
            <Table
              rowKey="id"
              dataSource={d.accounts}
              pagination={false}
              scroll={{ x: 980 }}
              expandable={{
                expandedRowKeys: expanded,
                onExpandedRowsChange: (keys) => setExpanded(keys as string[]),
                expandedRowRender: (a) => <PermissionCheckView check={a.permission_check} />,
              }}
              columns={[
                { title: "名称", dataIndex: "name" },
                { title: "Account ID", render: (_, a) => <Mono copy>{a.account_id}</Mono> },
                {
                  title: "Token",
                  width: 100,
                  render: (_, a) => <StatusTag kind={a.token_set ? "ok" : "attention"}>{a.token_set ? "已设置" : "未设置"}</StatusTag>,
                },
                {
                  title: "权限检查",
                  render: (_, a) => {
                    const s = checkSummary(a.permission_check);
                    return (
                      <Space size={4} wrap>
                        <StatusTag kind={s.kind}>{s.label}</StatusTag>
                        {a.permission_check ? <TimeText value={a.permission_check.checked_at} /> : null}
                      </Space>
                    );
                  },
                },
                {
                  title: "Mesh",
                  render: (_, a) =>
                    a.used_for_mesh || meshAccount === a.id ? (
                      <Tag color="blue">Mesh 使用中</Tag>
                    ) : (
                      <Button size="small" loading={act.busy === `mesh:${a.id}`} onClick={() => void selectForMesh(a)}>
                        用于 Mesh
                      </Button>
                    ),
                },
                {
                  title: "绑定部署",
                  render: (_, a) =>
                    a.bound_deployment ? (
                      <Link to={refLink(a.bound_deployment) ?? "#/cloudflare"}>{a.bound_deployment.name || a.bound_deployment.id}</Link>
                    ) : (
                      <Typography.Text type="secondary">—</Typography.Text>
                    ),
                },
                {
                  title: "",
                  className: "table-actions",
                  render: (_, a) => (
                    <Space size={0}>
                      <Button type="link" size="small" loading={act.busy === `check:${a.id}`} disabled={!a.token_set} onClick={() => void check(a)}>
                        检查权限
                      </Button>
                      <Button type="link" size="small" onClick={() => setDrawer({ open: true, account: a })}>
                        编辑
                      </Button>
                      <Button type="link" size="small" danger onClick={() => askDelete(a)}>
                        删除
                      </Button>
                    </Space>
                  ),
                },
              ]}
            />
          )}
        </DataView>
      </Section>

      <Collapse
        style={{ marginBottom: 16 }}
        defaultActiveKey={list.length === 0 && accounts.data ? ["howto"] : []}
        key={accounts.data ? `howto-${list.length === 0}` : "howto-loading"}
        items={[
          {
            key: "howto",
            label: "如何创建 API token",
            children: <DataView state={req}>{(r) => <TokenHowTo req={r} />}</DataView>,
          },
        ]}
      />

      <div id="mesh">
        <MeshDeploy key={meshKey} accounts={list} onAccountsChanged={() => void accounts.reload()} />
      </div>

      <AccountDrawer
        key={drawer.account?.id ?? "new"}
        open={drawer.open}
        account={drawer.account}
        onClose={() => setDrawer({ open: false, account: null })}
        onRefused={setRefused}
        onSaved={(a) => {
          upsert(a);
          setDrawer({ open: false, account: null });
          message.success("已保存；可以「检查权限」");
          setMeshKey((k) => k + 1);
        }}
      />
      <RefusedDialog error={refused} onClose={() => setRefused(null)} />
    </Page>
  );
}
