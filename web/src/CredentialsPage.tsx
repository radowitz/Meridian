// 密钥: reusable SSH credentials (passwords and private keys) and the SOCKS
// credentials of external SOCKS exits. Secrets are write-only: the public
// key and fingerprint are always viewable, the password / private key /
// passphrase and the SOCKS username / password never are.

import { PlusOutlined } from "@ant-design/icons";
import {
  Alert,
  App as AntApp,
  Button,
  Drawer,
  Form,
  Input,
  Result,
  Segmented,
  Space,
  Tag,
  Typography,
} from "antd";
import { useEffect, useRef, useState, type ReactNode } from "react";
import * as api from "./api";
import { href, useRouter } from "./state";
import { SOCKS_VALUE_RE, type SOCKSCredentialView, type SSHCredentialCreate, type SSHCredentialView, type SSHSecretInput } from "./types";
import {
  RowActions,
  DataTable,
  ApiErrorAlert,
  DataView,
  EmptyState,
  Facts,
  Link,
  Mono,
  Page,
  RefList,
  RefusedDialog,
  Section,
  SecretField,
  StatusTag,
  TimeText,
  showFieldError,
  useAction,
  useApi,
  useConfirmDanger,
} from "./ui";
import type { ApiError } from "./api";

type CreateMode = "password" | "import" | "generate";

const SECRET_FIELDS = ["password", "private_key", "passphrase"] as const;

export function kindLabel(c: Pick<SSHCredentialView, "kind" | "key_type">) {
  if (c.kind === "password") return "密码";
  return c.key_type ? `私钥 · ${c.key_type}` : "私钥";
}

/** What to do with a new public key. */
function PublicKeyHandoff({ cred, fingerprint = true }: { cred: SSHCredentialView; fingerprint?: boolean }) {
  if (cred.kind !== "private_key" || !cred.public_key) return null;
  return (
    <div data-testid="public-key-handoff">
      <Typography.Paragraph>
        把下面这一行追加到服务器上登录用户的 <code>~/.ssh/authorized_keys</code>（每行一把公钥），之后才能用这把密钥登录。
      </Typography.Paragraph>
      <Mono block copy>
        {cred.public_key}
      </Mono>
      {fingerprint ? (
        <div style={{ marginTop: 12 }}>
          <Facts items={[["指纹", <Mono copy>{cred.fingerprint}</Mono>]]} />
        </div>
      ) : null}
    </div>
  );
}

function secretBody(mode: CreateMode, v: Record<string, string | undefined>): SSHSecretInput {
  if (mode === "password") return { kind: "password", password: v.password ?? "" };
  if (mode === "generate") return { kind: "private_key", generate: true, ...(v.comment ? { comment: v.comment } : {}) };
  return {
    kind: "private_key",
    private_key: v.private_key ?? "",
    ...(v.passphrase ? { passphrase: v.passphrase } : {}),
    ...(v.comment ? { comment: v.comment } : {}),
  };
}

function SecretInputs({ mode }: { mode: CreateMode }) {
  if (mode === "password")
    return (
      <Form.Item name="password" label="密码" rules={[{ required: true, message: "请输入密码" }]}>
        <SecretField aria-label="密码" />
      </Form.Item>
    );
  if (mode === "generate")
    return (
      <>
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          message="面板生成一把 ed25519 密钥，私钥只保存在面板的凭据存储里，任何时候都不会显示；创建后显示公钥，供你加到服务器上。"
        />
        <Form.Item name="comment" label="公钥注释" extra="出现在公钥末尾，便于在 authorized_keys 里识别，例如 meridian@gateway。">
          <Input autoComplete="off" />
        </Form.Item>
      </>
    );
  return (
    <>
      <Form.Item
        name="private_key"
        label="私钥"
        rules={[{ required: true, message: "请粘贴私钥" }]}
        extra="OpenSSH 或 PEM 格式，粘贴完整内容（含 BEGIN/END 行）。提交后输入框立即清空，私钥不会再显示。"
      >
        <SecretField multiline aria-label="私钥" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" />
      </Form.Item>
      <Form.Item name="passphrase" label="私钥口令" extra="私钥带口令时填写；面板保存口令以便无人值守使用。">
        <SecretField aria-label="私钥口令" />
      </Form.Item>
      <Form.Item name="comment" label="公钥注释">
        <Input autoComplete="off" />
      </Form.Item>
    </>
  );
}

/**
 * Create drawer, also used from the server form (「新建密钥」).
 * `fixedKind` limits the choice to what the server's auth method needs.
 */
export function CredentialCreateDrawer({
  open,
  onClose,
  onCreated,
  fixedKind,
}: {
  open: boolean;
  onClose: () => void;
  onCreated: (c: SSHCredentialView) => void;
  fixedKind?: "password" | "private_key";
}) {
  const [form] = Form.useForm();
  const [mode, setMode] = useState<CreateMode>(fixedKind === "password" ? "password" : fixedKind === "private_key" ? "generate" : "generate");
  const [created, setCreated] = useState<SSHCredentialView | null>(null);
  const [fieldHandled, setFieldHandled] = useState(false);
  const act = useAction();

  const close = () => {
    form.resetFields();
    setCreated(null);
    act.clear();
    onClose();
  };

  const modes = [
    { value: "generate", label: "生成 ed25519", disabled: fixedKind === "password" },
    { value: "import", label: "导入私钥", disabled: fixedKind === "password" },
    { value: "password", label: "密码", disabled: fixedKind === "private_key" },
  ];

  async function submit() {
    let values: Record<string, string | undefined>;
    try {
      values = await form.validateFields();
    } catch {
      return;
    }
    const body = { name: values.name ?? "", ...(values.notes ? { notes: values.notes } : {}), ...secretBody(mode, values) } as SSHCredentialCreate;
    let failed: ApiError | null = null;
    const res = await act.run(() => api.createCredential(body), "create", (e) => (failed = e));
    // Secrets leave the form whatever happened.
    form.setFieldsValue(Object.fromEntries(SECRET_FIELDS.map((f) => [f, undefined])));
    setFieldHandled(showFieldError(form, failed, ["name", "password", "private_key", "passphrase"]));
    if (!res) return;
    onCreated(res.credential);
    if (res.credential.kind === "private_key") setCreated(res.credential);
    else close();
  }

  return (
    <Drawer
      title={created ? "密钥已创建" : "新建密钥"}
      open={open}
      onClose={close}
      width={560}
      destroyOnHidden
      footer={
        created ? (
          <Button type="primary" onClick={close}>
            完成
          </Button>
        ) : (
          <Space>
            <Button onClick={close}>取消</Button>
            <Button type="primary" loading={!!act.busy} onClick={() => void submit()}>
              创建
            </Button>
          </Space>
        )
      }
    >
      {created ? (
        <>
          <Result status="success" title={created.name} subTitle={kindLabel(created)} style={{ padding: "8px 0 16px" }} />
          <PublicKeyHandoff cred={created} />
        </>
      ) : (
        <>
          <Segmented
            block
            options={modes}
            value={mode}
            onChange={(v) => {
              setMode(v as CreateMode);
              form.setFieldsValue(Object.fromEntries(SECRET_FIELDS.map((f) => [f, undefined])));
            }}
            style={{ marginBottom: 20 }}
          />
          {act.error && !fieldHandled ? <ApiErrorAlert error={act.error} /> : null}
          <Form form={form} layout="vertical" autoComplete="off" requiredMark="optional">
            <Form.Item name="name" label="名称" rules={[{ required: true, message: "请填写名称" }]}>
              <Input autoComplete="off" placeholder="例如 香港机器 root 密钥" />
            </Form.Item>
            <SecretInputs mode={mode} />
            <Form.Item name="notes" label="备注">
              <Input.TextArea rows={2} />
            </Form.Item>
          </Form>
        </>
      )}
    </Drawer>
  );
}

function RotateDrawer({ cred, onClose, onDone }: { cred: SSHCredentialView | null; onClose: () => void; onDone: (c: SSHCredentialView) => void }) {
  const [form] = Form.useForm();
  const [mode, setMode] = useState<CreateMode>("generate");
  const [rotated, setRotated] = useState<SSHCredentialView | null>(null);
  const [fieldHandled, setFieldHandled] = useState(false);
  const act = useAction();
  const effective: CreateMode = cred?.kind === "password" ? "password" : mode;

  const close = () => {
    form.resetFields();
    setRotated(null);
    act.clear();
    onClose();
  };

  async function submit() {
    if (!cred) return;
    let values: Record<string, string | undefined>;
    try {
      values = await form.validateFields();
    } catch {
      return;
    }
    let failed: ApiError | null = null;
    const res = await act.run(() => api.rotateCredential(cred.id, secretBody(effective, values)), "rotate", (e) => (failed = e));
    form.setFieldsValue(Object.fromEntries(SECRET_FIELDS.map((f) => [f, undefined])));
    setFieldHandled(showFieldError(form, failed, ["password", "private_key", "passphrase"]));
    if (!res) return;
    onDone(res.credential);
    if (res.credential.kind === "private_key") setRotated(res.credential);
    else close();
  }

  return (
    <Drawer
      title={rotated ? "已轮换" : `轮换 ${cred?.name ?? ""}`}
      open={!!cred}
      onClose={close}
      width={560}
      destroyOnHidden
      footer={
        rotated ? (
          <Button type="primary" onClick={close}>
            完成
          </Button>
        ) : (
          <Space>
            <Button onClick={close}>取消</Button>
            <Button type="primary" danger loading={!!act.busy} onClick={() => void submit()}>
              轮换
            </Button>
          </Space>
        )
      }
    >
      {rotated ? (
        <PublicKeyHandoff cred={rotated} />
      ) : (
        <>
          <Alert
            type="warning"
            showIcon
            style={{ marginBottom: 16 }}
            message="轮换保留同一个 ID，引用它的服务器自动改用新值。"
            description={
              cred?.kind === "password"
                ? "先在服务器上改好密码再轮换；轮换会清除这些服务器的连接测试结果。"
                : "新密钥的公钥要先加到服务器的 authorized_keys 上，否则之后的连接会失败；轮换会清除这些服务器的连接测试结果。"
            }
          />
          {cred?.kind === "private_key" ? (
            <Segmented
              block
              options={[
                { value: "generate", label: "生成新 ed25519" },
                { value: "import", label: "导入私钥" },
              ]}
              value={mode}
              onChange={(v) => setMode(v as CreateMode)}
              style={{ marginBottom: 20 }}
            />
          ) : null}
          {act.error && !fieldHandled ? <ApiErrorAlert error={act.error} /> : null}
          <Form form={form} layout="vertical" autoComplete="off">
            <SecretInputs mode={effective} />
          </Form>
          {cred && cred.in_use_by.length > 0 ? (
            <>
              <Typography.Text type="secondary">受影响的服务器和部署：</Typography.Text>
              <RefList refs={cred.in_use_by} />
            </>
          ) : null}
        </>
      )}
    </Drawer>
  );
}

function EditDrawer({ cred, onClose, onDone }: { cred: SSHCredentialView | null; onClose: () => void; onDone: (c: SSHCredentialView) => void }) {
  const [form] = Form.useForm();
  const act = useAction();
  return (
    <Drawer
      title={`编辑 ${cred?.name ?? ""}`}
      open={!!cred}
      onClose={() => {
        act.clear();
        onClose();
      }}
      width={480}
      destroyOnHidden
      footer={
        <Space>
          <Button onClick={onClose}>取消</Button>
          <Button
            type="primary"
            loading={!!act.busy}
            onClick={async () => {
              if (!cred) return;
              let v: { name: string; notes?: string; comment?: string };
              try {
                v = await form.validateFields();
              } catch {
                return;
              }
              const res = await act.run(() =>
                api.updateCredential(cred.id, { name: v.name, notes: v.notes ?? "", ...(cred.kind === "private_key" ? { comment: v.comment ?? "" } : {}) }),
              );
              if (res) {
                onDone(res.credential);
                onClose();
              }
            }}
          >
            保存
          </Button>
        </Space>
      }
    >
      {cred ? (
        <>
          <ApiErrorAlert error={act.error} />
          <Form form={form} layout="vertical" initialValues={{ name: cred.name, notes: cred.notes, comment: cred.comment }}>
            <Form.Item name="name" label="名称" rules={[{ required: true, message: "请填写名称" }]}>
              <Input autoComplete="off" />
            </Form.Item>
            {cred.kind === "private_key" ? (
              <Form.Item name="comment" label="公钥注释">
                <Input autoComplete="off" />
              </Form.Item>
            ) : null}
            <Form.Item name="notes" label="备注">
              <Input.TextArea rows={3} />
            </Form.Item>
          </Form>
          <Typography.Text type="secondary">要换密码或私钥，用「轮换」。</Typography.Text>
        </>
      ) : null}
    </Drawer>
  );
}

function CredentialDetail({
  cred,
  onClose,
  onRotate,
  onEdit,
  onDelete,
}: {
  cred: SSHCredentialView | undefined;
  onClose: () => void;
  onRotate: () => void;
  onEdit: () => void;
  onDelete: () => void;
}) {
  return (
    <Drawer
      title={cred?.name ?? "密钥"}
      open={!!cred}
      onClose={onClose}
      width={600}
      extra={
        cred ? (
          <Space>
            <Button onClick={onEdit}>编辑</Button>
            <Button onClick={onRotate}>轮换</Button>
            <Button danger onClick={onDelete}>
              删除
            </Button>
          </Space>
        ) : null
      }
    >
      {cred ? (
        <Space direction="vertical" size={20} style={{ width: "100%" }}>
          <Facts
            items={[
              ["ID", <Mono copy>{cred.id}</Mono>],
              ["种类", kindLabel(cred)],
              ["秘密", <Space><StatusTag kind={cred.secret_set ? "ok" : "attention"}>{cred.secret_set ? "已设置" : "未设置"}</StatusTag><Typography.Text type="secondary">不可查看</Typography.Text></Space>],
              ...(cred.kind === "private_key"
                ? ([
                    ["指纹", <Mono copy>{cred.fingerprint}</Mono>],
                    ["来源", cred.generated ? "面板生成" : "导入"],
                    ["私钥口令", cred.has_passphrase ? "有" : "无"],
                    ["注释", cred.comment || "—"],
                  ] as [string, ReactNode][])
                : []),
              ["创建", <TimeText value={cred.created_at} />],
              ["最近轮换", <TimeText value={cred.rotated_at} empty="从未轮换" />],
              ["备注", cred.notes || "—"],
            ]}
          />
          {cred.kind === "private_key" && cred.public_key ? (
            <div>
              <Typography.Title level={5}>公钥</Typography.Title>
              <PublicKeyHandoff cred={cred} fingerprint={false} />
            </div>
          ) : null}
          <div>
            <Typography.Title level={5}>使用者</Typography.Title>
            <RefList refs={cred.in_use_by} empty="没有服务器使用这把凭据" />
          </div>
        </Space>
      ) : null}
    </Drawer>
  );
}

export default function CredentialsPage() {
  const { route, navigate } = useRouter();
  const { message } = AntApp.useApp();
  const state = useApi(() => api.listCredentials(), []);
  const [creating, setCreating] = useState(route.query.get("new") === "1");
  const [rotating, setRotating] = useState<SSHCredentialView | null>(null);
  const [editing, setEditing] = useState<SSHCredentialView | null>(null);
  const [refused, setRefused] = useState<ApiError | null>(null);
  const confirm = useConfirmDanger();
  const selectedId = route.params[0];
  const creds = state.data?.credentials ?? [];
  const selected = creds.find((c) => c.id === selectedId);
  // A link to an object this page has not loaded yet (created elsewhere): re-read once.
  const [reread, setReread] = useState<string | null>(null);
  useEffect(() => {
    if (selectedId && state.data && !selected && reread !== selectedId) {
      setReread(selectedId);
      void state.reload();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId, state.data, selected]);

  const upsert = (c: SSHCredentialView) =>
    state.setData((d) => {
      if (!d) return d;
      const rest = d.credentials.filter((x) => x.id !== c.id);
      return { credentials: [...rest, c].sort((a, b) => a.name.localeCompare(b.name)) };
    });

  const askDelete = (c: SSHCredentialView) =>
    confirm({
      title: `删除密钥「${c.name}」？`,
      consequence:
        c.in_use_by.length > 0
          ? "它仍被引用，面板会拒绝删除并列出引用者。"
          : "删除后无法恢复，面板里存的密码或私钥一并清除；服务器上的 authorized_keys 不会被改动。",
      okText: "删除",
      onOk: async () => {
        try {
          await api.deleteCredential(c.id);
          message.success("已删除");
          if (selectedId === c.id) navigate(href("keys"), { replace: true });
          await state.reload();
        } catch (e) {
          setRefused(e as ApiError);
          void state.reload();
        }
      },
    });

  return (
    <Page
      title="密钥"
      description="登录服务器用的 SSH 密码和私钥，以及外部 SOCKS 出口的用户名和密码。可以被复用；保存后只能替换，不能再查看。"
      extra={
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreating(true)}>
          新建密钥
        </Button>
      }
    >
      <DataView
        state={state}
        isEmpty={(d) => d.credentials.length === 0}
        empty={
          <EmptyState
            title="还没有 SSH 密钥"
            description="添加服务器之前先准备登录方式：让面板生成一把 ed25519 密钥，导入已有私钥，或者保存一个密码。"
            action={
              <Button type="primary" onClick={() => setCreating(true)}>
                新建密钥
              </Button>
            }
          />
        }
      >
        {(d) => (
          <DataTable
            rowKey="id"
            dataSource={d.credentials}
            pageSize={50}
            onRow={(c) => ({ "data-testid": `credential-row-${c.id}` }) as React.HTMLAttributes<HTMLElement>}
            columns={[
              {
                title: "名称",
                dataIndex: "name",
                kind: "flex",
                width: 150,
                render: (_, c) => <Link to={href("keys", c.id)}>{c.name}</Link>,
              },
              {
                title: "种类",
                kind: "flex",
                width: 150,
                render: (_, c) => (
                  <Space size={4} wrap>
                    <span>{kindLabel(c)}</span>
                    {c.generated ? <Tag>面板生成</Tag> : null}
                    {c.has_passphrase ? <Tag>有口令</Tag> : null}
                  </Space>
                ),
              },
              {
                title: "指纹",
                kind: "flex",
                width: 200,
                render: (_, c) => (c.kind === "private_key" ? <Mono ellipsis>{c.fingerprint}</Mono> : <Typography.Text type="secondary">—</Typography.Text>),
              },
              { title: "创建", kind: "fixed", width: 100, card: "detail", render: (_, c) => <TimeText value={c.created_at} /> },
              { title: "最近轮换", kind: "fixed", width: 100, card: "detail", render: (_, c) => <TimeText value={c.rotated_at} empty="—" /> },
              {
                title: "使用者",
                kind: "flex",
                width: 150,
                render: (_, c) =>
                  c.in_use_by.length === 0 ? (
                    <Typography.Text type="secondary">未使用</Typography.Text>
                  ) : (
                    <Space size={[4, 0]} wrap>
                      {c.in_use_by.slice(0, 3).map((r) => (
                        <Link key={r.kind + r.id} to={r.kind === "server" ? href("servers", r.id) : href("cloudflare") + "?section=mesh"}>
                          {r.name || r.id}
                        </Link>
                      ))}
                      {c.in_use_by.length > 3 ? <Typography.Text type="secondary">等 {c.in_use_by.length} 个</Typography.Text> : null}
                    </Space>
                  ),
              },
              {
                title: "操作",
                kind: "actions",
                width: 100,
                render: (_, c) => (
                  <RowActions
                    label={c.name}
                    more={[
                      { key: "rotate", label: "轮换", onClick: () => setRotating(c) },
                      { key: "delete", label: "删除", danger: true, onClick: () => askDelete(c) },
                    ]}
                  >
                    <Button type="link" size="small" onClick={() => setEditing(c)}>
                      编辑
                    </Button>
                  </RowActions>
                ),
              },
            ]}
          />
        )}
      </DataView>

      <CredentialCreateDrawer
        open={creating}
        onClose={() => {
          setCreating(false);
          if (route.query.get("new")) navigate(href("keys"), { replace: true });
        }}
        onCreated={(c) => {
          upsert(c);
          message.success(`已创建「${c.name}」`);
        }}
      />
      <CredentialDetail
        cred={selected}
        onClose={() => navigate(href("keys"))}
        onRotate={() => selected && setRotating(selected)}
        onEdit={() => selected && setEditing(selected)}
        onDelete={() => selected && askDelete(selected)}
      />
      <RotateDrawer
        cred={rotating}
        onClose={() => setRotating(null)}
        onDone={(c) => {
          upsert(c);
          message.success("已轮换");
        }}
      />
      <EditDrawer cred={editing} onClose={() => setEditing(null)} onDone={(c) => upsert(c)} />
      <RefusedDialog error={refused} title="不能删除这把密钥" onClose={() => setRefused(null)} />
      <SocksSection focus={route.query.get("section") === "socks"} openCreate={route.query.get("socks") === "new"} />
      {selectedId && state.data && !selected && !state.loading && reread === selectedId ? (
        <Alert type="warning" showIcon style={{ marginTop: 16 }} message={`没有 ID 为 ${selectedId} 的密钥，它可能已被删除。`} />
      ) : null}
    </Page>
  );
}

// ---------------------------------------------------- SOCKS credentials ---
//
// Username and password of the SOCKS5 proxy behind an external SOCKS exit.
// Both halves are secret: sent once (create or rotate), never returned,
// never kept in component state beyond the form, cleared after every
// request whatever its outcome.

const SOCKS_SECRET_FIELDS = ["username", "password"] as const;
const SOCKS_VALUE_HELP = "1–255 个可打印 ASCII 字符，不能有空白、引号、反斜杠和 @ : / # ? % &。";

function SocksSecretInputs() {
  const rule = (what: string) => [
    { required: true, message: `请填写${what}` },
    { pattern: SOCKS_VALUE_RE, message: `${what}必须是${SOCKS_VALUE_HELP}` },
  ];
  return (
    <>
      <Form.Item name="username" label="SOCKS 用户名" rules={rule("用户名")} extra={SOCKS_VALUE_HELP}>
        <SecretField aria-label="SOCKS 用户名" />
      </Form.Item>
      <Form.Item name="password" label="SOCKS 密码" rules={rule("密码")} extra="提交后两个输入框立即清空，之后不能再查看，只能轮换。">
        <SecretField aria-label="SOCKS 密码" />
      </Form.Item>
    </>
  );
}

function SocksCreateDrawer({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (c: SOCKSCredentialView) => void }) {
  const [form] = Form.useForm();
  const [fieldHandled, setFieldHandled] = useState(false);
  const act = useAction();
  const close = () => {
    form.resetFields();
    act.clear();
    onClose();
  };
  async function submit() {
    let v: Record<string, string | undefined>;
    try {
      v = await form.validateFields();
    } catch {
      // Invalid input: the secrets leave the form all the same.
      form.setFieldsValue(Object.fromEntries(SOCKS_SECRET_FIELDS.map((f) => [f, undefined])));
      return;
    }
    let failed: ApiError | null = null;
    const res = await act.run(
      () => api.createSocksCredential({ name: (v.name ?? "").trim(), notes: v.notes ?? "", username: v.username ?? "", password: v.password ?? "" }),
      "create",
      (e) => (failed = e),
    );
    form.setFieldsValue(Object.fromEntries(SOCKS_SECRET_FIELDS.map((f) => [f, undefined])));
    setFieldHandled(showFieldError(form, failed, ["name", "notes", "username", "password"]));
    if (!res) return;
    onCreated(res.credential);
    close();
  }
  return (
    <Drawer
      title="新建 SOCKS 凭据"
      open={open}
      onClose={close}
      width={520}
      destroyOnHidden
      footer={
        <Space>
          <Button onClick={close}>取消</Button>
          <Button type="primary" loading={!!act.busy} onClick={() => void submit()}>
            创建
          </Button>
        </Space>
      }
    >
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        message="外部 SOCKS 出口所用代理的用户名和密码。"
        description="只在装机时写进承载节点的转发配置；面板从不登录那台代理设备，也不会再显示这两个值。"
      />
      {act.error && !fieldHandled ? <ApiErrorAlert error={act.error} /> : null}
      <Form form={form} layout="vertical" autoComplete="off" requiredMark="optional">
        <Form.Item name="name" label="名称" rules={[{ required: true, message: "请填写名称" }]}>
          <Input autoComplete="off" placeholder="例如 马来西亚住宅代理" />
        </Form.Item>
        <SocksSecretInputs />
        <Form.Item name="notes" label="备注">
          <Input.TextArea rows={2} />
        </Form.Item>
      </Form>
    </Drawer>
  );
}

function SocksRotateDrawer({ cred, onClose, onDone }: { cred: SOCKSCredentialView | null; onClose: () => void; onDone: (c: SOCKSCredentialView) => void }) {
  const [form] = Form.useForm();
  const [fieldHandled, setFieldHandled] = useState(false);
  const act = useAction();
  const close = () => {
    form.resetFields();
    act.clear();
    onClose();
  };
  async function submit() {
    if (!cred) return;
    let v: Record<string, string | undefined>;
    try {
      v = await form.validateFields();
    } catch {
      form.setFieldsValue(Object.fromEntries(SOCKS_SECRET_FIELDS.map((f) => [f, undefined])));
      return;
    }
    let failed: ApiError | null = null;
    const res = await act.run(() => api.rotateSocksCredential(cred.id, { username: v.username ?? "", password: v.password ?? "" }), "rotate", (e) => (failed = e));
    form.setFieldsValue(Object.fromEntries(SOCKS_SECRET_FIELDS.map((f) => [f, undefined])));
    setFieldHandled(showFieldError(form, failed, ["username", "password"]));
    if (!res) return;
    onDone(res.credential);
    close();
  }
  return (
    <Drawer
      title={`轮换 ${cred?.name ?? ""}`}
      open={!!cred}
      onClose={close}
      width={520}
      destroyOnHidden
      footer={
        <Space>
          <Button onClick={close}>取消</Button>
          <Button type="primary" danger loading={!!act.busy} onClick={() => void submit()}>
            轮换
          </Button>
        </Space>
      }
    >
      <Alert
        type="warning"
        showIcon
        style={{ marginBottom: 16 }}
        message="轮换保留同一个 ID，引用它的外部出口改用新的用户名和密码。"
        description="新值要在承载节点重新装机后才生效；先在代理上改好，再轮换，再到「部署」页重新下发承载节点。"
      />
      {act.error && !fieldHandled ? <ApiErrorAlert error={act.error} /> : null}
      <Form form={form} layout="vertical" autoComplete="off">
        <SocksSecretInputs />
      </Form>
      {cred && cred.used_by.length > 0 ? (
        <>
          <Typography.Text type="secondary">受影响的外部出口：</Typography.Text>
          <RefList refs={cred.used_by} />
        </>
      ) : null}
    </Drawer>
  );
}

function SocksEditDrawer({ cred, onClose, onDone }: { cred: SOCKSCredentialView | null; onClose: () => void; onDone: (c: SOCKSCredentialView) => void }) {
  const [form] = Form.useForm();
  const act = useAction();
  const close = () => {
    act.clear();
    onClose();
  };
  return (
    <Drawer
      title={`编辑 ${cred?.name ?? ""}`}
      open={!!cred}
      onClose={close}
      width={480}
      destroyOnHidden
      footer={
        <Space>
          <Button onClick={close}>取消</Button>
          <Button
            type="primary"
            loading={!!act.busy}
            onClick={async () => {
              if (!cred) return;
              let v: { name: string; notes?: string };
              try {
                v = await form.validateFields();
              } catch {
                return;
              }
              const res = await act.run(() => api.updateSocksCredential(cred.id, { name: v.name.trim(), notes: v.notes ?? "" }));
              if (res) {
                onDone(res.credential);
                close();
              }
            }}
          >
            保存
          </Button>
        </Space>
      }
    >
      {cred ? (
        <>
          <ApiErrorAlert error={act.error} />
          <Form form={form} layout="vertical" initialValues={{ name: cred.name, notes: cred.notes }}>
            <Form.Item name="name" label="名称" rules={[{ required: true, message: "请填写名称" }]}>
              <Input autoComplete="off" />
            </Form.Item>
            <Form.Item name="notes" label="备注">
              <Input.TextArea rows={3} />
            </Form.Item>
          </Form>
          <Typography.Text type="secondary">要换用户名或密码，用「轮换」。</Typography.Text>
        </>
      ) : null}
    </Drawer>
  );
}

/** The SOCKS credentials of external SOCKS exits (section of the 密钥 page). */
function SocksSection({ focus, openCreate }: { focus: boolean; openCreate: boolean }) {
  const { message } = AntApp.useApp();
  const state = useApi(() => api.listSocksCredentials(), []);
  const [creating, setCreating] = useState(openCreate);
  const [rotating, setRotating] = useState<SOCKSCredentialView | null>(null);
  const [editing, setEditing] = useState<SOCKSCredentialView | null>(null);
  const [refused, setRefused] = useState<ApiError | null>(null);
  const confirm = useConfirmDanger();
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (focus) ref.current?.scrollIntoView?.({ block: "start" });
  }, [focus]);

  const upsert = (c: SOCKSCredentialView) =>
    state.setData((d) => {
      if (!d) return d;
      const rest = d.credentials.filter((x) => x.id !== c.id);
      return { credentials: [...rest, c].sort((a, b) => a.name.localeCompare(b.name)) };
    });

  const askDelete = (c: SOCKSCredentialView) =>
    confirm({
      title: `删除 SOCKS 凭据「${c.name}」？`,
      consequence:
        c.used_by.length > 0
          ? "它仍被外部出口使用，面板会拒绝删除并列出这些出口。"
          : "删除后无法恢复，面板里存的用户名和密码一并清除；代理设备本身不受影响。",
      okText: "删除",
      onOk: async () => {
        try {
          await api.deleteSocksCredential(c.id);
          message.success("已删除");
          await state.reload();
        } catch (e) {
          setRefused(e as ApiError);
          void state.reload();
        }
      },
    });

  return (
    <div ref={ref} data-testid="socks-credentials">
      <Section
        id="socks"
        title="SOCKS 凭据"
        extra={
          <Button icon={<PlusOutlined />} onClick={() => setCreating(true)}>
            新建 SOCKS 凭据
          </Button>
        }
      >
        <Typography.Paragraph type="secondary">
          外部 SOCKS 出口所用代理的用户名和密码。只写不读：保存后不能再查看，只能轮换；只在承载节点装机时使用。
        </Typography.Paragraph>
        <DataView
          state={state}
          rows={3}
          isEmpty={(d) => d.credentials.length === 0}
          empty={<EmptyState title="还没有 SOCKS 凭据" description="添加外部 SOCKS 出口之前，先在这里保存代理的用户名和密码。" />}
        >
          {(d) => (
            <DataTable
              rowKey="id"
              dataSource={d.credentials}
              pageSize={50}
              onRow={(c) => ({ "data-testid": `socks-row-${c.id}` }) as React.HTMLAttributes<HTMLElement>}
              columns={[
                {
                  title: "名称",
                  dataIndex: "name",
                  kind: "flex",
                  width: 160,
                  render: (_, c) => (
                    <span>
                      {c.name} <Typography.Text type="secondary" className="mono-small">{c.id}</Typography.Text>
                    </span>
                  ),
                },
                { title: "备注", kind: "flex", width: 160, card: "detail", render: (_, c) => c.notes || <Typography.Text type="secondary">—</Typography.Text> },
                {
                  title: "用户名和密码",
                  kind: "fixed",
                  width: 150,
                  render: (_, c) => (
                    <Space size={4}>
                      <StatusTag kind={c.secret_set ? "ok" : "attention"}>{c.secret_set ? "已设置" : "未设置"}</StatusTag>
                      <Typography.Text type="secondary">不可查看</Typography.Text>
                    </Space>
                  ),
                },
                { title: "创建", kind: "fixed", width: 100, card: "detail", render: (_, c) => <TimeText value={c.created_at} /> },
                { title: "最近轮换", kind: "fixed", width: 100, card: "detail", render: (_, c) => <TimeText value={c.rotated_at} empty="—" /> },
                {
                  title: "使用者",
                  kind: "flex",
                  width: 140,
                  render: (_, c) =>
                    c.used_by.length === 0 ? (
                      <Typography.Text type="secondary">未使用</Typography.Text>
                    ) : (
                      <Space size={[4, 0]} wrap>
                        {c.used_by.slice(0, 3).map((r) => (
                          <Link key={r.kind + r.id} to={href("exits")}>
                            {r.name || r.id}
                          </Link>
                        ))}
                        {c.used_by.length > 3 ? <Typography.Text type="secondary">等 {c.used_by.length} 个</Typography.Text> : null}
                      </Space>
                    ),
                },
                {
                  title: "操作",
                  kind: "actions",
                  width: 100,
                  render: (_, c) => (
                    <RowActions
                      label={c.name}
                      more={[
                        { key: "rotate", label: "轮换", onClick: () => setRotating(c) },
                        { key: "delete", label: "删除", danger: true, onClick: () => askDelete(c) },
                      ]}
                    >
                      <Button type="link" size="small" onClick={() => setEditing(c)}>
                        编辑
                      </Button>
                    </RowActions>
                  ),
                },
              ]}
            />
          )}
        </DataView>
      </Section>
      <SocksCreateDrawer
        open={creating}
        onClose={() => setCreating(false)}
        onCreated={(c) => {
          upsert(c);
          message.success(`已创建「${c.name}」`);
        }}
      />
      <SocksRotateDrawer
        cred={rotating}
        onClose={() => setRotating(null)}
        onDone={(c) => {
          upsert(c);
          message.success("已轮换；承载节点重新装机后生效");
        }}
      />
      <SocksEditDrawer cred={editing} onClose={() => setEditing(null)} onDone={(c) => upsert(c)} />
      <RefusedDialog error={refused} title="不能删除这个 SOCKS 凭据" onClose={() => setRefused(null)} />
    </div>
  );
}
