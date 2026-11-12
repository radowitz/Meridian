// 密钥: reusable SSH credentials (passwords and private keys). Secrets are
// write-only: the public key and fingerprint are always viewable, the
// password / private key / passphrase never are.

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
  Table,
  Tag,
  Typography,
} from "antd";
import { useEffect, useState, type ReactNode } from "react";
import * as api from "./api";
import { href, useRouter } from "./state";
import type { SSHCredentialCreate, SSHCredentialView, SSHSecretInput } from "./types";
import {
  ApiErrorAlert,
  DataView,
  EmptyState,
  Facts,
  Link,
  Mono,
  Page,
  RefList,
  RefusedDialog,
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
      description="登录服务器用的 SSH 密码和私钥。可以被多台服务器复用；保存后只能替换，不能再查看。"
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
          <Table
            rowKey="id"
            dataSource={d.credentials}
            pagination={false}
            scroll={{ x: 860 }}
            columns={[
              {
                title: "名称",
                dataIndex: "name",
                width: 180,
                render: (_, c) => <Link to={href("keys", c.id)}>{c.name}</Link>,
              },
              {
                title: "种类",
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
                width: 260,
                render: (_, c) => (c.kind === "private_key" ? <Mono ellipsis>{c.fingerprint}</Mono> : <Typography.Text type="secondary">—</Typography.Text>),
              },
              { title: "创建", width: 110, render: (_, c) => <TimeText value={c.created_at} /> },
              { title: "最近轮换", width: 110, render: (_, c) => <TimeText value={c.rotated_at} empty="—" /> },
              {
                title: "使用者",
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
                title: "",
                width: 170,
                className: "table-actions",
                render: (_, c) => (
                  <Space size={0}>
                    <Button type="link" size="small" onClick={() => setRotating(c)}>
                      轮换
                    </Button>
                    <Button type="link" size="small" onClick={() => setEditing(c)}>
                      编辑
                    </Button>
                    <Button type="link" size="small" danger onClick={() => askDelete(c)}>
                      删除
                    </Button>
                  </Space>
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
      {selectedId && state.data && !selected && !state.loading && reread === selectedId ? (
        <Alert type="warning" showIcon style={{ marginTop: 16 }} message={`没有 ID 为 ${selectedId} 的密钥，它可能已被删除。`} />
      ) : null}
    </Page>
  );
}
