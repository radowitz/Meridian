// 服务器: managed remote hosts (relays, hubs, exits). The core interaction is
// the way from "added" to "ready": choose a credential → fetch the host key
// fingerprint → confirm and pin exactly that value → connection test.

import { PlusOutlined, SafetyCertificateOutlined, WarningFilled } from "@ant-design/icons";
import {
  Alert,
  App as AntApp,
  Button,
  Descriptions,
  Divider,
  Drawer,
  Form,
  Input,
  InputNumber,
  Radio,
  Select,
  Space,
  Steps,
  Table,
  Tag,
  Typography,
} from "antd";
import { useEffect, useMemo, useState, type HTMLAttributes, type ReactNode } from "react";
import * as api from "./api";
import type { ApiError } from "./api";
import { CredentialCreateDrawer, kindLabel } from "./CredentialsPage";
import { href, useRouter } from "./state";
import type { AuthMethod, SSHCredentialView, ServerInput, ServerPatch, ServerView } from "./types";
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
  StatusTag,
  TimeText,
  showFieldError,
  useAction,
  useApi,
  useConfirmDanger,
  type StatusKind,
} from "./ui";

// ------------------------------------------------------------ vocabulary ---

export const HOST_KEY_STATUS: Record<string, { kind: StatusKind; label: string }> = {
  unknown: { kind: "neutral", label: "未获取" },
  discovered: { kind: "attention", label: "待确认" },
  trusted: { kind: "ok", label: "已固定" },
  mismatch: { kind: "failed", label: "指纹不符" },
};

const MISSING_LABEL: Record<string, string> = {
  credential: "选择密钥",
  host_key: "确认主机指纹",
  connection_test: "通过连接测试",
};

const TEST_CODE: Record<string, string> = {
  unreachable: "连不上",
  timeout: "超时",
  auth_failed: "登录被拒绝",
  host_key_mismatch: "主机指纹不符",
  host_key_untrusted: "主机指纹未确认",
  command_failed: "命令失败",
};

export function serverReadiness(s: ServerView): { kind: StatusKind; label: string } {
  if (s.host_key.state === "mismatch") return { kind: "failed", label: "指纹不符" };
  if (s.ready) return { kind: "ok", label: "就绪" };
  if (s.last_test && !s.last_test.ok && s.operable) return { kind: "failed", label: "连接失败" };
  return { kind: "attention", label: "需要处理" };
}

function authLabel(a: AuthMethod) {
  return a === "password" ? "密码" : "密钥";
}

const credKindFor = (auth: AuthMethod) => (auth === "password" ? "password" : "private_key");

// ------------------------------------------------------------- the form ---

interface FormValues {
  name: string;
  address: string;
  port: number;
  user: string;
  auth: AuthMethod;
  credential_id?: string;
  tags?: string[];
  notes?: string;
}

function ServerFormDrawer({
  open,
  server,
  creds,
  onClose,
  onSaved,
  onCredCreated,
}: {
  open: boolean;
  server: ServerView | null;
  creds: SSHCredentialView[];
  onClose: () => void;
  onSaved: (s: ServerView, created: boolean) => void;
  onCredCreated: (c: SSHCredentialView) => void;
}) {
  const [form] = Form.useForm<FormValues>();
  const act = useAction();
  const confirm = useConfirmDanger();
  const [refused, setRefused] = useState<ApiError | null>(null);
  const [fieldHandled, setFieldHandled] = useState(false);
  const [newCred, setNewCred] = useState(false);
  const auth = Form.useWatch("auth", form) ?? server?.auth ?? "key";
  const options = creds
    .filter((c) => c.kind === credKindFor(auth))
    .map((c) => ({ value: c.id, label: `${c.name} · ${kindLabel(c)}` }));

  const initial: FormValues = server
    ? {
        name: server.name,
        address: server.address,
        port: server.port,
        user: server.user,
        auth: server.auth,
        credential_id: server.credential_id || undefined,
        tags: server.tags ?? [],
        notes: server.notes,
      }
    : { name: "", address: "", port: 22, user: "root", auth: "key", tags: [] };

  async function save() {
    let v: FormValues;
    try {
      v = await form.validateFields();
    } catch {
      return;
    }
    setFieldHandled(false);
    const fields = ["name", "address", "port", "user", "auth", "credential_id", "tags", "notes"];
    const onError = (e: ApiError) => {
      if (e.code === "in_use") setRefused(e);
      else setFieldHandled(showFieldError(form, e, fields));
    };
    if (!server) {
      const input: ServerInput = {
        name: v.name.trim(),
        address: v.address.trim(),
        port: v.port,
        user: v.user.trim(),
        auth: v.auth,
        credential_id: v.credential_id ?? "",
        tags: v.tags ?? [],
        notes: v.notes ?? "",
      };
      const res = await act.run(() => api.createServer(input), "save", onError);
      if (res) onSaved(res.server, true);
      return;
    }
    const patch: ServerPatch = {};
    if (v.name.trim() !== server.name) patch.name = v.name.trim();
    if (v.address.trim() !== server.address) patch.address = v.address.trim();
    if (v.port !== server.port) patch.port = v.port;
    if (v.user.trim() !== server.user) patch.user = v.user.trim();
    if (v.auth !== server.auth) patch.auth = v.auth;
    if ((v.credential_id ?? "") !== (server.credential_id ?? "")) patch.credential_id = v.credential_id ?? "";
    if (JSON.stringify(v.tags ?? []) !== JSON.stringify(server.tags ?? [])) patch.tags = v.tags ?? [];
    if ((v.notes ?? "") !== (server.notes ?? "")) patch.notes = v.notes ?? "";
    if (Object.keys(patch).length === 0) {
      onClose();
      return;
    }
    const endpoint = patch.address !== undefined || patch.port !== undefined;
    const login = patch.user !== undefined || patch.auth !== undefined || patch.credential_id !== undefined;
    const doSave = async () => {
      const res = await act.run(() => api.updateServer(server.id, patch), "save", onError);
      if (res) onSaved(res.server, false);
    };
    const consequences: string[] = [];
    if (endpoint && server.host_key.state !== "unknown")
      consequences.push("改地址或端口会清除已固定的主机指纹，保存后要重新获取并核对指纹。");
    if ((endpoint || login) && server.last_test) consequences.push("连接测试结果会被清除，需要重新测试。");
    if (consequences.length > 0) {
      confirm({
        title: "保存这些修改？",
        consequence: consequences.join(""),
        okText: "保存",
        danger: false,
        onOk: doSave,
      });
    } else {
      await doSave();
    }
  }

  return (
    <Drawer
      title={server ? `编辑 ${server.name}` : "添加服务器"}
      open={open}
      onClose={onClose}
      width={520}
      destroyOnHidden
      footer={
        <Space>
          <Button onClick={onClose}>取消</Button>
          <Button type="primary" loading={act.busy === "save"} onClick={() => void save()}>
            {server ? "保存" : "添加"}
          </Button>
        </Space>
      }
    >
      {act.error && !fieldHandled && act.error.code !== "in_use" ? <ApiErrorAlert error={act.error} /> : null}
      {server && (server.host_key.state !== "unknown" || server.last_test) ? (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          message="改地址或端口会清除已固定的主机指纹；改地址、端口、用户、认证方式或密钥会清除连接测试结果。"
        />
      ) : null}
      <Form form={form} layout="vertical" initialValues={initial} autoComplete="off" requiredMark="optional">
        <Form.Item name="name" label="名称" rules={[{ required: true, message: "请填写名称" }]}>
          <Input placeholder="例如 香港枢纽" />
        </Form.Item>
        <Space.Compact block>
          <Form.Item
            name="address"
            label="地址"
            style={{ flex: 1 }}
            rules={[{ required: true, message: "请填写 IP 或主机名" }]}
          >
            <Input placeholder="IP 或主机名" className="mono" />
          </Form.Item>
          <Form.Item name="port" label="SSH 端口" style={{ width: 120 }} rules={[{ required: true, message: "端口" }]}>
            <InputNumber min={1} max={65535} style={{ width: "100%" }} />
          </Form.Item>
        </Space.Compact>
        <Form.Item name="user" label="登录用户" rules={[{ required: true, message: "请填写用户" }]}>
          <Input className="mono" />
        </Form.Item>
        <Form.Item name="auth" label="认证方式">
          <Radio.Group
            optionType="button"
            options={[
              { value: "key", label: "密钥" },
              { value: "password", label: "密码" },
            ]}
            onChange={() => form.setFieldValue("credential_id", undefined)}
          />
        </Form.Item>
        <Form.Item label={auth === "password" ? "密码凭据" : "SSH 密钥"} extra="没有合适的？可以新建，新建后自动选中。">
          <Space.Compact block>
            <Form.Item name="credential_id" noStyle>
              <Select
                allowClear
                placeholder={options.length ? "选择一个" : auth === "password" ? "还没有密码凭据" : "还没有 SSH 密钥"}
                options={options}
                style={{ flex: 1 }}
                aria-label="凭据"
              />
            </Form.Item>
            <Button onClick={() => setNewCred(true)}>新建</Button>
          </Space.Compact>
        </Form.Item>
        <Form.Item name="tags" label="标签">
          <Select mode="tags" tokenSeparators={[",", " "]} placeholder="例如 hk、出口" />
        </Form.Item>
        <Form.Item name="notes" label="备注">
          <Input.TextArea rows={2} />
        </Form.Item>
      </Form>
      <CredentialCreateDrawer
        open={newCred}
        fixedKind={credKindFor(auth)}
        onClose={() => setNewCred(false)}
        onCreated={(c) => {
          onCredCreated(c);
          form.setFieldValue("credential_id", c.id);
        }}
      />
      <RefusedDialog error={refused} title="这台服务器被部署固定，不能修改连接信息" onClose={() => setRefused(null)} />
    </Drawer>
  );
}

// ------------------------------------------------------------- the flow ---

function FingerprintRows({ rows }: { rows: [string, string | undefined, string | undefined, string | undefined][] }) {
  return (
    <div className="fp-compare">
      {rows.map(([label, keyType, fp, at]) => (
        <div key={label} style={{ display: "contents" }}>
          <Typography.Text type="secondary">{label}</Typography.Text>
          <Space size={6} wrap>
            {keyType ? <Tag>{keyType}</Tag> : null}
            <Mono copy>{fp}</Mono>
            {at ? <TimeText value={at} /> : null}
          </Space>
        </div>
      ))}
    </div>
  );
}

function OutOfBandHint() {
  return (
    <Typography.Paragraph type="secondary" style={{ marginTop: 8, marginBottom: 0 }}>
      在服务器控制台（云厂商的 VNC / 串口，或已经信任的会话）里运行{" "}
      <code>for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf "$f"; done</code>，对应类型的 SHA256 值一致才确认。
    </Typography.Paragraph>
  );
}

function ServerFlow({
  server,
  creds,
  onChanged,
  onEdit,
  onCredCreated,
}: {
  server: ServerView;
  creds: SSHCredentialView[];
  onChanged: (s: ServerView) => void;
  onEdit: () => void;
  onCredCreated: (c: SSHCredentialView) => void;
}) {
  const act = useAction();
  const confirm = useConfirmDanger();
  const { message } = AntApp.useApp();
  const [pick, setPick] = useState<string | undefined>(undefined);
  const [newCred, setNewCred] = useState(false);
  const [matched, setMatched] = useState<boolean | null>(null);
  const hk = server.host_key;
  const mismatch = hk.state === "mismatch";
  const hasCred = !!server.credential;
  const credOptions = creds.filter((c) => c.kind === credKindFor(server.auth)).map((c) => ({ value: c.id, label: c.name }));

  const discover = () =>
    act.run(async () => {
      setMatched(null);
      const r = await api.discoverHostKey(server.id);
      onChanged(r.server);
      if (r.discovery.matches_pinned) {
        setMatched(true);
        message.success("指纹与已固定的一致");
      }
    }, "discover");

  const trust = (fp: string, title: string, consequence: string) =>
    confirm({
      title,
      consequence,
      okText: "确认并固定",
      danger: mismatch,
      onOk: () =>
        act.run(async () => {
          const r = await api.trustHostKey(server.id, fp);
          onChanged(r.server);
          message.success("已固定主机指纹");
        }, "trust"),
    });

  const forget = () =>
    confirm({
      title: "清除已固定的指纹？",
      consequence: "删除已固定的指纹，回到「未获取」；之后要重新获取并核对指纹，使用这台服务器的操作在此之前都会被拒绝。",
      okText: "清除",
      onOk: () =>
        act.run(async () => {
          const r = await api.forgetHostKey(server.id);
          onChanged(r.server);
        }, "forget"),
    });

  const test = () =>
    act.run(async () => {
      try {
        const r = await api.testServer(server.id);
        onChanged(r.server);
        if (r.test.ok) message.success("连接测试通过");
      } finally {
        // A failed test is recorded on the server too.
        try {
          onChanged((await api.getServer(server.id)).server);
        } catch {
          /* keep the last view */
        }
      }
    }, "test");

  const stepCred = hasCred ? "finish" : "process";
  const stepSeen = mismatch ? "error" : hk.state === "unknown" ? (hasCred ? "process" : "wait") : "finish";
  const stepTrust = mismatch ? "error" : hk.state === "trusted" ? "finish" : hk.state === "discovered" ? "process" : "wait";
  const lt = server.last_test;
  const stepTest = hk.state !== "trusted" || !hasCred ? "wait" : lt?.ok ? "finish" : lt ? "error" : "process";

  return (
    <div data-testid="server-flow">
      {act.error ? <ApiErrorAlert error={act.error} onClose={act.clear} /> : null}
      {mismatch ? (
        <Alert
          type="error"
          showIcon
          icon={<WarningFilled />}
          style={{ marginBottom: 20 }}
          data-testid="host-key-mismatch"
          message="主机指纹与固定值不符，所有连接都被拒绝"
          description={
            <Space direction="vertical" style={{ width: "100%" }}>
              <FingerprintRows
                rows={[
                  ["已固定", hk.key_type, hk.fingerprint, hk.pinned_at],
                  ["这次看到", hk.seen_key_type, hk.seen_fingerprint, hk.seen_at],
                ]}
              />
              <Typography.Text>
                如果刚重装了系统或换过主机密钥，这是预期的；否则可能有人在冒充这台服务器。先在服务器控制台核对新指纹。
              </Typography.Text>
              <OutOfBandHint />
              <Space wrap style={{ marginTop: 4 }}>
                <Button
                  danger
                  type="primary"
                  disabled={!hk.seen_fingerprint}
                  loading={act.busy === "trust"}
                  onClick={() =>
                    trust(
                      hk.seen_fingerprint!,
                      "信任新指纹？",
                      `以后只接受 ${hk.seen_fingerprint}，旧指纹作废。只在控制台核对过新指纹之后这样做。`,
                    )
                  }
                >
                  信任新指纹
                </Button>
                <Button loading={act.busy === "forget"} onClick={forget}>
                  清除固定并重新获取
                </Button>
              </Space>
            </Space>
          }
        />
      ) : null}
      <Steps
        direction="vertical"
        size="small"
        items={[
          {
            title: "选择密钥",
            status: stepCred,
            description: (
              <div className="step-body">
                {hasCred ? (
                  <Space wrap>
                    <span>
                      {authLabel(server.auth)}登录，使用{" "}
                      <Link to={href("keys", server.credential!.id)}>{server.credential!.name}</Link>
                    </span>
                    <Button size="small" onClick={onEdit}>
                      更换
                    </Button>
                  </Space>
                ) : (
                  <Space wrap>
                    <Select
                      style={{ minWidth: 220 }}
                      placeholder={credOptions.length ? `选择${server.auth === "password" ? "密码凭据" : "SSH 密钥"}` : "还没有可用的凭据"}
                      options={credOptions}
                      value={pick}
                      onChange={setPick}
                      aria-label="选择凭据"
                    />
                    <Button
                      type="primary"
                      disabled={!pick}
                      loading={act.busy === "cred"}
                      onClick={() =>
                        act.run(async () => {
                          const r = await api.updateServer(server.id, { credential_id: pick });
                          onChanged(r.server);
                        }, "cred")
                      }
                    >
                      使用
                    </Button>
                    <Button onClick={() => setNewCred(true)}>新建</Button>
                  </Space>
                )}
              </div>
            ),
          },
          {
            title: "获取主机指纹",
            status: stepSeen,
            description: (
              <div className="step-body">
                {hk.state === "discovered" ? (
                  <>
                    <FingerprintRows rows={[["看到", hk.seen_key_type, hk.seen_fingerprint, hk.seen_at]]} />
                    <OutOfBandHint />
                  </>
                ) : hk.state === "unknown" ? (
                  <Typography.Text type="secondary">
                    面板连到 {server.address}:{server.port}，只读取主机公钥，不登录。
                  </Typography.Text>
                ) : hk.state === "trusted" ? (
                  <Typography.Text type="secondary">已获取并固定。{matched ? "刚才重新获取，与固定值一致。" : ""}</Typography.Text>
                ) : null}
                {!mismatch ? (
                  <div style={{ marginTop: 8 }}>
                    <Button
                      type={hk.state === "unknown" ? "primary" : "default"}
                      size={hk.state === "unknown" ? "middle" : "small"}
                      loading={act.busy === "discover"}
                      onClick={() => void discover()}
                    >
                      {hk.state === "unknown" ? "获取指纹" : "重新获取"}
                    </Button>
                  </div>
                ) : null}
              </div>
            ),
          },
          {
            title: "确认并固定",
            status: stepTrust,
            description: (
              <div className="step-body">
                {hk.state === "discovered" && hk.seen_fingerprint ? (
                  <Button
                    type="primary"
                    icon={<SafetyCertificateOutlined />}
                    loading={act.busy === "trust"}
                    onClick={() =>
                      trust(
                        hk.seen_fingerprint!,
                        "固定这个主机指纹？",
                        `之后只接受 ${hk.seen_fingerprint}；如果服务器出示别的指纹，面板会拒绝连接。`,
                      )
                    }
                  >
                    核对一致，确认
                  </Button>
                ) : hk.state === "trusted" ? (
                  <Space direction="vertical" size={4}>
                    <FingerprintRows rows={[["已固定", hk.key_type, hk.fingerprint, hk.pinned_at]]} />
                    <Space size={8}>
                      <Typography.Text type="secondary">
                        {hk.source === "mesh_journal" ? "从 Mesh 部署记录迁移而来" : "由你在面板里确认"}
                      </Typography.Text>
                      <Button size="small" type="link" danger onClick={forget} style={{ padding: 0 }}>
                        清除固定
                      </Button>
                    </Space>
                  </Space>
                ) : mismatch ? (
                  <Typography.Text type="danger">见上方：先处理指纹不符。</Typography.Text>
                ) : (
                  <Typography.Text type="secondary">获取指纹后，核对一致再确认。确认时提交的就是上一步看到的那一个值。</Typography.Text>
                )}
              </div>
            ),
          },
          {
            title: "连接测试",
            status: stepTest,
            description: (
              <div className="step-body">
                {lt ? (
                  lt.ok ? (
                    <Descriptions
                      size="small"
                      column={1}
                      items={[
                        { key: "at", label: "时间", children: <TimeText value={lt.at} /> },
                        { key: "os", label: "系统", children: lt.os || "—" },
                        { key: "kernel", label: "内核", children: <Mono>{lt.kernel}</Mono> },
                        { key: "arch", label: "架构", children: lt.arch || "—" },
                        { key: "auth", label: "登录方式", children: lt.auth_method ? authLabel(lt.auth_method) : "—" },
                        { key: "ms", label: "耗时", children: `${lt.duration_ms} ms` },
                      ]}
                    />
                  ) : (
                    <Alert
                      type="error"
                      showIcon
                      message={`测试失败：${(lt.code && TEST_CODE[lt.code]) || lt.code || "未知原因"}`}
                      description={
                        <>
                          <div>{lt.error}</div>
                          <Typography.Text type="secondary">
                            <TimeText value={lt.at} />
                          </Typography.Text>
                        </>
                      }
                    />
                  )
                ) : (
                  <Typography.Text type="secondary">登录并运行一条固定的只读命令（读系统、内核和架构），不做任何修改。</Typography.Text>
                )}
                <div style={{ marginTop: 8 }}>
                  <Button
                    type={stepTest === "process" ? "primary" : "default"}
                    disabled={hk.state !== "trusted" || !hasCred}
                    loading={act.busy === "test"}
                    onClick={() => void test()}
                  >
                    {lt ? "重新测试" : "测试连接"}
                  </Button>
                </div>
              </div>
            ),
          },
        ]}
      />
      <CredentialCreateDrawer
        open={newCred}
        fixedKind={credKindFor(server.auth)}
        onClose={() => setNewCred(false)}
        onCreated={(c) => {
          onCredCreated(c);
          setPick(c.id);
        }}
      />
    </div>
  );
}

function ServerDetail({
  server,
  creds,
  onClose,
  onChanged,
  onEdit,
  onDelete,
  onCredCreated,
}: {
  server: ServerView | undefined;
  creds: SSHCredentialView[];
  onClose: () => void;
  onChanged: (s: ServerView) => void;
  onEdit: () => void;
  onDelete: () => void;
  onCredCreated: (c: SSHCredentialView) => void;
}) {
  const r = server ? serverReadiness(server) : null;
  return (
    <Drawer
      title={
        server ? (
          <Space>
            <span>{server.name}</span>
            {r ? <StatusTag kind={r.kind}>{r.label}</StatusTag> : null}
          </Space>
        ) : (
          "服务器"
        )
      }
      open={!!server}
      onClose={onClose}
      width={680}
      extra={
        server ? (
          <Space>
            <Button onClick={onEdit}>编辑</Button>
            <Button danger onClick={onDelete}>
              删除
            </Button>
          </Space>
        ) : null
      }
    >
      {server ? (
        <>
          <Facts
            items={[
              ["ID", <Mono copy>{server.id}</Mono>],
              ["连接", <Mono copy>{`${server.user}@${server.address}:${server.port}`}</Mono>],
              ["节点", server.node ? <Link to={href("topology", server.node.id)}>{server.node.name || server.node.id}</Link> : <Typography.Text type="secondary">拓扑里还没有节点使用它</Typography.Text>],
              ...(server.tags?.length ? ([["标签", <Space size={4} wrap>{server.tags.map((t) => <Tag key={t}>{t}</Tag>)}</Space>]] as [string, ReactNode][]) : []),
              ...(server.notes ? ([["备注", server.notes]] as [string, ReactNode][]) : []),
            ]}
          />
          <Divider orientation="left" plain>
            接入流程
          </Divider>
          <ServerFlow server={server} creds={creds} onChanged={onChanged} onEdit={onEdit} onCredCreated={onCredCreated} />
          <Divider orientation="left" plain>
            引用
          </Divider>
          <RefList refs={server.in_use_by} empty="没有节点或部署引用这台服务器" />
        </>
      ) : null}
    </Drawer>
  );
}

// -------------------------------------------------------------- the page ---

export default function ServersPage() {
  const { route, navigate } = useRouter();
  const { message } = AntApp.useApp();
  const confirm = useConfirmDanger();
  const servers = useApi(() => api.listServers(), []);
  const creds = useApi(() => api.listCredentials(), []);
  const [form, setForm] = useState<{ open: boolean; server: ServerView | null }>({ open: false, server: null });
  const [refused, setRefused] = useState<ApiError | null>(null);
  const selectedId = route.params[0];
  const list = servers.data?.servers ?? [];
  const selected = list.find((s) => s.id === selectedId);
  // A link to an object this page has not loaded yet (created elsewhere): re-read once.
  const [reread, setReread] = useState<string | null>(null);
  useEffect(() => {
    if (selectedId && servers.data && !selected && reread !== selectedId) {
      setReread(selectedId);
      void servers.reload();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId, servers.data, selected]);
  const credList = creds.data?.credentials ?? [];

  const upsert = (s: ServerView) =>
    servers.setData((d) => (d ? { servers: d.servers.some((x) => x.id === s.id) ? d.servers.map((x) => (x.id === s.id ? s : x)) : [...d.servers, s] } : d));
  const addCred = (c: SSHCredentialView) => creds.setData((d) => (d ? { credentials: [...d.credentials, c] } : d));

  const summary = useMemo(() => {
    const ready = list.filter((s) => s.ready).length;
    return { ready, attention: list.length - ready };
  }, [list]);

  const askDelete = (s: ServerView) =>
    confirm({
      title: `删除服务器「${s.name}」？`,
      consequence:
        s.in_use_by.length > 0
          ? "它仍被节点或部署引用，面板会拒绝删除并列出引用者。"
          : "只删除面板里的记录和已固定的指纹，不会登录或改动这台服务器。",
      okText: "删除",
      onOk: async () => {
        try {
          await api.deleteServer(s.id);
          message.success("已删除");
          if (selectedId === s.id) navigate(href("servers"), { replace: true });
          await servers.reload();
        } catch (e) {
          setRefused(e as ApiError);
          void servers.reload();
        }
      },
    });

  return (
    <Page
      title="服务器"
      description="运行中继、枢纽和出口的远端主机。每台都要选好登录密钥、确认主机指纹并通过连接测试，才能装机或部署。"
      extra={
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setForm({ open: true, server: null })}>
          添加服务器
        </Button>
      }
    >
      {creds.error ? <ApiErrorAlert error={creds.error} onRetry={() => void creds.reload()} /> : null}
      <DataView
        state={servers}
        isEmpty={(d) => d.servers.length === 0}
        empty={
          <EmptyState
            title="还没有服务器"
            description={
              credList.length === 0 ? (
                <span>
                  先在 <Link to={href("keys")}>密钥</Link> 页准备登录方式，再添加服务器。
                </span>
              ) : (
                "添加一台服务器，然后获取并确认它的主机指纹。"
              )
            }
            action={
              <Button type="primary" onClick={() => setForm({ open: true, server: null })}>
                添加服务器
              </Button>
            }
          />
        }
      >
        {(d) => (
          <>
            <Space style={{ marginBottom: 12 }} wrap>
              <StatusTag kind="ok">{`就绪 ${summary.ready}`}</StatusTag>
              {summary.attention > 0 ? <StatusTag kind="attention">{`需要处理 ${summary.attention}`}</StatusTag> : null}
            </Space>
            <Table
              rowKey="id"
              dataSource={d.servers}
              pagination={false}
              scroll={{ x: 1100 }}
              onRow={(s) => ({ "data-testid": `server-row-${s.id}` }) as HTMLAttributes<HTMLElement>}
              columns={[
                { title: "名称", width: 160, render: (_, s) => <Link to={href("servers", s.id)}>{s.name}</Link> },
                { title: "地址", render: (_, s) => <Mono>{`${s.user}@${s.address}:${s.port}`}</Mono> },
                {
                  title: "登录",
                  render: (_, s) =>
                    s.credential ? (
                      <Space size={4}>
                        <span>{authLabel(s.auth)}</span>
                        <Link to={href("keys", s.credential.id)}>{s.credential.name}</Link>
                      </Space>
                    ) : (
                      <StatusTag kind="attention">{`${authLabel(s.auth)} · 未选择`}</StatusTag>
                    ),
                },
                {
                  title: "主机指纹",
                  render: (_, s) => {
                    const st = HOST_KEY_STATUS[s.host_key.state] ?? HOST_KEY_STATUS.unknown;
                    return <StatusTag kind={st.kind} title={s.host_key.fingerprint || s.host_key.seen_fingerprint}>{st.label}</StatusTag>;
                  },
                },
                {
                  title: "最近测试",
                  render: (_, s) =>
                    s.last_test ? (
                      <Space size={4}>
                        <StatusTag kind={s.last_test.ok ? "ok" : "failed"}>{s.last_test.ok ? "通过" : "失败"}</StatusTag>
                        <TimeText value={s.last_test.at} />
                      </Space>
                    ) : (
                      <Typography.Text type="secondary">未测试</Typography.Text>
                    ),
                },
                {
                  title: "节点",
                  render: (_, s) =>
                    s.node ? <Link to={href("topology", s.node.id)}>{s.node.name || s.node.id}</Link> : <Typography.Text type="secondary">—</Typography.Text>,
                },
                {
                  title: "状态",
                  render: (_, s) => {
                    const r = serverReadiness(s);
                    return (
                      <StatusTag kind={r.kind} title={s.missing.length ? `还需：${s.missing.map((m) => MISSING_LABEL[m] ?? m).join("、")}` : undefined}>
                        {r.label}
                      </StatusTag>
                    );
                  },
                },
                {
                  title: "",
                  className: "table-actions",
                  render: (_, s) => (
                    <Space size={0}>
                      <Button type="link" size="small" onClick={() => navigate(href("servers", s.id))}>
                        {s.ready ? "详情" : "继续"}
                      </Button>
                      <Button type="link" size="small" onClick={() => setForm({ open: true, server: s })}>
                        编辑
                      </Button>
                      <Button type="link" size="small" danger onClick={() => askDelete(s)}>
                        删除
                      </Button>
                    </Space>
                  ),
                },
              ]}
            />
          </>
        )}
      </DataView>
      {selectedId && servers.data && !selected && !servers.loading && reread === selectedId ? (
        <Alert type="warning" showIcon style={{ marginTop: 16 }} message={`没有 ID 为 ${selectedId} 的服务器，它可能已被删除。`} />
      ) : null}

      <ServerDetail
        server={selected}
        creds={credList}
        onClose={() => navigate(href("servers"))}
        onChanged={upsert}
        onEdit={() => selected && setForm({ open: true, server: selected })}
        onDelete={() => selected && askDelete(selected)}
        onCredCreated={addCred}
      />
      <ServerFormDrawer
        key={form.server?.id ?? "new"}
        open={form.open}
        server={form.server}
        creds={credList}
        onClose={() => setForm({ open: false, server: null })}
        onCredCreated={addCred}
        onSaved={(s, created) => {
          upsert(s);
          setForm({ open: false, server: null });
          message.success(created ? "已添加，接着获取主机指纹" : "已保存");
          if (created) navigate(href("servers", s.id));
        }}
      />
      <RefusedDialog error={refused} title="不能删除这台服务器" onClose={() => setRefused(null)} />
    </Page>
  );
}
