// 远程接入: phones and laptops reach home through a WireGuard entrance on
// the gateway. Settings, what the user has to do on the router (the panel
// never touches it), devices with their live state, and the one-time
// configuration: shown once in a dialog (text, copy, download, a QR code
// drawn in the browser), held only in component state, gone on close.

import {
  DeleteOutlined,
  DownloadOutlined,
  EditOutlined,
  MobileOutlined,
  PlusOutlined,
  ReloadOutlined,
  SyncOutlined,
  WarningFilled,
} from "@ant-design/icons";
import {
  Alert,
  App as AntApp,
  Button,
  Checkbox,
  Drawer,
  Form,
  Input,
  InputNumber,
  Modal,
  QRCode,
  Space,
  Switch,
  Tag,
  Tooltip,
  Typography,
} from "antd";
import { useEffect, useMemo, useState } from "react";
import * as api from "./api";
import type { ApiError } from "./api";
import { href, useRouter, useStatus } from "./state";
import type { RemoteAccessView, RemoteDeviceConfigResult, RemoteDevicePatch, RemoteDeviceView, RemoteFastApply, RemoteMode, RemoteRuntimeView, RemoteSettingsPatch, RouterForward } from "./types";
import {
  RowActions,
  CommandBlock,
  DataTable,
  EllipsisText,
  type DataColumn,
  ApiErrorAlert,
  ApplyRequiredNotice,
  CopyButton,
  DataView,
  EmptyState,
  Facts,
  IssueList,
  Mono,
  Page,
  RefusedDialog,
  Section,
  StatusTag,
  TimeText,
  bytes,
  downloadText,
  showFieldError,
  useAction,
  useApi,
  useConfirmDanger,
  type StatusKind,
  Note,
} from "./ui";

const MODE_TITLE: Record<RemoteMode, string> = { full: "全隧道", home: "仅家网" };
const MODE_SHORT: Record<RemoteMode, string> = {
  full: "手机全部流量和 DNS 都经家里的网关，按家里的规则分流。",
  home: "只有访问家里局域网的流量走隧道；上网仍走手机当前的网络。",
};

const RUNTIME_REASON: Record<string, string> = {
  disabled: "远程接入没有启用",
  agent_unavailable: "宿主执行通道不可用，读不到运行状态",
  interface_absent: "网关上还没有远程接入接口（还没安装，或已停用）",
  error: "读取运行状态出错",
};

/** QR codes above this size get hard to scan from a screen at level M. */
const QR_MAX_M = 900;
const QR_MAX_L = 1800;

function deviceStatus(d: RemoteDeviceView, rt: RemoteRuntimeView | undefined): { kind: StatusKind; label: string; tip?: string } {
  switch (d.runtime_state) {
    case "ok":
      if (d.runtime?.online) return { kind: "ok", label: "在线", tip: "3 分钟内有过握手" };
      return { kind: "neutral", label: d.runtime?.last_handshake_at ? "离线" : "从未连接", tip: "3 分钟内没有握手" };
    case "disabled":
      return { kind: "neutral", label: "已停用" };
    case "not_installed":
      return { kind: "pending", label: "尚未安装", tip: "设备已加入配置，但网关上还没有它：在「部署」页安装后才能连接。" };
    case "unavailable":
      return { kind: "unverified", label: "读不到状态", tip: rt?.reason || RUNTIME_REASON[rt?.state ?? ""] || "运行状态不可用" };
    default:
      return { kind: "neutral", label: "未读取" };
  }
}

// ------------------------------------------------------- one-time dialog ---

/**
 * The one-time configuration. `result` lives only in the parent's state and
 * is dropped by onClose; nothing here writes it anywhere else.
 */
export function ConfigOnceDialog({ result, title, onClose }: { result: RemoteDeviceConfigResult | null; title: string; onClose: () => void }) {
  const [ack, setAck] = useState(false);
  const [big, setBig] = useState(false);
  useEffect(() => {
    setAck(false);
    setBig(false);
  }, [result]);
  const text = result?.config.text ?? "";
  const size = new TextEncoder().encode(text).length;
  const level: "M" | "L" | null = size <= QR_MAX_M ? "M" : size <= QR_MAX_L ? "L" : null;

  return (
    <Modal
      open={!!result}
      title={title}
      width={820}
      closable={false}
      maskClosable={false}
      keyboard={false}
      destroyOnHidden
      footer={
        <Space wrap style={{ justifyContent: "space-between", width: "100%" }}>
          <Checkbox checked={ack} onChange={(e) => setAck(e.target.checked)} data-testid="config-ack">
            我已导入设备或保存好配置，知道关闭后无法再次显示
          </Checkbox>
          <Button type="primary" disabled={!ack} onClick={onClose}>
            关闭
          </Button>
        </Space>
      }
    >
      {result ? (
        <div data-testid="config-once">
          <Alert
            type="warning"
            showIcon
            icon={<WarningFilled />}
            style={{ marginBottom: 16 }}
            message="这份配置只显示这一次"
            description="里面有设备的私钥。网关不保存这把私钥，关闭后谁都无法再显示它；丢了只能在设备列表里「重新生成」，旧配置随下一次安装失效。不要截图发到聊天软件里。"
          />
          <div className="config-once">
            <div className="config-qr">
              {level ? (
                <>
                  <QRCode value={text} type="svg" errorLevel={level} size={big ? 360 : 248} style={{ maxWidth: "100%", height: "auto" }} bordered={false} color="#000000" bgColor="#ffffff" />
                  <Note inline>在手机 WireGuard App 里选「扫描二维码」。二维码在浏览器里生成，没有发到任何地方。</Note>
                  <Button size="small" type="link" onClick={() => setBig((b) => !b)}>
                    {big ? "缩小" : "放大二维码"}
                  </Button>
                </>
              ) : (
                <Alert type="info" showIcon message="配置太长，不适合做成二维码；请用下载的文件或复制文本导入。" />
              )}
            </div>
            <div className="config-text">
              <Space wrap style={{ marginBottom: 8 }}>
                <CopyButton text={text} label="复制配置" />
                <Button size="small" icon={<DownloadOutlined />} onClick={() => downloadText(result.config.filename || "meridian.conf", text)}>
                  下载 {result.config.filename}
                </Button>
                <span className="muted">{MODE_TITLE[result.config.mode]}</span>
              </Space>
              <pre className="config-pre" data-testid="config-text" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", overflowX: "hidden" }}>
                {text}
              </pre>
              <Note>
                {result.config.explanation}
              </Note>
            </div>
          </div>
          {result.fast_apply?.status === "applied" ? (
            <Alert type="success" showIcon style={{ marginTop: 16 }} message="已生效" data-testid="fast-applied" />
          ) : (
            <Alert
              type={result.fast_apply?.status === "failed" ? "warning" : "info"}
              showIcon
              style={{ marginTop: 16 }}
              message={result.fast_apply?.status === "failed" ? `未生效：${result.fast_apply.reason ?? ""}` : "设备要在安装之后才能连上"}
              description={
                <span>
                  到「部署」页安装后生效；路由器 UDP {result.router_forward.external_port || "端口"} 转发也要先做好。
                </span>
              }
            />
          )}
        </div>
      ) : null}
    </Modal>
  );
}

// -------------------------------------------------------- router forward ---

function RouterForwardBlock({ f, enabled }: { f: RouterForward; enabled: boolean }) {
  const ready = f.external_port > 0;
  return (
    <Section
      title="路由器上需要做的事"
      extra={
        <StatusTag kind="unverified" title="面板不连接路由器，也无法从外网验证转发是否生效；用手机关掉 Wi-Fi、在蜂窝网络下连一次才算验证。">
          面板无法验证
        </StatusTag>
      }
    >
      <Note>
        面板不会修改你的路由器。在家里的主路由（例如 RouterOS）上添加一条端口转发（dst-nat），否则外面的设备连不进来。
      </Note>
      {ready ? (
        <div className="forward-grid" data-testid="router-forward">
          <div className="forward-cell">
            <span className="muted">协议</span>
            <Mono copy>{f.protocol.toUpperCase()}</Mono>
          </div>
          <div className="forward-cell">
            <span className="muted">外部端口</span>
            <Mono copy>{String(f.external_port)}</Mono>
          </div>
          <div className="forward-cell">
            <span className="muted">内部地址</span>
            <Mono copy>{f.internal_address}</Mono>
          </div>
          <div className="forward-cell">
            <span className="muted">内部端口</span>
            <Mono copy>{String(f.internal_port)}</Mono>
          </div>
        </div>
      ) : null}
      <Note>{f.description}</Note>
      {ready ? (
        <details className="ros-hint">
          <summary>RouterOS 示例命令</summary>
          <CommandBlock label="RouterOS 端口转发命令，可左右滚动">{`/ip firewall nat add chain=dstnat protocol=udp dst-port=${f.external_port} in-interface-list=WAN action=dst-nat to-addresses=${f.internal_address} to-ports=${f.internal_port} comment="meridian remote access"`}</CommandBlock>
          <Note inline>按你的路由器调整入接口；只是示例，面板不会执行它。</Note>
        </details>
      ) : null}
      {f.ipv6_note ? (
        <Note>
          IPv6：{f.ipv6_note}
        </Note>
      ) : null}
      {!enabled ? <Typography.Text type="secondary">远程接入还没有启用。</Typography.Text> : null}
    </Section>
  );
}

// -------------------------------------------------------------- settings ---

interface SettingsValues {
  endpoint: string;
  listen_port?: number;
  ipv4_prefix: string;
  ipv6_prefix: string;
  mtu?: number;
  keepalive?: number;
}

function SettingsSection({ view, onSaved }: { view: RemoteAccessView; onSaved: (v: RemoteAccessView, what: string) => void }) {
  const [form] = Form.useForm<SettingsValues>();
  const act = useAction();
  const [refused, setRefused] = useState<ApiError | null>(null);
  const [handled, setHandled] = useState(false);
  const s = view.settings;
  const initial: SettingsValues = {
    endpoint: s.endpoint,
    listen_port: s.listen_port || undefined,
    ipv4_prefix: s.ipv4_prefix,
    ipv6_prefix: s.ipv6_prefix,
    mtu: s.mtu,
    keepalive: s.keepalive,
  };
  // Refill the form only when these fields change on the server: switching allow_peers keeps what is typed.
  useEffect(() => form.setFieldsValue(initial), [JSON.stringify(initial)]); // eslint-disable-line react-hooks/exhaustive-deps
  const fields = ["endpoint", "listen_port", "ipv4_prefix", "ipv6_prefix", "mtu", "keepalive"];
  const onError = (e: ApiError) => {
    if (e.code === "in_use") {
      setRefused(e);
      setHandled(true);
      return;
    }
    setHandled(showFieldError(form, e, fields));
  };

  const save = async () => {
    let v: SettingsValues;
    try {
      v = await form.validateFields();
    } catch {
      return;
    }
    setHandled(false);
    const body: RemoteSettingsPatch = {};
    if (v.endpoint.trim() !== s.endpoint) body.endpoint = v.endpoint.trim();
    if ((v.listen_port ?? 0) !== s.listen_port) body.listen_port = v.listen_port ?? 0;
    if (v.ipv4_prefix.trim() !== s.ipv4_prefix) body.ipv4_prefix = v.ipv4_prefix.trim();
    if (v.ipv6_prefix.trim() !== s.ipv6_prefix) body.ipv6_prefix = v.ipv6_prefix.trim();
    if (v.mtu !== s.mtu) body.mtu = v.mtu;
    if (v.keepalive !== s.keepalive) body.keepalive = v.keepalive;
    if (Object.keys(body).length === 0) return;
    const r = await act.run(() => api.putRemoteAccess(body), "save", onError);
    if (r) onSaved(r, "远程接入设置已保存");
  };
  const toggle = (enabled: boolean) =>
    act.run(
      async () => {
        const r = await api.putRemoteAccess({ enabled });
        onSaved(r, enabled ? "远程接入已启用" : "远程接入已停用");
      },
      "enable",
      onError,
    );

  const setPeers = (allow_peers: boolean) =>
    act.run(
      async () => {
        const r = await api.putRemoteAccess({ allow_peers });
        onSaved(r, allow_peers ? "已允许设备互相访问，安装到网关后生效" : "已禁止设备互相访问，安装到网关后生效");
      },
      "peers",
      onError,
    );

  const outdated = view.devices.filter((d) => d.config_outdated).length;
  return (
    <Section
      title="入口设置"
      extra={
        <Space>
          <Typography.Text>{s.enabled ? "已启用" : "未启用"}</Typography.Text>
          <Switch checked={s.enabled} loading={act.busy === "enable"} onChange={(v) => void toggle(v)} aria-label="启用远程接入" />
        </Space>
      }
    >
      {act.error && !handled ? <ApiErrorAlert error={act.error} onClose={act.clear} /> : null}
      <Form form={form} layout="vertical" initialValues={initial} requiredMark="optional" autoComplete="off" className="remote-settings">
        <div className="form-grid">
          <Form.Item
            name="endpoint"
            label="Endpoint（外面的设备连哪里）"
            extra={<Note>{"你家的公网地址或指向它的域名（DDNS）。面板不猜测公网地址，必须由你填写。"}</Note>}
            rules={[{ required: true, message: "填写域名或公网地址" }]}
          >
            <Input className="mono" placeholder="例如 home.example.net" />
          </Form.Item>
          <Form.Item name="listen_port" label="监听端口（UDP）" extra={<Note>{"路由器转发的外部端口要和它一致。"}</Note>} rules={[{ required: true, message: "填写端口" }]}>
            <InputNumber min={1} max={65535} style={{ width: "100%" }} placeholder="51888" />
          </Form.Item>
          <Form.Item name="ipv4_prefix" label="设备 IPv4 地址池" extra={<Note>{`默认 ${s.defaults.ipv4_prefix}；有设备时不能修改。`}</Note>}>
            <Input className="mono" disabled={view.devices.length > 0} />
          </Form.Item>
          <Form.Item name="ipv6_prefix" label="设备 IPv6 地址池" extra={<Note>{`默认 ${s.defaults.ipv6_prefix}；有设备时不能修改。`}</Note>}>
            <Input className="mono" disabled={view.devices.length > 0} />
          </Form.Item>
          <Form.Item name="mtu" label="MTU" extra={<Note>{`默认 ${s.defaults.mtu}。`}</Note>}>
            <InputNumber min={1280} max={1500} style={{ width: "100%" }} />
          </Form.Item>
          <Form.Item name="keepalive" label="Keepalive（秒）" extra={<Note>{`默认 ${s.defaults.keepalive}；手机在 NAT 后需要。`}</Note>}>
            <InputNumber min={0} max={600} style={{ width: "100%" }} />
          </Form.Item>
        </div>
        <div className="remote-peers" data-testid="remote-allow-peers">
          <Space wrap align="center">
            <Switch checked={s.allow_peers} loading={act.busy === "peers"} onChange={(v) => void setPeers(v)} aria-label="允许接入设备互相访问" />
            <Typography.Text>允许接入设备互相访问</Typography.Text>
            <Note>
              {`打开后，连回家的设备之间可以互相访问，比如在外面用笔记本访问另一台也连着回家的电脑。默认关闭：万一某台设备的配置泄露，别人只能连到家里，碰不到你其他在外面的设备。改动要安装到网关后才生效。「只连家里」模式的设备要重新生成配置才能用上，需要的设备会在列表里标出来。`}
            </Note>
          </Space>
        </div>
        <Space wrap>
          <Button type="primary" loading={act.busy === "save"} onClick={() => void save()}>
            保存设置
          </Button>
          {outdated > 0 ? <Typography.Text type="warning">改动会让已经下发的配置过期（{outdated} 台已过期），需要给这些设备重新生成配置。</Typography.Text> : (
            <Note inline>改 Endpoint、端口、MTU 或 Keepalive 后，已经下发的设备配置会过期，需要重新生成。</Note>
          )}
        </Space>
      </Form>
      {s.public_key ? (
        <div style={{ marginTop: 16 }}>
          <Facts
            items={[
              ["网关公钥", <Mono key="pk" copy>{s.public_key}</Mono>],
              ["网关隧道地址", <span key="a" className="mono">{[s.gateway_ipv4, s.gateway_ipv6].filter(Boolean).join("  ") || "—"}</span>],
              ["设备", `${view.devices.length} / ${s.max_devices}`],
            ]}
          />
        </div>
      ) : null}
      <RefusedDialog error={refused} title="地址池里还有设备，未修改" onClose={() => setRefused(null)} />
    </Section>
  );
}

// ----------------------------------------------------------- device form ---

interface DeviceValues {
  name: string;
  notes?: string;
  mode: RemoteMode;
  preshared_key: boolean;
}

/**
 * What each mode does NOT do, kept visible on its card (safety-relevant);
 * the full explanation from the API is behind 「了解更多」.
 */
const MODE_SAFETY: Record<RemoteMode, string | null> = {
  full: null,
  home: "上网不经过 Meridian，不受防泄露保护。",
};

function ModeChoice({ value, onChange, modes }: { value?: RemoteMode; onChange?: (m: RemoteMode) => void; modes: Record<string, string> }) {
  return (
    <div className="option-cards" role="radiogroup" aria-label="路由模式">
      {(["full", "home"] as RemoteMode[]).map((m) => (
        <div key={m} className={`option-card option-card-box${value === m ? " selected" : ""}`} data-testid={`mode-card-${m}`}>
          <button type="button" role="radio" aria-checked={value === m} className="option-card-pick" onClick={() => onChange?.(m)}>
            <span className="option-card-title">
              {MODE_TITLE[m]}
              {m === "full" ? <span className="muted">推荐</span> : null}
            </span>
            <span className="option-card-desc">{MODE_SHORT[m]}</span>
          </button>
          {MODE_SAFETY[m] ? (
            <div className="option-card-safety" data-testid={`mode-safety-${m}`}>
              {MODE_SAFETY[m]}
            </div>
          ) : null}
          {modes[m] ? (
            <Note>{null}{" "}
              {modes[m]}
            </Note>
          ) : null}
        </div>
      ))}
    </div>
  );
}

function DeviceDrawer({
  open,
  device,
  view,
  onClose,
  onCreated,
  onSaved,
}: {
  open: boolean;
  device: RemoteDeviceView | null;
  view: RemoteAccessView;
  onClose: () => void;
  onCreated: (r: RemoteDeviceConfigResult) => void;
  onSaved: (d: RemoteDeviceView, fa?: RemoteFastApply) => void;
}) {
  const [form] = Form.useForm<DeviceValues>();
  const act = useAction();
  const [handled, setHandled] = useState(false);
  const mode = Form.useWatch("mode", form);
  const initial: DeviceValues = device
    ? { name: device.name, notes: device.notes, mode: device.mode, preshared_key: device.preshared_key }
    : { name: "", notes: "", mode: view.settings.defaults.mode ?? "full", preshared_key: true };

  const save = async () => {
    let v: DeviceValues;
    try {
      v = await form.validateFields();
    } catch {
      return;
    }
    setHandled(false);
    const onError = (e: ApiError) => setHandled(showFieldError(form, e, ["name", "notes", "mode"]));
    if (!device) {
      const r = await act.run(
        () => api.createRemoteDevice({ name: v.name.trim(), notes: v.notes ?? "", mode: v.mode, preshared_key: v.preshared_key, enabled: true }),
        "save",
        onError,
      );
      if (r) onCreated(r);
      return;
    }
    const patch: RemoteDevicePatch = {};
    if (v.name.trim() !== device.name) patch.name = v.name.trim();
    if ((v.notes ?? "") !== device.notes) patch.notes = v.notes ?? "";
    if (v.mode !== device.mode) patch.mode = v.mode;
    if (Object.keys(patch).length === 0) {
      onClose();
      return;
    }
    const r = await act.run(() => api.updateRemoteDevice(device.id, patch), "save", onError);
    if (r) onSaved(r.device, r.fast_apply);
  };

  return (
    <Drawer
      title={device ? `编辑设备「${device.name}」` : "添加设备"}
      open={open}
      onClose={onClose}
      width={600}
      destroyOnHidden
      footer={
        <Space>
          <Button onClick={onClose}>取消</Button>
          <Button type="primary" loading={act.busy === "save"} onClick={() => void save()}>
            {device ? "保存" : "添加并生成配置"}
          </Button>
        </Space>
      }
    >
      {act.error && !handled ? <ApiErrorAlert error={act.error} /> : null}
      {!device ? (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          message="添加后会立即生成这台设备的配置（含私钥），只显示一次。"
          description={<Note>{"准备好手机上的 WireGuard App，或者准备好保存文件的位置。"}</Note>}
        />
      ) : null}
      <Form form={form} layout="vertical" initialValues={initial} requiredMark="optional" autoComplete="off">
        <Form.Item name="name" label="设备名称" rules={[{ required: true, message: "填写名称" }]}>
          <Input placeholder="例如 我的手机" />
        </Form.Item>
        <Form.Item name="mode" label="路由模式">
          <ModeChoice modes={view.settings.modes} />
        </Form.Item>
        {device && mode && mode !== device.mode ? (
          <Alert type="warning" showIcon style={{ marginBottom: 16 }} message="改模式会改变设备配置里的 AllowedIPs 和 DNS：保存后要给这台设备重新生成并重新导入配置。" />
        ) : null}
        {!device ? (
          <Form.Item name="preshared_key" valuePropName="checked" extra={<Note>{"在公钥之外再加一层对称密钥（WireGuard PresharedKey），建议保留。"}</Note>}>
            <Checkbox>使用预共享密钥</Checkbox>
          </Form.Item>
        ) : null}
        <Form.Item name="notes" label="备注">
          <Input.TextArea rows={2} />
        </Form.Item>
      </Form>
    </Drawer>
  );
}

// ------------------------------------------------------------------ page ---

export default function RemotePage() {
  const view = useApi(() => api.getRemoteAccess(), []);
  const { markApplyRequired, install, refresh } = useStatus();
  const { route, navigate } = useRouter();
  const { message } = AntApp.useApp();
  const confirm = useConfirmDanger();
  const act = useAction();
  const [editing, setEditing] = useState<RemoteDeviceView | "new" | null>(null);
  const [once, setOnce] = useState<{ result: RemoteDeviceConfigResult; title: string } | null>(null);
  const [changed, setChanged] = useState(false);
  const focus = route.params[0];

  useEffect(() => {
    if (!focus || !view.data) return;
    const d = view.data.devices.find((x) => x.id === focus);
    if (d) setEditing(d);
  }, [focus, view.data === undefined]); // eslint-disable-line react-hooks/exhaustive-deps

  // fa: the device change's fast path (absent for settings changes).
  const changedDoc = (what: string, fa?: RemoteFastApply) => {
    if (fa?.status === "applied" || fa?.status === "none") {
      refresh();
      message.success(fa.status === "applied" ? `${what}，已生效` : what);
      return;
    }
    markApplyRequired();
    setChanged(true);
    if (fa?.status === "failed") message.error(`${what}，未生效：${fa.reason ?? ""}`);
    else message.success(`${what}；安装后在网关生效${fa?.reason ? `（${fa.reason}）` : ""}`);
  };
  const putDevice = (d: RemoteDeviceView) =>
    view.setData((old) => (old ? { ...old, devices: old.devices.some((x) => x.id === d.id) ? old.devices.map((x) => (x.id === d.id ? { ...d, runtime: x.runtime, runtime_state: d.runtime_state === "not_read" ? x.runtime_state : d.runtime_state } : x)) : [...old.devices, d] } : old));

  const regenerate = (d: RemoteDeviceView) =>
    confirm({
      title: `为「${d.name}」重新生成配置？`,
      consequence: `生成新的私钥${d.preshared_key ? "和预共享密钥" : ""}，设备地址不变。设备上的旧配置在下一次安装后失效，要导入新配置。新配置只显示一次。`,
      okText: "重新生成",
      danger: false,
      onOk: () =>
        act.run(async () => {
          const r = await api.regenerateRemoteDevice(d.id, { preshared_key: d.preshared_key });
          putDevice(r.device);
          changedDoc(`已为 ${d.name} 生成新配置`, r.fast_apply);
          setOnce({ result: r, title: `「${r.device.name}」的新配置` });
        }, `regen:${d.id}`),
    });

  const setEnabled = (d: RemoteDeviceView, enabled: boolean) => {
    const run = () =>
      act.run(async () => {
        const r = await api.updateRemoteDevice(d.id, { enabled });
        putDevice(r.device);
        changedDoc(enabled ? `${d.name} 已启用` : `${d.name} 已停用`, r.fast_apply);
      }, `enable:${d.id}`);
    if (enabled) return void run();
    confirm({
      title: `停用「${d.name}」？`,
      consequence: "安装后网关拒绝这台设备连接；它的配置和地址保留，重新启用后不用重新导入。",
      okText: "停用",
      onOk: run,
    });
  };

  const remove = (d: RemoteDeviceView) =>
    confirm({
      title: `删除「${d.name}」？`,
      consequence: "设备从配置里移除，它的地址可以给新设备使用；安装后这台设备再也连不上，设备上的配置作废，无法恢复。",
      okText: "删除",
      onOk: () =>
        act.run(async () => {
          const r = await api.deleteRemoteDevice(d.id);
          view.setData((old) => (old ? { ...old, devices: old.devices.filter((x) => x.id !== d.id) } : old));
          changedDoc(`${d.name} 已删除`, r.fast_apply);
        }, `del:${d.id}`),
    });

  const v = view.data;
  const rt = v?.runtime;
  const pendingInstall = install.kind === "changed" || install.kind === "not_installed";

  const columns = useMemo(
    (): DataColumn<RemoteDeviceView>[] => [
      {
        title: "设备",
        kind: "flex",
        width: 180,
        render: (_: unknown, d: RemoteDeviceView) => (
          <div>
            <Space size={4} wrap>
              <MobileOutlined />
              <Tooltip title={<>密钥生成于 <TimeText value={d.key_created_at} />{d.preshared_key ? "，带预共享密钥" : ""}</>}>
                <Typography.Text strong>{d.name}</Typography.Text>
              </Tooltip>
              {d.config_outdated ? (
                <Tooltip title="网关这边和配置有关的设置（Endpoint、端口、密钥、地址池、模式、MTU、Keepalive）改过了，设备上的配置可能连不上。重新生成并重新导入。">
                  <StatusTag kind="attention">
                    配置已过期
                  </StatusTag>
                </Tooltip>
              ) : null}
            </Space>
            {d.notes ? <EllipsisText className="muted cell-small" text={d.notes} /> : null}
          </div>
        ),
      },
      {
        title: "模式",
        kind: "fixed",
        width: 96,
        render: (_: unknown, d: RemoteDeviceView) => (
          <Tooltip title={MODE_SHORT[d.mode]}>
            <Tag color={d.mode === "full" ? "blue" : "default"}>{MODE_TITLE[d.mode]}</Tag>
          </Tooltip>
        ),
      },
      {
        title: "地址",
        kind: "flex",
        width: 150,
        render: (_: unknown, d: RemoteDeviceView) => (
          <div className="mono-small cell-stack">
            <EllipsisText text={d.ipv4} mono />
            {d.ipv6 ? <EllipsisText className="muted" text={d.ipv6} mono /> : null}
          </div>
        ),
      },
      {
        title: "状态",
        kind: "flex",
        width: 200,
        render: (_: unknown, d: RemoteDeviceView) => {
          const s = deviceStatus(d, rt);
          return (
            <div data-testid={`device-status-${d.id}`}>
              <StatusTag kind={s.kind} title={s.tip}>
                {s.label}
              </StatusTag>
              {d.runtime ? (
                <div className="muted" style={{ fontSize: 12, marginTop: 2 }}>
                  握手 <TimeText value={d.runtime.last_handshake_at} empty="从未" /> · ↓{bytes(d.runtime.rx_bytes)} ↑{bytes(d.runtime.tx_bytes)}
                </div>
              ) : null}
            </div>
          );
        },
      },
      {
        title: "启用",
        kind: "fixed",
        width: 60,
        render: (_: unknown, d: RemoteDeviceView) => (
          <Switch size="small" checked={d.enabled} loading={act.busy === `enable:${d.id}`} onChange={(on) => setEnabled(d, on)} aria-label={`启用 ${d.name}`} />
        ),
      },
      {
        title: "操作",
        kind: "actions",
        width: 120,
        render: (_: unknown, d: RemoteDeviceView) => (
          <RowActions
            label={d.name}
            more={[
              { key: "edit", icon: <EditOutlined />, label: "编辑", onClick: () => setEditing(d) },
              { key: "delete", icon: <DeleteOutlined />, label: "删除", danger: true, onClick: () => remove(d) },
            ]}
          >
            <Button type="link" size="small" icon={<SyncOutlined />} loading={act.busy === `regen:${d.id}`} onClick={() => regenerate(d)}>
              重新生成
            </Button>
          </RowActions>
        ),
      },
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [rt, act.busy],
  );

  return (
    <Page
      title="远程接入"

      extra={
        <Button
          type="primary"
          icon={<PlusOutlined />}
          disabled={!v || !v.settings.endpoint || !v.settings.listen_port}
          onClick={() => setEditing("new")}
        >
          添加设备
        </Button>
      }
    >
      {changed || (pendingInstall && v && v.devices.length > 0) ? <ApplyRequiredNotice what={changed ? "远程接入已修改" : "有远程接入改动或其他改动"} /> : null}
      <ApiErrorAlert error={act.error} onClose={act.clear} />
      <DataView state={view} rows={8}>
        {(v) => (
          <>
            <div className="page-notes" data-testid="remote-independent">
              <Note>远程接入独立于拓扑和部署引导，只在这一页改；安装到网关后生效。</Note>
            </div>
            <SettingsSection
              view={v}
              onSaved={(r, what) => {
                view.setData((old) => (old ? { ...r, runtime: old.runtime } : r));
                changedDoc(what);
              }}
            />
            <RouterForwardBlock f={v.router_forward} enabled={v.settings.enabled} />
            <IssueList issues={v.issues ?? []} />
            <Section
              title={`设备（${v.devices.length}）`}
              extra={
                <Space>
                  {rt ? (
                    rt.available ? (
                      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                        运行状态读于 <TimeText value={rt.read_at} />
                      </Typography.Text>
                    ) : (
                      <StatusTag kind={rt.state === "disabled" ? "neutral" : "unverified"} title={rt.reason}>
                        {RUNTIME_REASON[rt.state] ?? "读不到运行状态"}
                      </StatusTag>
                    )
                  ) : null}
                  <Button size="small" icon={<ReloadOutlined />} onClick={() => void view.reload()} loading={view.loading}>
                    刷新
                  </Button>
                </Space>
              }
            >
              {!v.settings.endpoint || !v.settings.listen_port ? (
                <Alert type="warning" showIcon style={{ marginBottom: 12 }} message="先在上面填写 Endpoint 和监听端口，才能添加设备。" />
              ) : null}
              {v.devices.length === 0 ? (
                <EmptyState
                  title="还没有设备"
                  description="添加一台设备，扫描二维码或导入文件就能连回家。"
                  action={
                    <Button type="primary" icon={<PlusOutlined />} disabled={!v.settings.endpoint || !v.settings.listen_port} onClick={() => setEditing("new")}>
                      添加设备
                    </Button>
                  }
                />
              ) : (
                <DataTable<RemoteDeviceView>
                  rowKey="id"
                  dataSource={v.devices}
                  pageSize={50}
                  columns={columns}
                  onRow={(d) => ({ "data-testid": `device-row-${d.id}` }) as React.HTMLAttributes<HTMLElement>}
                />
              )}
            </Section>
            <DeviceDrawer
              open={editing !== null}
              device={editing === "new" ? null : editing}
              view={v}
              onClose={() => {
                setEditing(null);
                if (focus) navigate(href("remote"), { replace: true });
              }}
              onCreated={(r) => {
                setEditing(null);
                putDevice(r.device);
                changedDoc(`设备 ${r.device.name} 已添加`, r.fast_apply);
                setOnce({ result: r, title: `「${r.device.name}」的配置` });
              }}
              onSaved={(d, fa) => {
                setEditing(null);
                putDevice(d);
                changedDoc(`${d.name} 已保存`, fa);
              }}
            />
          </>
        )}
      </DataView>
      <ConfigOnceDialog result={once?.result ?? null} title={once?.title ?? ""} onClose={() => setOnce(null)} />
    </Page>
  );
}
