// First-run setup wizard (#/setup): gateway → template → servers →
// topology → preflight → install. Progress lives on the panel
// (GET/PUT /api/setup/wizard), never in the browser; SSH secrets go to the
// credential store only. The wizard never installs: its last step opens the
// deployment guide, which has its own preflight and confirmations.
// Explanations live in the usage guide (GUIDE_TEXT.setup).

import { Alert, Button, Form, Input, InputNumber, Modal, Radio, Result, Select, Skeleton, Space, Steps, Typography } from "antd";
import { useCallback, useEffect, useMemo, useState } from "react";
import * as api from "./api";
import type { ApiError } from "./api";
import type { PreflightRecord, ServerView } from "./types";
import { ApiErrorAlert, Mono, StatusTag } from "./ui_base";
import { PreflightReport, normalizePreflight, preflightBlockedReason } from "./Preflight";
import { href, useRouter } from "./state";
import { wizardEvents } from "./wizard_events";

const STEPS: { key: api.WizardStep; title: string }[] = [
  { key: "gateway", title: "添加网关" },
  { key: "template", title: "选模板" },
  { key: "servers", title: "添加服务器" },
  { key: "topology", title: "生成拓扑" },
  { key: "preflight", title: "预检" },
  { key: "install", title: "安装" },
];
const idx = (s: api.WizardStep) => STEPS.findIndex((x) => x.key === s);


function withDone(st: api.WizardState, step: api.WizardStep, next: api.WizardStep): api.WizardState {
  const done = st.done.includes(step) ? st.done : [...st.done, step];
  return { ...st, done, step: next };
}

export default function SetupWizard() {
  const [view, setView] = useState<api.WizardView | null>(null);
  const [err, setErr] = useState<ApiError | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    api.getWizard().then(setView, (e: ApiError) => setErr(e));
  }, []);

  const save = useCallback(async (st: api.WizardState) => {
    setSaving(true);
    try {
      const v = await api.putWizard(st);
      setView(v);
      setErr(null);
      return v;
    } catch (e) {
      setErr(e as ApiError);
      throw e;
    } finally {
      setSaving(false);
    }
  }, []);

  if (!view) return err ? <ApiErrorAlert error={err} /> : <Skeleton active />;
  if (!view.active)
    return (
      <div data-testid="wizard-inactive">
        <Result status="info" title="已有部署" extra={<Button href={href("")}>概览</Button>} />
      </div>
    );

  const st = view.state;
  const current = idx(st.step);
  const reach = Math.max(current, ...st.done.map((d) => idx(d) + 1));
  const go = (i: number) => {
    if (i <= reach && i !== current) void save({ ...st, step: STEPS[i].key }).catch(() => {});
  };
  const back = current > 0 ? () => go(current - 1) : undefined;

  return (
    <div className="setup-wizard" data-testid="setup-wizard">
      <Typography.Title level={4} style={{ marginTop: 0 }}>
        首次配置
      </Typography.Title>
      <Steps
        size="small"
        current={current}
        onChange={go}
        items={STEPS.map((s, i) => ({
          title: s.title,
          disabled: i > reach,
          status: i === current ? "process" : st.done.includes(s.key) ? "finish" : "wait",
        }))}
        style={{ marginBottom: 24 }}
      />
      {err ? <ApiErrorAlert error={err} /> : null}
      <div data-testid={`wizard-step-${st.step}`}>
        {st.step === "gateway" ? <GatewayStep view={view} saving={saving} onNext={(g) => save(withDone({ ...st, gateway: g }, "gateway", "template"))} /> : null}
        {st.step === "template" ? <TemplateStep st={st} saving={saving} back={back} onNext={(t) => save(withDone({ ...st, template: t }, "template", "servers"))} /> : null}
        {st.step === "servers" ? <ServersStep st={st} saving={saving} back={back} onNext={(input) => save(withDone({ ...st, input }, "servers", "topology"))} /> : null}
        {st.step === "topology" ? <TopologyStep st={st} back={back} onNext={(v) => save(withDone({ ...st, topology_version: v }, "topology", "preflight"))} /> : null}
        {st.step === "preflight" ? <PreflightStep back={back} onNext={(id) => save(withDone({ ...st, preflight_id: id }, "preflight", "install"))} /> : null}
        {st.step === "install" ? <InstallStep back={back} /> : null}
      </div>
    </div>
  );
}

function Nav({ back, next, nextLabel = "下一步", disabled, loading }: { back?: () => void; next?: () => void; nextLabel?: string; disabled?: boolean; loading?: boolean }) {
  return (
    <Space style={{ marginTop: 16 }}>
      {back ? <Button onClick={back}>上一步</Button> : null}
      {next ? (
        <Button type="primary" onClick={next} disabled={disabled} loading={loading}>
          {nextLabel}
        </Button>
      ) : null}
    </Space>
  );
}

// ------------------------------------------------------------- gateway ---

function GatewayStep({ view, saving, onNext }: { view: api.WizardView; saving: boolean; onNext: (g: api.TemplateGateway) => Promise<unknown> }) {
  const [form] = Form.useForm<api.TemplateGateway>();
  const g = view.state.gateway;
  const initial: api.TemplateGateway = {
    lan_interface: g.lan_interface,
    lan_ipv4: g.lan_ipv4 || (view.detected.lan_ip ? `${view.detected.lan_ip}/24` : ""),
    router_ipv4: g.router_ipv4,
  };
  return (
    <Form form={form} layout="vertical" initialValues={initial} style={{ maxWidth: 420 }} onFinish={(v) => void onNext(v).catch(() => {})}>
      <Form.Item name="lan_interface" label="局域网网卡" rules={[{ required: true, message: "必填" }]}>
        <Input className="mono" placeholder="eth0" />
      </Form.Item>
      <Form.Item name="lan_ipv4" label="网关地址" rules={[{ required: true, message: "必填" }, { pattern: /^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/, message: "地址/前缀" }]}>
        <Input className="mono" placeholder="192.0.2.2/24" />
      </Form.Item>
      <Form.Item name="router_ipv4" label="主路由器" rules={[{ required: true, message: "必填" }, { pattern: /^\d{1,3}(\.\d{1,3}){3}$/, message: "IPv4 地址" }]}>
        <Input className="mono" placeholder="192.0.2.1" />
      </Form.Item>
      <Button type="primary" htmlType="submit" loading={saving}>
        下一步
      </Button>
    </Form>
  );
}

// ------------------------------------------------------------ template ---

const ROLE: Record<string, string> = { gateway: "网关", relay: "中继", hub: "枢纽", ix: "IX 专线", exit: "出口" };

function TemplateStep({ st, saving, back, onNext }: { st: api.WizardState; saving: boolean; back?: () => void; onNext: (id: string) => Promise<unknown> }) {
  const [list, setList] = useState<api.TopologyTemplate[] | null>(null);
  const [err, setErr] = useState<ApiError | null>(null);
  const [pick, setPick] = useState(st.template);
  useEffect(() => {
    api.getTemplates().then((r) => setList(r.templates), (e: ApiError) => setErr(e));
  }, []);
  if (err) return <ApiErrorAlert error={err} />;
  if (!list) return <Skeleton active />;
  return (
    <>
      <Radio.Group value={pick} onChange={(e) => setPick(e.target.value as string)} style={{ display: "grid", gap: 8 }}>
        {list.map((t) => (
          <Radio key={t.id} value={t.id}>
            <Space size={12}>
              <span>{t.name}</span>
              <Typography.Text type="secondary">{t.nodes.map((n) => ROLE[n] ?? n).join(" → ")}</Typography.Text>
            </Space>
          </Radio>
        ))}
      </Radio.Group>
      <Nav back={back} next={() => void onNext(pick).catch(() => {})} disabled={!pick} loading={saving} />
    </>
  );
}

// ------------------------------------------------------------- servers ---

/** The primary roles a template needs in the wizard. */
function rolesOf(template: string): ("relay" | "hub")[] {
  if (template === "relay") return ["relay"];
  if (template === "relay_hub" || template === "ix") return ["relay", "hub"];
  return [];
}
/** relay_hub and ix may add a backup hub; only relay_hub may put it behind its own relays. */
const allowsBackupHub = (template: string) => template === "relay_hub" || template === "ix";
const allowsBackupRelays = (template: string) => template === "relay_hub";

const blank = (): api.TemplateServer => ({ name: "", endpoint_v4: "", server_id: "" });

function emptyAnswers(template: string, prev?: api.TemplateAnswers | null): api.TemplateAnswers {
  const out: api.TemplateAnswers = {
    exits: prev?.exits?.length ? prev.exits : [{ ...blank(), region: "" }],
    default_region: prev?.default_region ?? "",
  };
  for (const r of rolesOf(template)) out[r] = prev?.[r] ?? blank();
  if (allowsBackupHub(template) && prev?.backup_hub) {
    out.backup_hub = prev.backup_hub;
    if (allowsBackupRelays(template) && prev.backup_relays?.length) out.backup_relays = prev.backup_relays;
  }
  return out;
}

const serverOK = (s: ServerView | undefined) => !!s && s.operable && !!s.last_test?.ok;
const ipv4Of = (s: ServerView) => (/^\d+\.\d+\.\d+\.\d+$/.test(s.address) ? s.address : "");
/** The WAN NIC the server's connection test read (its default route). */
const detectedWAN = (s: ServerView | undefined) => (s?.last_test?.ok ? s.last_test.wan_interface ?? "" : "");

function ServersStep({ st, saving, back, onNext }: { st: api.WizardState; saving: boolean; back?: () => void; onNext: (a: api.TemplateAnswers) => Promise<unknown> }) {
  const [ans, setAns] = useState<api.TemplateAnswers>(() => emptyAnswers(st.template, st.input));
  const [servers, setServers] = useState<ServerView[]>([]);
  const [adding, setAdding] = useState<null | ((s: ServerView) => void)>(null);
  const reload = useCallback(() => api.listServers().then((r) => setServers(r.servers ?? []), () => {}), []);
  useEffect(() => {
    void reload();
  }, [reload]);
  const byId = useMemo(() => new Map(servers.map((s) => [s.id, s])), [servers]);
  const ix = st.template === "ix";

  // A row linked to a server whose test read its WAN NIC, with none filled
  // in yet (e.g. resumed after a reload), takes the detected one.
  useEffect(() => {
    const fill = (v: api.TemplateServer | undefined): api.TemplateServer | undefined => {
      if (!v || v.wan_interface || !v.server_id) return v;
      const w = detectedWAN(byId.get(v.server_id));
      return w ? { ...v, wan_interface: w } : v;
    };
    setAns((a) => {
      const next: api.TemplateAnswers = {
        ...a,
        exits: a.exits.map((e) => fill(e)!),
        relay: fill(a.relay),
        hub: fill(a.hub),
        backup_hub: fill(a.backup_hub),
        backup_relays: a.backup_relays?.map((e) => fill(e)!),
      };
      for (const k of ["relay", "hub", "backup_hub", "backup_relays"] as const) if (next[k] === undefined) delete next[k];
      return JSON.stringify(next) === JSON.stringify(a) ? a : next;
    });
  }, [byId]);

  const link = (v: api.TemplateServer, s: ServerView | undefined, id: string): api.TemplateServer => ({
    ...v,
    server_id: id,
    endpoint_v4: v.endpoint_v4 || (s ? ipv4Of(s) : ""),
    wan_interface: detectedWAN(s) || v.wan_interface || "",
  });

  const row = (label: string, v: api.TemplateServer, set: (v: api.TemplateServer) => void, opts: { region?: boolean; ingress?: boolean; testId: string }) => {
    const sv = v.server_id ? byId.get(v.server_id) : undefined;
    const det = detectedWAN(sv);
    return (
      <div className="wizard-row" data-testid={opts.testId} key={opts.testId} style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center", marginBottom: 8 }}>
        <span style={{ width: 64 }}>{label}</span>
        <Input aria-label={`${label}名称`} placeholder="名称" style={{ width: 140 }} value={v.name} onChange={(e) => set({ ...v, name: e.target.value })} />
        {opts.region ? <Input aria-label={`${label}地区`} placeholder="地区" style={{ width: 80 }} value={v.region} onChange={(e) => set({ ...v, region: e.target.value })} /> : null}
        {opts.ingress ? <Input aria-label={`${label}国内入口`} className="mono" placeholder="国内入口 IPv4" style={{ width: 150 }} value={v.ingress_v4} onChange={(e) => set({ ...v, ingress_v4: e.target.value })} /> : null}
        <Input aria-label={`${label}公网地址`} className="mono" placeholder="公网 IPv4" style={{ width: 150 }} value={v.endpoint_v4} onChange={(e) => set({ ...v, endpoint_v4: e.target.value })} />
        <Select
          aria-label={`${label}服务器`}
          style={{ width: 180 }}
          placeholder="服务器"
          value={v.server_id || undefined}
          options={servers.map((s) => ({ value: s.id, label: s.name }))}
          onChange={(id: string) => set(link(v, byId.get(id), id))}
        />
        <Button
          onClick={() =>
            setAdding(() => (s: ServerView) => {
              void reload();
              set({ ...link(v, s, s.id), name: v.name || s.name });
            })
          }
        >
          添加服务器
        </Button>
        {sv ? (
          <Input
            aria-label={`${label}WAN 网卡`}
            className="mono"
            addonBefore="WAN"
            placeholder={det || "eth0"}
            title={det ? `连接测试读到默认路由在 ${det}` : undefined}
            style={{ width: 150 }}
            value={v.wan_interface ?? ""}
            onChange={(e) => set({ ...v, wan_interface: e.target.value.trim() })}
          />
        ) : null}
        {sv && !(v.wan_interface ?? "").trim() ? (
          <Typography.Text type="danger" data-testid={`${opts.testId}-wan-error`}>
            填写 WAN 网卡
          </Typography.Text>
        ) : null}
        {sv ? <StatusTag kind={serverOK(sv) ? "ok" : "attention"}>{serverOK(sv) ? "已连通" : "未连通"}</StatusTag> : null}
      </div>
    );
  };

  const backups = ans.backup_hub ? [ans.backup_hub, ...(ans.backup_relays ?? [])] : [];
  const entries: api.TemplateServer[] = [...ans.exits, ...rolesOf(st.template).map((r) => ans[r]!), ...backups];
  const complete =
    entries.every((e) => e.name.trim() && e.endpoint_v4.trim() && e.server_id && serverOK(byId.get(e.server_id)) && /^[^\s/'"]{1,15}$/.test(e.wan_interface ?? "")) &&
    ans.exits.every((e) => e.region?.trim()) &&
    (!ix || !!ans.hub?.ingress_v4?.trim()) &&
    ans.exits.some((e) => e.region === ans.default_region);
  const regions = Array.from(new Set(ans.exits.map((e) => e.region ?? "").filter(Boolean)));
  const relays = ans.backup_relays ?? [];
  const setRelays = (list: api.TemplateServer[]) => {
    const next: api.TemplateAnswers = { ...ans, backup_relays: list };
    if (!list.length) delete next.backup_relays;
    setAns(next);
  };

  return (
    <>
      {rolesOf(st.template).map((r) =>
        row(r === "hub" ? (ix ? "IX 专线" : "枢纽") : "中继", ans[r]!, (v) => setAns({ ...ans, [r]: v }), { testId: `wizard-${r}`, ingress: r === "hub" && ix }),
      )}
      {ans.exits.map((e, i) =>
        row(`出口 ${i + 1}`, e, (v) => setAns({ ...ans, exits: ans.exits.map((x, j) => (j === i ? v : x)) }), { region: true, testId: `wizard-exit-${i}` }),
      )}
      <Space style={{ marginBottom: 8 }}>
        <Button onClick={() => setAns({ ...ans, exits: [...ans.exits, { ...blank(), region: "" }] })}>添加出口</Button>
        {ans.exits.length > 1 ? <Button onClick={() => setAns({ ...ans, exits: ans.exits.slice(0, -1) })}>移除最后一个出口</Button> : null}
      </Space>
      {allowsBackupHub(st.template) ? (
        <div data-testid="wizard-backup" style={{ marginBottom: 8 }}>
          {ans.backup_hub ? row("备用枢纽", ans.backup_hub, (v) => setAns({ ...ans, backup_hub: v }), { testId: "wizard-backup-hub" }) : null}
          {relays.map((r, i) => row(`备用中继 ${i + 1}`, r, (v) => setRelays(relays.map((x, j) => (j === i ? v : x))), { testId: `wizard-backup-relay-${i}` }))}
          <Space>
            {ans.backup_hub ? (
              <Button
                onClick={() => {
                  const next = { ...ans };
                  delete next.backup_hub;
                  delete next.backup_relays;
                  setAns(next);
                }}
              >
                移除备用枢纽
              </Button>
            ) : (
              <Button onClick={() => setAns({ ...ans, backup_hub: blank() })}>添加备用枢纽</Button>
            )}
            {ans.backup_hub && allowsBackupRelays(st.template) ? <Button onClick={() => setRelays([...relays, blank()])}>添加备用中继</Button> : null}
            {relays.length ? <Button onClick={() => setRelays(relays.slice(0, -1))}>移除最后一个备用中继</Button> : null}
          </Space>
        </div>
      ) : null}
      <div>
        <Space>
          <span>默认地区</span>
          <Select aria-label="默认地区" style={{ width: 120 }} value={ans.default_region || undefined} options={regions.map((r) => ({ value: r, label: r }))} onChange={(v: string) => setAns({ ...ans, default_region: v })} />
        </Space>
      </div>
      <Nav back={back} next={() => void onNext(ans).catch(() => {})} disabled={!complete} loading={saving} />
      {adding ? (
        <AddServer
          onClose={() => setAdding(null)}
          onReady={(s) => {
            adding(s);
            setAdding(null);
          }}
        />
      ) : null}
    </>
  );
}

/** New server: credential → server → host-key fingerprint confirmation → connection test. */
export function AddServer({ onClose, onReady }: { onClose: () => void; onReady: (s: ServerView) => void }) {
  const [form] = Form.useForm<{ name: string; address: string; port: number; user: string; kind: "password" | "private_key"; secret: string }>();
  const [server, setServer] = useState<ServerView | null>(null);
  const [fp, setFp] = useState<{ key_type: string; fingerprint: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<ApiError | null>(null);
  const run = async (f: () => Promise<void>) => {
    setBusy(true);
    setErr(null);
    try {
      await f();
    } catch (e) {
      setErr(e as ApiError);
    } finally {
      setBusy(false);
    }
  };
  const create = (v: { name: string; address: string; port: number; user: string; kind: "password" | "private_key"; secret: string }) =>
    run(async () => {
      const secret = v.kind === "password" ? { kind: "password" as const, password: v.secret } : { kind: "private_key" as const, private_key: v.secret };
      const c = await api.createCredential({ name: v.name, ...secret });
      const auth = v.kind === "password" ? "password" : "key";
      const s = await api.createServer({ name: v.name, address: v.address, port: v.port, user: v.user, auth, credential_id: c.credential.id });
      setServer(s.server);
      const d = await api.discoverHostKey(s.server.id);
      setServer(d.server);
      setFp(d.discovery);
    });
  const trust = () =>
    run(async () => {
      const r = await api.trustHostKey(server!.id, fp!.fingerprint);
      setServer(r.server);
      const t = await api.testServer(server!.id);
      setServer(t.server);
    });
  const retest = () =>
    run(async () => {
      const t = await api.testServer(server!.id);
      setServer(t.server);
    });
  const trusted = server?.host_key?.state === "trusted";
  const tested = server?.last_test;
  return (
    <Modal open title="添加服务器" onCancel={onClose} footer={null} destroyOnClose>
      {err ? <ApiErrorAlert error={err} /> : null}
      {!server ? (
        <Form form={form} layout="vertical" initialValues={{ port: 22, user: "root", kind: "password" }} onFinish={(v) => void create(v)}>
          <Form.Item name="name" label="名称" rules={[{ required: true, message: "必填" }]}>
            <Input />
          </Form.Item>
          <Form.Item name="address" label="地址" rules={[{ required: true, message: "必填" }]}>
            <Input className="mono" />
          </Form.Item>
          <Space>
            <Form.Item name="port" label="端口">
              <InputNumber min={1} max={65535} />
            </Form.Item>
            <Form.Item name="user" label="用户">
              <Input />
            </Form.Item>
          </Space>
          <Form.Item name="kind" label="登录方式">
            <Radio.Group options={[{ value: "password", label: "密码" }, { value: "private_key", label: "私钥" }]} />
          </Form.Item>
          <Form.Item noStyle shouldUpdate>
            {() => (
              <Form.Item name="secret" label={form.getFieldValue("kind") === "password" ? "登录密码" : "私钥内容"} rules={[{ required: true, message: "必填" }]}>
                {form.getFieldValue("kind") === "password" ? <Input.Password autoComplete="new-password" /> : <Input.TextArea rows={4} className="mono" />}
              </Form.Item>
            )}
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={busy}>
            获取指纹
          </Button>
        </Form>
      ) : (
        <Space direction="vertical" style={{ width: "100%" }}>
          {fp ? (
            <div data-testid="wizard-fingerprint">
              <Typography.Text type="secondary">{fp.key_type}</Typography.Text> <Mono>{fp.fingerprint}</Mono>
            </div>
          ) : null}
          {!trusted ? (
            <Button type="primary" onClick={() => void trust()} loading={busy} disabled={!fp}>
              确认指纹并测试
            </Button>
          ) : tested?.ok ? (
            <>
              <StatusTag kind="ok">已连通</StatusTag>
              {tested.wan_interface ? (
                <span data-testid="wizard-detected-wan">
                  <Typography.Text type="secondary">WAN 网卡</Typography.Text> <Mono>{tested.wan_interface}</Mono>
                </span>
              ) : null}
              <Button type="primary" onClick={() => onReady(server)}>
                完成
              </Button>
            </>
          ) : (
            <>
              {tested ? <Alert type="error" showIcon message={tested.error || tested.code || "连接失败"} /> : null}
              <Button onClick={() => void retest()} loading={busy}>
                重新测试
              </Button>
            </>
          )}
        </Space>
      )}
    </Modal>
  );
}

// ------------------------------------------------------------ topology ---

function TopologyStep({ st, back, onNext }: { st: api.WizardState; back?: () => void; onNext: (version: string) => Promise<unknown> }) {
  const [prev, setPrev] = useState<api.TemplatePreview | null>(null);
  const [err, setErr] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!st.input) return;
    api.previewTemplate(st.template, { ...st.input, gateway: st.gateway }).then(setPrev, (e: ApiError) => setErr(e));
  }, [st.template, st.gateway, st.input]);
  const saveTopo = async () => {
    if (!prev) return;
    setBusy(true);
    setErr(null);
    try {
      await api.putTopology(prev.topology, false);
      const d = await api.getDeploy();
      await onNext(d.topology_version ?? d.plan?.topology_version ?? "saved");
    } catch (e) {
      setErr(e as ApiError);
    } finally {
      setBusy(false);
    }
  };
  const errors = prev?.issues.filter((i) => i.severity === "error") ?? [];
  return (
    <>
      {err ? <ApiErrorAlert error={err} /> : null}
      {!prev && !err ? <Skeleton active /> : null}
      {prev ? (
        <div data-testid="wizard-preview">
          <ul className="wizard-nodes">
            {prev.topology.nodes.map((n) => (
              <li key={n.id}>
                {ROLE[n.role] ?? n.role} <span>{n.name}</span>
              </li>
            ))}
          </ul>
          {errors.map((i, k) => (
            <Alert key={k} type="error" showIcon message={i.message} style={{ marginBottom: 4 }} />
          ))}
        </div>
      ) : null}
      <Nav back={back} next={() => void saveTopo()} nextLabel="保存拓扑" disabled={!prev || !prev.valid} loading={busy} />
    </>
  );
}

// ----------------------------------------------------------- preflight ---

function PreflightStep({ back, onNext }: { back?: () => void; onNext: (id: string) => Promise<unknown> }) {
  const [pf, setPf] = useState<{ rec?: PreflightRecord; error?: ApiError; running?: boolean } | null>(null);
  const run = () => {
    setPf({ running: true });
    api.hostPreflight().then(
      (r) => setPf(r?.preflight ? { rec: normalizePreflight(r.preflight) } : { error: new api.ApiError(502, { error: "没有预检结果" }) }),
      (e: ApiError) => setPf({ error: e }),
    );
  };
  const reason = pf?.rec ? preflightBlockedReason(pf.rec) : null;
  const usable = pf?.rec && !pf.rec.blocking && !reason ? pf.rec.id : undefined;
  return (
    <>
      <Button onClick={run} loading={pf?.running}>
        {pf ? "重新预检" : "运行预检"}
      </Button>
      <div style={{ marginTop: 12 }}>
        {pf?.error ? <ApiErrorAlert error={pf.error} /> : null}
        {pf?.rec ? <PreflightReport rec={pf.rec} /> : null}
        {reason ? <Alert type="warning" showIcon message={reason} /> : null}
      </div>
      <Nav back={back} next={() => usable && void onNext(usable).catch(() => {})} disabled={!usable} />
    </>
  );
}

// ------------------------------------------------------------- install ---

function InstallStep({ back }: { back?: () => void }) {
  const { navigate } = useRouter();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<ApiError | null>(null);
  const open = async () => {
    setBusy(true);
    try {
      await api.completeWizard();
      wizardEvents.onFinish();
      navigate(href("deploy"));
    } catch (e) {
      setErr(e as ApiError);
      setBusy(false);
    }
  };
  return (
    <>
      {err ? <ApiErrorAlert error={err} /> : null}
      <Nav back={back} next={() => void open()} nextLabel="打开部署" loading={busy} />
    </>
  );
}
