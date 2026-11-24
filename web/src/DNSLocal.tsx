import { App, Button, Form, Input, Popconfirm, Space, Typography } from "antd";
import * as api from "./api";
import { ApiErrorAlert, Fold, Link, useAction, useApi, useConfirmDanger } from "./ui";
import { href } from "./state";

export function DNSLocal() {
  const { message } = App.useApp();
  const [form] = Form.useForm<api.DNSHostRecord>();
  const state = useApi(api.getDNSLocal, []);
  const action = useAction();
  const confirm = useConfirmDanger();

  async function change(kind: "flush" | "add" | "delete", host?: api.DNSHostRecord) {
    const result = await action.run(() => api.changeDNSLocal(kind, host), kind, () => void state.reload());
    if (!result) return;
    if (kind !== "flush") state.setData(result);
    if (kind === "add") form.resetFields();
    message.success(kind === "flush" ? "网关 DNS 缓存已清除" : kind === "add" ? "Hosts 已生效" : "Hosts 已删除并生效");
  }

  return <Fold title="DNS 缓存与 Hosts" id="dns-local" testId="dns-local">
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <div>
        <Button loading={action.busy === "flush"} disabled={!state.data?.cache_enabled || !!action.busy} onClick={() => confirm({
          title: "清除网关所有 DNS 缓存？",
          consequence: "SmartDNS 会短暂重启，下次查询重新解析。客户端和上游解析器各自保存的缓存需要分别清除。",
          okText: "清除缓存",
          onOk: () => change("flush"),
        })}>清除所有 DNS 缓存</Button>
      </div>
      <ApiErrorAlert error={state.error} onRetry={() => void state.reload()} />
      <ApiErrorAlert error={action.error} onClose={action.clear} />
      {state.data ? <>
        {state.data.hosts_enabled ? (
          <Form form={form} layout="vertical" className="dns-host-form" onFinish={host => void change("add", host)} disabled={!!action.busy}>
            <Form.Item name="name" label="域名" rules={[{ required: true, message: "请输入域名" }]}>
              <Input placeholder="nas.example.lan" autoComplete="off" />
            </Form.Item>
            <Form.Item name="ip" label="IP 地址" rules={[{ required: true, message: "请输入 IP 地址" }]}>
              <Input placeholder="192.168.1.10 或 IPv6" autoComplete="off" />
            </Form.Item>
            <Button type="primary" htmlType="submit" loading={action.busy === "add"}>添加并生效</Button>
          </Form>
        ) : <Typography.Text type="secondary">首次使用需<Link to={href("deploy")}>安装新版网关解析配置</Link>。之后添加或删除即时生效。</Typography.Text>}
        {state.data.hosts.length ? <ul className="plain-list">
          {state.data.hosts.map(host => <li key={`${host.name}/${host.ip}`}>
            <Space wrap>
              <strong>{host.name}</strong>
              <code>{host.ip}</code>
              <Popconfirm title={`删除 ${host.name} → ${host.ip}？`} description="删除后网关立即不再返回这条记录。" okText="删除" okButtonProps={{ danger: true }} cancelText="取消" onConfirm={() => change("delete", host)}>
                <Button size="small" danger disabled={!state.data?.hosts_enabled || !!action.busy} aria-label={`删除 ${host.name} ${host.ip}`}>删除</Button>
              </Popconfirm>
            </Space>
          </li>)}
        </ul> : <Typography.Text type="secondary">暂无 Hosts 记录</Typography.Text>}
      </> : null}
    </Space>
  </Fold>;
}
