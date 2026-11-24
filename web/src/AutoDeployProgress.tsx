import { Alert, Button, Space } from "antd";
import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { href } from "./state";
import type { DeployView, MTUChange } from "./types";
import { Link } from "./ui_base";

type Progress = {
  phase: "running" | "done" | "stopped";
  view?: DeployView;
  repairs: MTUChange[];
  error?: string;
  saved: boolean;
};

type Run = (onUpdate: (view: DeployView) => void, onRepair: (changes: MTUChange[]) => void, onSaved: () => void) => Promise<void>;
const ProgressContext = createContext<{ progress: Progress | null; track: (run: Run, saved: boolean) => Promise<void>; dismiss: () => void } | null>(null);

export function AutoDeployProvider({ children }: { children: ReactNode }) {
  const [progress, setProgress] = useState<Progress | null>(null);
  const running = useRef(false);
  async function track(run: Run, saved: boolean) {
    if (running.current) return;
    running.current = true;
    const priorRun = saved && progress?.phase === "stopped" ? progress.view?.run?.id : undefined;
    setProgress({
      phase: "running", repairs: priorRun ? progress!.repairs : [], saved,
    });
    const patch = (next: Partial<Progress>) => setProgress(previous => previous && { ...previous, ...next });
    try {
      await run(
        view => setProgress(previous => previous && {
          ...previous, view,
          repairs: priorRun && !previous.view && view.run?.id !== priorRun ? [] : previous.repairs,
        }),
        changes => setProgress(previous => previous && { ...previous, repairs: [...previous.repairs, ...changes] }),
        () => patch({ saved: true }),
      );
      patch({ phase: "done" });
    } catch (error) {
      patch({ phase: "stopped", error: error instanceof Error ? error.message : String(error) });
    } finally {
      running.current = false;
    }
  }
  return <ProgressContext.Provider value={{ progress, track, dismiss: () => setProgress(null) }}>{children}</ProgressContext.Provider>;
}

export const useOptionalAutoDeployProgress = () => useContext(ProgressContext);
export const useAutoDeployProgress = () => useOptionalAutoDeployProgress()!;

const phases: Record<string, string> = {
  pending: "等待预检", preflighting: "正在预检", review: "预检通过",
  blocked: "预检受阻", installing: "正在下发", unknown: "正在复核安装记录", failed: "下发失败",
};

export function AutoDeployProgress({ onResume }: { onResume?: () => void }) {
  const { progress: value, dismiss } = useAutoDeployProgress();
  const [now, setNow] = useState(Date.now);
  const run = value?.view?.run;
  const current = run?.steps.find(step => step.node_id === run.current);
  const retryAt = current?.retry_at ? Date.parse(current.retry_at) : 0;
  useEffect(() => {
    if (!retryAt || value?.phase !== "running") return;
    setNow(Date.now());
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [retryAt, value?.phase]);
  if (!value) return null;

  const done = run?.steps.filter(step => step.phase === "done").length ?? 0;
  const server = current?.current_target?.server_id ?? current?.plan_target?.server_id;
  const needsServer = /^(host_key_|auth_|server_not_ready|credential)/.test(current?.code ?? "") ||
    /指纹|SSH 凭据/.test(value.error ?? "");
  const stage = retryAt > now ? `SSH 限流，剩余 ${Math.ceil((retryAt - now) / 1000)} 秒`
    : current ? phases[current.phase] : value.saved ? "正在准备部署计划" : "正在保存拓扑";
  const message = value.phase === "done" ? "自动部署完成"
    : value.phase === "stopped" ? value.saved ? "配置已保存，部署已暂停" : "自动部署已暂停"
    : "正在自动部署";
  return <Alert className="auto-deploy-progress" showIcon
    type={value.phase === "running" ? "info" : value.phase === "stopped" ? "warning" : "success"}
    message={message}
    closable={value.phase === "done"} onClose={dismiss}
    description={<div role="status">
      {run?.steps.length ? <div>已完成 {done}/{run.steps.length}{current ? ` · ${current.node_name}` : ""}{value.phase === "running" ? ` · ${stage}` : ""}</div>
        : value.phase === "running" ? <div>{stage}</div> : null}
      {value.error ? <div>{value.error}</div> : null}
      {value.repairs.length ? <details open>
        <summary>自动修复 · {value.repairs.length} 项</summary>
        <ul className="plain-list">{value.repairs.map((change, index) => <li key={index}>
          <Link to={href("topology", change.link_id)}>{change.link_id}</Link> · {change.field === "wg_port" ? "UDP 端口" : "MTU"} · {change.from_effective ?? (change.from || "默认")} → {change.to} · {change.field === "wg_port" ? "原端口被占用" : "上联承载不足"}
        </li>)}</ul>
      </details> : null}
    </div>}
    action={value.phase === "stopped" ? <Space wrap>
      {needsServer && server ? <Link to={`${href("servers", server)}?from=deploy`}>打开服务器</Link> : null}
      {value.saved && onResume && !run?.stale ? <Button size="small" onClick={onResume}>继续自动部署</Button> : null}
      <Link to={`${href("deploy")}?section=guide`}>查看部署并继续</Link>
    </Space> : undefined}
  />;
}
