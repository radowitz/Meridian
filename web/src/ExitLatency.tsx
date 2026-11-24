import { LatencyBadge } from "./LatencyBadge";
import { Button, Space, Typography } from "antd";
import { useEffect, useRef, useState } from "react";
import * as api from "./api";
import { ApiErrorAlert, Fold, Note, TimeText, formatAbsolute, useApi } from "./ui";

export interface ExitLatencyRow {
 exit_id: string; name: string; scope: "exit_resolver" | "carrier_resolver";
 state: string; rtt_ms?: number; sent: number; received: number;
 measured_at: string; interface?: string; error?: string; stale: boolean;
}
export interface ExitLatencyView { available: boolean; running: boolean; rows: ExitLatencyRow[] }
const stateWord: Record<string,string> = { not_measured:"尚未测量",not_installed:"网关尚未安装此出口",unreachable:"未连通",unavailable:"测量不可用",busy:"宿主正忙",path_changed:"路径改变，请重测",cancelled:"测量已取消" };

export function ExitLatencyValue({row,compact}:{row?:ExitLatencyRow; /** Badge only (table rows). */ compact?:boolean}) {
 if(!row || row.state==="not_measured")return null;
 const ok=(row.state==="ok" || row.state==="partial") && row.rtt_ms!==undefined && Number.isFinite(row.rtt_ms) && row.rtt_ms>=0;
 return <span className="latency-reading">
  <LatencyBadge ms={ok ? row.rtt_ms : undefined} digits={1} stale={row.stale} partial={ok && row.state==="partial"}
    failed={row.state==="unreachable"} label={stateWord[row.state] ?? "未知"}
    title={`网关到${row.scope==="carrier_resolver"?"承载节点":"出口"}解析器的 TCP 握手，${row.received}/${row.sent} 次成功，测于 ${formatAbsolute(new Date(row.measured_at))}${row.error?`，${row.error}`:""}`} />
  {ok && !compact ? <span className="muted">网关实测</span> : null}
 </span>;
}

/**
 * The stored gateway → exit latencies, with one bounded measurement when the
 * page opens and a row is unmeasured or stale (GET never probes), and a quiet
 * re-read every minute while the page is visible.
 */
export function useExitLatency() {
 const view=useApi(api.getExitLatency,[]);
 const [busy,setBusy]=useState(false);
 const [error,setError]=useState<api.ApiError>();
 const initiated=useRef(false);
 const refresh=async()=>{
  setBusy(true);setError(undefined);
  try {view.setData(await api.measureExitLatency());}
  catch(e){setError(api.isApiError(e)?e:new api.ApiError(500,{error:String(e)}));}
  finally{setBusy(false);}
 };
 useEffect(()=>{
  const d=view.data;
  if(!d || initiated.current)return;
  initiated.current=true;
  if(d.available && !d.running && d.rows.some(r=>r.state==="not_measured" || r.stale))void refresh();
  // eslint-disable-next-line react-hooks/exhaustive-deps
 },[view.data]);
 useEffect(()=>{
  const id=setInterval(()=>{if(!document.hidden && !busy)void view.reload();},60_000);
  return ()=>clearInterval(id);
 },[busy,view.reload]);
 return {view,busy,error,refresh};
}

/**
 * One-line state of the latencies for a folded panel. Only fresh readings of
 * an exit's own resolver count as connected: an external SOCKS exit is
 * measured to its carrier only, and an old reading waits for a new one.
 */
export function latencySummary(rows: ExitLatencyRow[]): string {
 if(rows.length===0)return "";
 if(rows.every(r=>r.state==="not_measured"))return "尚未测量";
 const own=rows.filter(r=>r.scope==="exit_resolver");
 const ok=own.filter(r=>!r.stale && (r.state==="ok"||r.state==="partial")).length;
 const down=own.filter(r=>!r.stale && r.state==="unreachable").length;
 const old=rows.filter(r=>r.stale && r.state!=="not_measured").length;
 const carrier=rows.length-own.length;
 return [`${ok}/${own.length} 个出口连通`, down?`${down} 个不通`:"", old?`${old} 个待重测`:"", carrier?`${carrier} 个外部出口只测到承载节点`:""].filter(Boolean).join(" · ");
}

export function ExitLatencyPanel({onData}:{onData?:(rows:ExitLatencyRow[])=>void}) {
 const {view,busy,error,refresh}=useExitLatency();
 useEffect(()=>{if(view.data)onData?.(view.data.rows);},[view.data,onData]);
 return <Fold title="网关 → 各出口延迟" summary={view.data?latencySummary(view.data.rows):undefined} extra={<Button size="small" loading={busy} disabled={view.data?.available===false} onClick={()=>void refresh()}>测量延迟</Button>}>
  <Note mode="popover" label="延迟测量说明">从本地网关经当前隧道到出口解析服务的 TCP 握手往返时间，每轮最多 3 次取平均；不含上游 DNS 查询或网站响应时间。只测连通性，不参与自动切换。</Note>
  <ApiErrorAlert error={error ?? view.error} />
  {view.data?.available===false?<Typography.Text type="secondary">需升级宿主代理以测量延迟。</Typography.Text>:null}
  <div data-testid="gateway-exit-latency" style={{overflowWrap:"anywhere"}}>
   {view.data?.rows.map(r=>{
    const measured=(r.state==="ok" || r.state==="partial") && r.rtt_ms!==undefined && Number.isFinite(r.rtt_ms) && r.rtt_ms>=0;
    return <div key={r.exit_id} data-testid={`exit-latency-${r.exit_id}`} className="latency-result-row">
     <Typography.Text strong>{r.name || r.exit_id}</Typography.Text>
     <LatencyBadge ms={measured ? r.rtt_ms : undefined} digits={1} stale={r.stale} partial={measured && r.state==="partial"} failed={r.state==="unreachable"} label={stateWord[r.state] ?? "未知"} />
     {r.sent>0?<span className="muted">{r.received}/{r.sent} 次握手成功</span>:null}
     {r.stale?<Typography.Text type="warning">结果已过期，请重测</Typography.Text>:null}
     {r.state!=="not_measured"?<span className="muted">测于 <TimeText value={r.measured_at} /></span>:null}
     {r.scope==="carrier_resolver"?<span className="muted">外部 SOCKS：仅到承载节点解析器</span>:null}
     {r.error?<span className="muted">{r.error}</span>:null}
    </div>;
   })}
  </div>
  {!view.data && !view.error?<Space>读取中…</Space>:null}
 </Fold>;
}
