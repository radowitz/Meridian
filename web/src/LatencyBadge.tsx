export function LatencyBadge({ ms, digits = 0, stale = false, partial = false, failed = false, label, title }: {
  ms?: number | null;
  digits?: number;
  stale?: boolean;
  partial?: boolean;
  failed?: boolean;
  label?: string;
  title?: string;
}) {
  const measured = typeof ms === "number" && Number.isFinite(ms) && ms >= 0;
  const band = measured ? ms < 80 ? "较低" : ms < 180 ? "中等" : "较高" : "无样本";
  const tone = stale ? "neutral" : failed ? "bad" : partial ? "warn"
    : !measured ? "neutral" : ms < 80 ? "ok" : ms < 180 ? "info" : "warn";
  const value = measured ? `${ms.toFixed(digits)} ms` : label ?? "未测量";
  const detail = stale ? "已过期" : partial ? "部分探测成功" : measured ? `延迟${band}` : value;
  return <span className="latency-badge" data-tone={tone} title={[value, detail, title].filter(Boolean).join(" · ")}>
    <span className="latency-badge-dot" aria-hidden="true" />
    {value}
    {stale ? <span>已过期</span> : partial ? <span>部分成功</span> : null}
    {measured && !stale && !partial ? <span className="sr-only"> · {detail}</span> : null}
  </span>;
}
