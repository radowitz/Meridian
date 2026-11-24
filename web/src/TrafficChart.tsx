import { formatAbsolute } from "./ui";
// Real-time throughput on the overview: polls GET /api/traffic every second
// while the page is visible, turns consecutive counter samples into rates
// (a reset sample is a new baseline, never a rate) and shows the current
// download / upload rates (domestic / foreign) and active connections.

import { useEffect, useRef, useState, type ReactNode } from "react";
import * as api from "./api";
import type { TrafficConnections, TrafficKey, TrafficView } from "./types";

export const POLL_MS = 1000;
const HISTORY_MS = 60_000;
/** No successful sample for this long: the panel says 过期 instead of 实时. */
export const STALE_MS = 3 * POLL_MS + 1000;

const KEYS: TrafficKey[] = ["down_domestic", "down_foreign", "up_domestic", "up_foreign"];

/** Rates in bit/s; null where the counter is missing in either sample. */
export interface RatePoint {
  t: number;
  v: Record<TrafficKey, number | null>;
}

export interface Sample {
  t: number;
  epoch?: number;
  counters: TrafficView["counters"];
}

/** The sample to keep as baseline, or null when the answer carries no counters. */
export function sampleOf(v: TrafficView): Sample | null {
  if (!v.available || !v.read_at) return null;
  const t = Date.parse(v.read_at);
  return Number.isFinite(t) ? { t, epoch: v.counter_epoch, counters: v.counters } : null;
}

/**
 * The rate between the previous sample and this answer. Null when there is
 * no previous sample, the answer is a reset (new baseline), time did not
 * advance, or every counter went backwards.
 */
export function rateBetween(prev: Sample | null, cur: TrafficView): RatePoint | null {
  const s = sampleOf(cur);
  if (!prev || !s || cur.reset || prev.epoch !== s.epoch) return null;
  const dt = (s.t - prev.t) / 1000;
  if (dt <= 0) return null;
  const v = {} as RatePoint["v"];
  let any = false;
  for (const k of KEYS) {
    const a = prev.counters[k]?.bytes;
    const b = s.counters[k]?.bytes;
    if (a === undefined || b === undefined || b < a) {
      v[k] = null;
      continue;
    }
    v[k] = ((b - a) * 8) / dt;
    any = true;
  }
  return any ? { t: s.t, v } : null;
}

export type Freshness = "live" | "stale" | "paused" | "waiting";
export function freshness(lastOk: number | null, now: number, hidden: boolean): Freshness {
  if (hidden) return "paused";
  if (lastOk === null) return "waiting";
  return now - lastOk > STALE_MS ? "stale" : "live";
}

/** A rate with its unit: kbit/s below 1 Mbit/s, Gbit/s from 1 Gbit/s; null → "—". */
export function fmtRate(bps: number | null | undefined): { n: string; unit: string } {
  if (bps === null || bps === undefined || !Number.isFinite(bps)) return { n: "—", unit: "" };
  const [d, unit] = bps >= 1e9 ? [1e9, "Gbit/s"] : bps >= 1e6 ? [1e6, "Mbit/s"] : [1e3, "kbit/s"];
  const m = bps / d;
  return { n: m >= 100 ? m.toFixed(0) : m >= 10 ? m.toFixed(1) : m.toFixed(2), unit };
}

/** A connection count; unknown (null/absent) is "—", never 0. */
export const fmtCount = (n: number | null | undefined) => (typeof n === "number" ? String(n) : "—");

const clock = (t: number) => formatAbsolute(new Date(t)).slice(11);

function Rate({ id, bps }: { id: string; bps: number | null | undefined }) {
  const r = fmtRate(bps);
  return (
    <span className="ts-val" data-testid={id}>
      <span className="num">{r.n}</span>
      {r.unit ? <span className="ts-unit">{r.unit}</span> : null}
    </span>
  );
}

function Row({ label, kind, children }: { label: string; kind?: "dom" | "for"; children: ReactNode }) {
  return (
    <div className={`ts-row${kind ? ` ${kind}` : ""}`}>
      <span className="ts-label">{label}</span>
      {children}
    </div>
  );
}

export function TrafficStats({ rate, conns }: { rate: RatePoint | null | undefined; conns: TrafficConnections | null | undefined }) {
  const v = rate?.v;
  const ok = !!conns?.available;
  const count = (id: string, n: number | null | undefined) => (
    <span className="ts-val" data-testid={id}>
      <span className="num">{fmtCount(ok ? n : null)}</span>
    </span>
  );
  return (
    <div className="traffic-stats" data-testid="traffic-stats">
      <div className="ts-col" data-testid="ts-down">
        <div className="ts-head">下载</div>
        <Row label="国内" kind="dom"><Rate id="traffic-down-dom" bps={v?.down_domestic} /></Row>
        <Row label="国外" kind="for"><Rate id="traffic-down-for" bps={v?.down_foreign} /></Row>
      </div>
      <div className="ts-col" data-testid="ts-up">
        <div className="ts-head">上传</div>
        <Row label="国内" kind="dom"><Rate id="traffic-up-dom" bps={v?.up_domestic} /></Row>
        <Row label="国外" kind="for"><Rate id="traffic-up-for" bps={v?.up_foreign} /></Row>
      </div>
      <div className="ts-col" data-testid="ts-conns">
        <div className="ts-head">连接</div>
        {ok && conns!.split ? (
          <>
            <Row label="国内" kind="dom">{count("traffic-conn-dom", conns!.domestic)}</Row>
            <Row label="国外" kind="for">{count("traffic-conn-for", conns!.foreign)}</Row>
          </>
        ) : null}
        <Row label="合计">{count("traffic-conn-total", conns?.total)}</Row>
      </div>
    </div>
  );
}

type TrendPoint = { t: number; down: number | null; up: number | null };

function TrafficTrend({ points, now }: { points: TrendPoint[]; now: number }) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const max = Math.max(1_000, ...points.flatMap(p => [p.down ?? 0, p.up ?? 0]));
  const magnitude = 10 ** Math.floor(Math.log10(max));
  const step = (max / magnitude <= 2 ? 2 : max / magnitude <= 5 ? 5 : 10) * magnitude;
  const [selectedTime, setSelectedTime] = useState<number>();
  const samples = points.filter(point => point.down !== null || point.up !== null);
  const selected = samples.find(point => point.t === selectedTime);
  const selectAt = (ratio: number) => {
    const target = now - HISTORY_MS * (1 - Math.max(0, Math.min(1, ratio)));
    const point = samples.reduce<TrendPoint | undefined>((best, item) =>
      !best || Math.abs(item.t - target) < Math.abs(best.t - target) ? item : best, undefined);
    setSelectedTime(point && Math.abs(point.t - target) <= POLL_MS * 1.5 ? point.t : undefined);
  };
  useEffect(() => {
    const el = canvas.current;
    if (!el || typeof CanvasRenderingContext2D === "undefined") return;
    const draw = () => {
      const { width, height } = el.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      el.width = Math.round(width * dpr);
      el.height = Math.round(height * dpr);
      const ctx = el.getContext("2d");
      if (!ctx || !width || !height) return;
      ctx.scale(dpr, dpr);
      const css = getComputedStyle(el);
      if (selected) {
        const x = 2 + (width - 4) * (1 - (now - selected.t) / HISTORY_MS);
        ctx.fillStyle = css.getPropertyValue("--m-border").trim();
        ctx.fillRect(x, 0, 1, height);
      }
      for (const [key, color] of [["down", "--m-accent"], ["up", "--m-role-relay"]] as const) {
        ctx.beginPath();
        ctx.strokeStyle = css.getPropertyValue(color).trim();
        ctx.lineWidth = 2;
        ctx.lineJoin = "round";
        let previousTime: number | undefined;
        for (const point of points) {
          const value = point[key];
          if (value === null) {
            previousTime = undefined;
            continue;
          }
          const x = 2 + (width - 4) * (1 - (now - point.t) / HISTORY_MS);
          const y = height - 2 - (height - 4) * value / step;
          if (previousTime === undefined || point.t - previousTime > 2.5 * POLL_MS) ctx.moveTo(x, y);
          else ctx.lineTo(x, y);
          previousTime = point.t;
        }
        ctx.stroke();
      }
    };
    draw();
    const observer = typeof ResizeObserver === "undefined" ? undefined : new ResizeObserver(draw);
    observer?.observe(el);
    return () => observer?.disconnect();
  }, [points, now, selected, step]);

  const top = fmtRate(step);
  return <figure className="traffic-trend" aria-label="最近 60 秒上传和下载速率">
    <div className="traffic-chart-grid">
      <span className="traffic-axis-max">{top.n} {top.unit}</span>
      <canvas ref={canvas} tabIndex={0} role="img" aria-label="上传下载图，左右方向键查看采样"
        onPointerMove={event => {
          if (event.pointerType === "touch" && event.buttons === 0) return;
          const rect = event.currentTarget.getBoundingClientRect();
          if (rect.width) selectAt((event.clientX - rect.left) / rect.width);
        }}
        onPointerDown={event => {
          const rect = event.currentTarget.getBoundingClientRect();
          if (rect.width) selectAt((event.clientX - rect.left) / rect.width);
        }}
        onPointerLeave={event => { if (event.pointerType !== "touch") setSelectedTime(undefined); }}
        onKeyDown={event => {
          if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
          event.preventDefault();
          const index = selected ? samples.indexOf(selected) : samples.length;
          const next = Math.max(0, Math.min(samples.length - 1, index + (event.key === "ArrowLeft" ? -1 : 1)));
          setSelectedTime(samples[next]?.t);
        }} />
    </div>
    <figcaption>
      <span>60 秒前</span>
      <span className="traffic-legend"><span className="traffic-down-key">下载</span><span className="traffic-up-key">上传</span></span>
      <span>现在</span>
    </figcaption>
    <div className="traffic-inspect" aria-live="polite">{selected ?
      `${clock(selected.t)} · 下载 ${rateText(selected.down)} · 上传 ${rateText(selected.up)}` : null}</div>
  </figure>;
}

export function fmtTrafficUsage(bytes: number | undefined) {
  if (bytes === undefined || !Number.isFinite(bytes) || bytes < 0) return "—";
  const [scale, unit] = bytes >= 1e12 ? [1e12, "TB"] : [1e9, "GB"];
  return `${(bytes / scale).toFixed(2)} ${unit}`;
}

function rateText(value: number | null) {
  const { n, unit } = fmtRate(value);
  return unit ? `${n} ${unit}` : n;
}

function TrafficUsage({ usage, since }: { usage: TrafficView["usage_bytes"]; since?: TrafficView["usage_since"] }) {
  if (usage?.domestic === undefined && usage?.foreign === undefined) return null;
  return <dl className="traffic-usage" aria-label="累计已用流量">
    {(["domestic", "foreign"] as const).map(region => <div key={region}>
      <dt>{region === "domestic" ? "国内已用" : "国外已用"}</dt>
      <dd className="num" data-testid={`traffic-used-${region}`}>{fmtTrafficUsage(usage?.[region])}</dd>
      {usage?.[region] !== undefined ? <small className="muted">{since?.[region] ?
        `起始采样 ${formatAbsolute(new Date(since[region]!))}` : "历史累计 · 起点未知"}</small> : null}
    </div>)}
  </dl>;
}

const QUIET: Record<string, string> = {
  not_installed: "网速：数据面还没装计数器",
  agent_unavailable: "网速：宿主通道不可用",
  read_failed: "网速：读取失败",
};

export default function TrafficChart() {
  const [last, setLast] = useState<RatePoint | null>(null);
  const [history, setHistory] = useState<RatePoint[]>([]);
  const [usage, setUsage] = useState<TrafficView["usage_bytes"]>();
  const [since, setSince] = useState<TrafficView["usage_since"]>();
  const [conns, setConns] = useState<TrafficConnections | null>(null);
  const [down, setDown] = useState<{ code: string; message?: string } | null>(null);
  const [lastOk, setLastOk] = useState<number | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const [hidden, setHidden] = useState(() => typeof document !== "undefined" && document.visibilityState === "hidden");
  const prev = useRef<Sample | null>(null);

  useEffect(() => {
    const onVis = () => setHidden(document.visibilityState === "hidden");
    document.addEventListener("visibilitychange", onVis);
    return () => document.removeEventListener("visibilitychange", onVis);
  }, []);

  useEffect(() => {
    if (hidden) return;
    // After a pause the old baseline would average over the hidden time: start over.
    prev.current = null;
    setLast(null);
    let stop = false;
    // Freshness clock independent of requests: a hanging request still goes 过期 on time.
    const clockTimer = setInterval(() => setNow(Date.now()), 1000);
    let timer: ReturnType<typeof setTimeout> | undefined;
    const ctl = new AbortController();
    const tick = async () => {
      const startedAt = Date.now();
      try {
        const v = await api.getTraffic(ctl.signal);
        if (stop) return;
        const t = Date.now();
        setConns(v.connections ?? null);
        if (v.usage_bytes) { setUsage(v.usage_bytes); setSince(v.usage_since); }
        if (!v.available) {
          setDown({ code: v.code ?? "read_failed", message: v.message });
          prev.current = null;
          setLast(null);
          if (v.connections?.available) setLastOk(t);
        } else {
          setDown(null);
          const sample = sampleOf(v);
          if (sample && prev.current && sample.t === prev.current.t) return;
          const p = rateBetween(prev.current, v);
          prev.current = sample;
          // Rates use the gateway's read_at; freshness uses this browser's clock (no skew).
          // No valid rate (reset, missing counters, first sample): show —, never an old rate.
          setLast(p);
          setHistory(points => {
            const recent = points.filter(point => t - point.t <= HISTORY_MS).slice(-60);
            if (p) return [...recent, { ...p, t }];
            if (recent.length) return [...recent, { t, v: { down_domestic: null, down_foreign: null, up_domestic: null, up_foreign: null } }];
            return recent;
          });
          setLastOk(t);
        }
        setNow(t);
      } catch {
        if (stop) return;
        setDown({ code: "read_failed" });
        setConns(null);
        prev.current = null;
        setLast(null);
        setNow(Date.now());
      } finally {
        if (!stop) timer = setTimeout(() => void tick(), Math.max(0, POLL_MS - (Date.now() - startedAt)));
      }
    };
    void tick();
    return () => {
      stop = true;
      ctl.abort();
      clearInterval(clockTimer);
      if (timer) clearTimeout(timer);
    };
  }, [hidden]);

  if (down && !last && !conns?.available && !history.some(point => now - point.t <= HISTORY_MS)) {
    return (
      <div className="traffic-quiet" data-testid="traffic-chart" data-state="unavailable" title={down.message}>
        {QUIET[down.code] ?? "网速：读不到"}
        <TrafficUsage usage={usage} since={since} />
      </div>
    );
  }
  const f = freshness(lastOk, now, hidden);
  const cur = f === "live" ? last : null;
  const trend = history.filter(point => now - point.t <= HISTORY_MS).map(({ t, v }) => {
    const total = (a: number | null, b: number | null) => a === null || b === null ? null : a + b;
    return { t, down: total(v.down_domestic, v.down_foreign), up: total(v.up_domestic, v.up_foreign) };
  });
  const status =
    f === "live" ? `实时 · ${clock(lastOk!)}` : f === "paused" ? "数据暂停" : f === "stale" ? `数据暂停 · 数据已过期 · 更新于 ${clock(lastOk!)}` : "等待数据";
  return (
    <section className="traffic" data-testid="traffic-chart" data-state={down ? "unavailable" : f} aria-label="网速">
      <div className="traffic-head">
        <span className="traffic-title">网速</span>
        <span className="muted" data-testid="traffic-freshness">
          {down ? "数据暂停" : status}
          {down ? ` · ${QUIET[down.code] ?? "读不到"}` : ""}
        </span>
      </div>
      {trend.length > 1 && trend.some(point => point.down !== null || point.up !== null) ? <TrafficTrend points={trend} now={now} /> : null}
      <TrafficUsage usage={usage} since={since} />
      <TrafficStats rate={cur} conns={f === "live" ? conns : null} />
    </section>
  );
}
