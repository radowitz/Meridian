// Real-time throughput on the overview: polls GET /api/traffic every 2 s
// while the page is visible, turns consecutive counter samples into rates
// (a reset sample is a new baseline, never a rate) and shows the current
// download / upload rates (domestic / foreign) and active connections.

import { useEffect, useRef, useState, type ReactNode } from "react";
import * as api from "./api";
import type { TrafficConnections, TrafficKey, TrafficView } from "./types";

export const POLL_MS = 2000;
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
  counters: TrafficView["counters"];
}

/** The sample to keep as baseline, or null when the answer carries no counters. */
export function sampleOf(v: TrafficView): Sample | null {
  if (!v.available || !v.read_at) return null;
  const t = Date.parse(v.read_at);
  return Number.isFinite(t) ? { t, counters: v.counters } : null;
}

/**
 * The rate between the previous sample and this answer. Null when there is
 * no previous sample, the answer is a reset (new baseline), time did not
 * advance, or every counter went backwards.
 */
export function rateBetween(prev: Sample | null, cur: TrafficView): RatePoint | null {
  const s = sampleOf(cur);
  if (!prev || !s || cur.reset) return null;
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

const clock = (t: number) => new Date(t).toLocaleTimeString([], { hour12: false });

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

const QUIET: Record<string, string> = {
  not_installed: "网速：数据面还没装计数器",
  agent_unavailable: "网速：宿主通道不可用",
  read_failed: "网速：读取失败",
};

export default function TrafficChart() {
  const [last, setLast] = useState<RatePoint | null>(null);
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
      try {
        const v = await api.getTraffic(ctl.signal);
        if (stop) return;
        const t = Date.now();
        setConns(v.connections ?? null);
        if (!v.available) {
          setDown({ code: v.code ?? "read_failed", message: v.message });
          prev.current = null;
          setLast(null);
          if (v.connections?.available) setLastOk(t);
        } else {
          setDown(null);
          const p = rateBetween(prev.current, v);
          prev.current = sampleOf(v);
          // Rates use the gateway's read_at; freshness uses this browser's clock (no skew).
          // No valid rate (reset, missing counters, first sample): show —, never an old rate.
          setLast(p);
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
      }
      if (!stop) timer = setTimeout(() => void tick(), POLL_MS);
    };
    void tick();
    return () => {
      stop = true;
      ctl.abort();
      clearInterval(clockTimer);
      if (timer) clearTimeout(timer);
    };
  }, [hidden]);

  if (down && !last && !conns?.available) {
    return (
      <div className="traffic-quiet" data-testid="traffic-chart" data-state="unavailable" title={down.message}>
        {QUIET[down.code] ?? "网速：读不到"}
      </div>
    );
  }
  const f = freshness(lastOk, now, hidden);
  const cur = f === "live" ? last : null;
  const status =
    f === "live" ? `实时 · ${clock(lastOk!)}` : f === "paused" ? "已暂停" : f === "stale" ? `过期 · 更新于 ${clock(lastOk!)}` : "等待数据";
  return (
    <section className="traffic" data-testid="traffic-chart" data-state={f} aria-label="网速">
      <div className="traffic-head">
        <span className="traffic-title">网速</span>
        <span className="muted" data-testid="traffic-freshness">
          {status}
          {down ? ` · ${QUIET[down.code] ?? "读不到"}` : ""}
        </span>
      </div>
      <TrafficStats rate={cur} conns={f === "live" ? conns : null} />
    </section>
  );
}
