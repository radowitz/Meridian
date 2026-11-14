// The demo's permanent marker: a bar fixed at the bottom of the window
// ("演示数据", the scenario, scenario and theme pickers) and a faint
// watermark over the whole page, so that no screenshot of the demo can be
// taken for a real panel. Plain elements with inline styles: nothing here
// depends on the panel's theme or components.

import { useEffect, useRef, type CSSProperties } from "react";
import { DEMO_MARKER, SCENARIOS, demoHref, scenarioOf, type DemoParams, type DemoTheme } from "./scenarios";

const BAR_HEIGHT = 36;

const bar: CSSProperties = {
  position: "fixed",
  left: 0,
  right: 0,
  bottom: 0,
  zIndex: 2147483000,
  minHeight: BAR_HEIGHT,
  boxSizing: "border-box",
  display: "flex",
  flexWrap: "wrap",
  alignItems: "center",
  gap: "4px 12px",
  padding: "4px 12px",
  background: "repeating-linear-gradient(135deg, #8a1c1c 0 12px, #a12424 12px 24px)",
  color: "#fff",
  font: '13px/1.4 -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif',
  boxShadow: "0 -2px 6px rgba(0,0,0,.25)",
};

const badge: CSSProperties = { fontWeight: 700, letterSpacing: 2, padding: "1px 8px", border: "2px solid #fff", borderRadius: 4, whiteSpace: "nowrap" };
const select: CSSProperties = { font: "inherit", maxWidth: "100%", color: "#222", background: "#fff", borderRadius: 4, border: 0, padding: "1px 4px" };

// A repeated diagonal "演示数据 · 合成场景" as an inline SVG (no external resource).
const MARK_SVG =
  "data:image/svg+xml;charset=utf-8," +
  encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" width="360" height="200"><text x="20" y="120" transform="rotate(-24 180 100)" ' +
      'font-family="sans-serif" font-size="26" font-weight="700" fill="#c0392b" fill-opacity="0.06">演示数据 · 合成场景</text></svg>',
  );

const watermark: CSSProperties = {
  position: "fixed",
  inset: 0,
  zIndex: 2147482999,
  pointerEvents: "none",
  backgroundImage: `url("${MARK_SVG}")`,
  backgroundRepeat: "repeat",
};

function go(p: DemoParams) {
  window.location.href = demoHref(p, window.location.hash, window.location.pathname);
}

export function DemoChrome({ params }: { params: DemoParams }) {
  const sc = scenarioOf(params.scenario);
  const barRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    // Room for the bar below the page (it wraps on narrow windows); the
    // title always says it is a demo.
    const pad = () => {
      document.body.style.paddingBottom = `${Math.max(BAR_HEIGHT, barRef.current?.offsetHeight ?? 0) + 8}px`;
    };
    pad();
    const ro = typeof ResizeObserver === "function" && barRef.current ? new ResizeObserver(pad) : null;
    if (ro && barRef.current) ro.observe(barRef.current);
    const mark = () => {
      if (!document.title.startsWith("【演示】")) document.title = `【演示】${document.title}`;
    };
    mark();
    const titleEl = document.querySelector("title");
    const mo = titleEl ? new MutationObserver(mark) : null;
    if (titleEl) mo!.observe(titleEl, { childList: true, characterData: true, subtree: true });
    return () => {
      mo?.disconnect();
      ro?.disconnect();
    };
  }, []);
  return (
    <>
      <div style={watermark} data-demo-chrome="watermark" aria-hidden="true" />
      <div ref={barRef} style={bar} role="region" aria-label="演示数据说明" data-demo-chrome="bar" data-marker={DEMO_MARKER}>
        <span style={badge}>演示数据</span>
        <span style={{ whiteSpace: "nowrap" }}>合成场景，不是真实网关；改动不会执行</span>
        <label style={{ display: "inline-flex", alignItems: "center", gap: 4, minWidth: 0 }}>
          <span style={{ whiteSpace: "nowrap" }}>场景</span>
          <select aria-label="演示场景" style={select} value={sc.id} title={sc.summary} onChange={(e) => go({ ...params, scenario: e.target.value })}>
            {SCENARIOS.map((s) => (
              <option key={s.id} value={s.id}>
                {s.label}
              </option>
            ))}
          </select>
        </label>
        <label style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
          <span style={{ whiteSpace: "nowrap" }}>主题</span>
          <select aria-label="演示主题" style={select} value={params.theme} onChange={(e) => go({ ...params, theme: e.target.value as DemoTheme })}>
            <option value="system">跟随系统</option>
            <option value="light">浅色</option>
            <option value="dark">深色</option>
          </select>
        </label>
        <span style={{ opacity: 0.85, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: "1 1 200px", minWidth: 0 }} title={sc.summary}>
          {sc.summary}
        </span>
      </div>
    </>
  );
}
