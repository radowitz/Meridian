// Entry of the demo preview (web/demo.html, `npm run demo:build`): the real
// panel shell and pages, driven by synthetic responses generated from the
// Go handlers, with a permanent "演示数据" marker. A development and
// acceptance tool only: the production entry (src/main.tsx) never imports
// anything under src/demo/, and the production build, the Go binary and
// the Docker image do not contain or serve it (web/README.md 「演示预览」).
//
// URL: demo.html (or index.html of dist-demo)?scenario=<id>&theme=light|dark#/<page>

import React from "react";
import ReactDOM from "react-dom/client";
import App from "../App";
import "../styles.css";
import { installDemoFetch, makeDemoApi } from "./api";
import { DemoChrome } from "./chrome";
import { loadScenario } from "./fixtures";
import { DEMO_MARKER, SCENARIOS, readDemoParams } from "./scenarios";

const THEME_KEY = "meridian.theme"; // the panel's own preference key (App.tsx)

async function boot() {
  const params = readDemoParams(window.location.search);
  // The URL decides the theme, so a screenshot or an audit run is reproducible.
  try {
    if (params.theme === "system") localStorage.removeItem(THEME_KEY);
    else localStorage.setItem(THEME_KEY, params.theme);
  } catch {
    /* storage unavailable: the panel follows the system */
  }
  const responses = await loadScenario(params.scenario);
  const { gaps } = installDemoFetch(makeDemoApi(responses));
  // For the layout audit script (web/tools/ui-audit.js) and the console.
  (window as unknown as Record<string, unknown>).__meridianDemo = {
    marker: DEMO_MARKER,
    scenario: params.scenario,
    theme: params.theme,
    scenarios: SCENARIOS.map((s) => s.id),
    gaps,
  };
  document.documentElement.dataset.demo = params.scenario;
  ReactDOM.createRoot(document.getElementById("root")!).render(
    <React.StrictMode>
      <DemoChrome params={params} />
      <App />
    </React.StrictMode>,
  );
}

boot().catch((e: unknown) => {
  // Say so on the page instead of leaving it blank.
  const el = document.getElementById("root")!;
  el.style.cssText = "padding:24px;font:14px sans-serif;color:#a12424";
  el.textContent = `演示预览无法启动：${e instanceof Error ? e.message : String(e)}`;
});
