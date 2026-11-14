// Scenarios of the demo preview (development and acceptance only; never
// part of the production panel). Each one is a set of responses generated
// from the real Go handlers on synthetic data (internal/api/
// demo_fixtures_test.go, web/src/demo/generated/*.json); see web/README.md
// 「演示预览」 and docs/ui-layout.md.

/** Present in every demo bundle and page; never in the production build (demo.test.tsx checks). */
export const DEMO_MARKER = "MERIDIAN-DEMO-PREVIEW";

export interface DemoScenario {
  id: string;
  /** Short label for the scenario bar. */
  label: string;
  /** What the scenario shows. */
  summary: string;
  /** Pages (hash keys, "" = overview) where it differs from its base scenario. */
  pages: string[];
}

export const ALL_PAGES = ["", "topology", "exits", "rules", "lists", "servers", "keys", "cloudflare", "remote", "deploy", "unlock", "leak"];

export const SCENARIOS: DemoScenario[] = [
  {
    id: "healthy",
    label: "正常",
    summary:
      "宿主通道正常，已安装且与拓扑一致；两台国内中继按测得的质量分担；主枢纽状态刚读过，每个地区组都有实际成员；解锁结果新鲜；嗅探服务运行中；Mesh 备路已部署。",
    pages: ALL_PAGES,
  },
  {
    id: "degraded",
    label: "降级",
    summary:
      "一台中继因丢包被剔除、另一台不通，备用枢纽承载；香港机房 1 健康检查失败；一个规则集下载失败、保留旧版；英国出口的解锁结果已过期；备用枢纽和香港机房 2 有待安装的改动；枢纽报告已过时；一台服务器连接测试超时；一台远程设备三天没有握手。",
    pages: ALL_PAGES,
  },
  {
    id: "unavailable",
    label: "不可用（第一次运行）",
    summary: "没有宿主执行通道，什么都没有安装，没有服务器和密钥；拓扑是同一份合成拓扑。",
    pages: ALL_PAGES,
  },
  { id: "deploy-running", label: "引导部署：进行中", summary: "按序部署引导运行中：第一个出口已安装，第二个正在下发。", pages: ["", "deploy"] },
  {
    id: "deploy-rate-limited",
    label: "引导部署：限速等待",
    summary: "服务器在 SSH 横幅之前拒绝了面板的地址：这一步在 retry_after 之前不再连接。",
    pages: ["", "deploy"],
  },
  { id: "deploy-compensated", label: "引导部署：失败已补偿", summary: "一个出口装机失败并已补偿，运行停止。", pages: ["", "deploy"] },
  { id: "deploy-unknown", label: "引导部署：结果不明", summary: "一个出口的回答无法读取：结果不明，运行停止。", pages: ["", "deploy"] },
  {
    id: "deploy-done",
    label: "引导部署：完成（安装 + 采纳）",
    summary: "运行完成：四个节点在本次运行中安装，一个依据服务器上的安装记录采纳。",
    pages: ["", "deploy"],
  },
  { id: "preflight-blocked", label: "网关预检有阻断项", summary: "「部署」页的网关预检返回阻断项（FORWARD DROP、53 端口被占用等）。", pages: ["deploy"] },
  {
    id: "save-refused",
    label: "整份保存被拒",
    summary:
      "整份拓扑保存被服务端以 independent_resource_changed 拒绝（生成时请求里带了被改过的服务组）。演示里任何「保存」都返回这条真实的拒绝：在拓扑或规则页改动后点「保存」查看。",
    pages: ["topology", "rules"],
  },
];

export type DemoTheme = "light" | "dark" | "system";

export interface DemoParams {
  scenario: string;
  theme: DemoTheme;
}

/** `?scenario=<id>&theme=light|dark` (the panel's own route stays in the hash). */
export function readDemoParams(search: string): DemoParams {
  const q = new URLSearchParams(search);
  const s = q.get("scenario") || "healthy";
  const t = q.get("theme");
  return {
    scenario: SCENARIOS.some((x) => x.id === s) ? s : "healthy",
    theme: t === "light" || t === "dark" ? t : "system",
  };
}

/** The demo URL for a scenario and theme, keeping the current page hash. */
export function demoHref(p: DemoParams, hash: string, path = ""): string {
  const q = new URLSearchParams();
  q.set("scenario", p.scenario);
  if (p.theme !== "system") q.set("theme", p.theme);
  return `${path}?${q.toString()}${hash || "#/"}`;
}

export function scenarioOf(id: string): DemoScenario {
  return SCENARIOS.find((s) => s.id === id) ?? SCENARIOS[0];
}
