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

export const ALL_PAGES = ["", "topology", "exits", "rules", "lists", "dns", "dns-log", "conn-log", "link-log", "servers", "keys", "cloudflare", "remote", "deploy", "unlock"];

/** The three log pages. */
export const LOG_PAGES = ["dns-log", "conn-log", "link-log"];

export const SCENARIOS: DemoScenario[] = [
  {
    id: "healthy",
    label: "正常",
    summary:
      "宿主通道正常，已安装且与拓扑一致；两台国内中继按测得的质量分担；主枢纽状态刚读过，每个地区组都有实际成员；解锁结果新鲜；嗅探服务运行中；Mesh 备路已部署。三种日志都在记录：连接日志和解析日志有四台合成设备的记录、可以互相跳转，链路日志有一次 UDP 腿握手超时和一次外部出口自检失败，都已恢复。",
    pages: ALL_PAGES,
  },
  {
    id: "degraded",
    label: "降级",
    summary:
      "一台中继因丢包被剔除、另一台不通，备用枢纽承载；香港机房 1 健康检查失败；一个规则集下载失败、保留旧版；英国出口的解锁结果已过期；备用枢纽和香港机房 2 有待安装的改动；枢纽报告已过时；一台服务器连接测试超时；一台远程设备三天没有握手。三种日志带着观测缺口：嗅探服务被强行终止过；解析日志有读晚了没有 MAC 的记录和时间不确定的记录，解析器换成了没有核对过的版本；链路日志有采集空窗、空窗后才发现的变化、合并的抖动、读不到的来源和状态未知的对象。",
    pages: ALL_PAGES,
  },
  {
    id: "unavailable",
    label: "不可用（第一次运行）",
    summary: "没有宿主执行通道，什么都没有安装，没有服务器和密钥；拓扑是同一份合成拓扑。三种日志都读不到，各自说明原因。",
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
  {
    id: "deploy-verify",
    label: "引导部署：只需核对",
    summary:
      "备用枢纽承载时的一次引导：两个节点按顺序安装，另有三个只需核对的节点单独列出——一台已核对并采纳，一台连不上（不挡住其它），一台在限速等待。",
    pages: ["", "deploy"],
  },
  {
    id: "deploy-skipped",
    label: "引导部署：跳过被阻断的节点",
    summary:
      "一个出口预检被阻断、一个出口连不上，操作者跳过了它们；不依赖它们的出口继续安装，下一个出口此刻预检被阻断（可跳过，确认里列出会继续等待的节点）；枢纽和网关依赖被跳过的节点，继续等待并写明在等哪台。",
    pages: ["", "deploy"],
  },
  {
    id: "logs-off",
    label: "日志：关闭 / 没有安装",
    summary:
      "三种日志都没有在记录：按域名嗅探没有开启，所以没有连接日志；解析日志是默认的关闭状态（解析器已核对，可以打开）；链路日志的采集服务还没有随网关安装。每一页说明这是哪种状态、怎样才会有数据。",
    pages: LOG_PAGES,
  },
  {
    id: "logs-empty",
    label: "日志：在记录，还没有数据",
    summary: "三种日志都已安装并在运行，但还没有一条记录：没有连接结束，解析器的审计文件还是空的，链路日志只有基线、没有状态变化。",
    pages: LOG_PAGES,
  },
  { id: "preflight-blocked", label: "网关预检有阻断项", summary: "「部署」页的网关预检返回阻断项（FORWARD DROP、53 端口被占用等）。", pages: ["deploy"] },
  {
    id: "save-refused",
    label: "整份保存被拒",
    summary:
      "整份拓扑保存被服务端以 independent_resource_changed 拒绝（生成时请求里带了被改过的独立资源）。演示里任何「保存」都返回这条真实的拒绝：在拓扑或规则页改动后点「保存」查看。",
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
