// 使用说明: the one place for explanations. Pages carry none of their own;
// the header's question-mark button opens this guide at the current page's
// section (#/help/<page>). Sections follow the sidebar: first-level groups,
// then their pages, same names and order. The current page's section also
// holds the explanations its body would otherwise show (Note/Help, moved
// here through the shell's slot, see ui.tsx).

import { CloseOutlined } from "@ant-design/icons";
import { Button } from "antd";
import { useEffect, useRef, type ReactNode } from "react";

/** One explanation per page (trimmed from the pages' former descriptions). */
export const GUIDE_TEXT: Record<string, string> = {
  "": "网关、链路、出口和流量的当前状态；点各项进入对应页面。",
  setup:
    "新安装的第一次配置，进度保存在面板上，离开后回来从原来的步骤继续，已完成的步骤可以点回去修改；改了前面的步骤，后面依赖它的步骤、已保存的拓扑版本和预检结果要重新做。添加网关：网关在局域网里的网卡、地址（带前缀）和主路由器地址，地址按打开面板用的地址预填。选模板：直连出口、单中继、中继 + 枢纽、IX 专线四种路径。添加服务器：为每个节点新建或选择服务器；SSH 密码或私钥只存进面板的凭据库，不进浏览器；先核对主机指纹（与服务商控制台或 ssh-keyscan 的结果一致）再确认，确认后自动做连接测试，指纹变化要重新确认。生成拓扑：按模板生成并校验，保存后成为存储的拓扑。预检：只读检查网关，有阻断项不能继续。安装：打开部署页，安装仍在那里逐台预检并由你确认；向导不会自己安装任何东西。备用枢纽、备用中继等可选项以后在拓扑页添加。",
  topology: "节点和链路组成的路径：网关 → 中继 →（IX →）枢纽 → 出口。点节点或链路编辑；新建链路用「添加链路」、节点的「连接到…」，或从节点边缘拖到另一个节点。",
  exits: "管理按国家或地区分组的出口及其切换策略。规则指向地区组。",
  rules: "按从上到下的顺序匹配规则，保存后安装才生效。规则决定哪些域名或地址走哪个地区组或出口。",
  lists: "管理分流名单的来源与手动更新。没有定时任务，只有点击「立即更新」才会下载并发布名单。",
  dns: "配置境外名字经出口使用的解析上游，并查看解析路径与检查结果。",
  "dns-log": "查看设备向网关查询的名字与应答，记录默认关闭。",
  "conn-log": "每台设备经网关的嗅探转发服务建立过哪些 TCP 连接、去了哪里、结果如何。",
  "link-log": "网关的链路和路径什么时候从什么状态变成了什么状态：承载路径、中继分担、隧道握手、WSS 承载、外部出口和嗅探自检目标。",
  deploy: "把存储的拓扑装到网关、回滚，以及把配置下发到远端节点。所有页面的修改都要在这里安装后才生效。",
  unlock: "按地区查看各服务在各出口的解锁结果；「采用」把服务的规则指向推荐出口所在的地区组，并让该组优先这个出口。",
  servers: "管理远端主机的登录凭据、指纹与连接测试。",
  keys: "管理 SSH 与 SOCKS 凭据，保存后只能替换、不能再查看。",
  cloudflare: "WireGuard 架在 Mesh 上所用的 Cloudflare 账户，以及主机级 Mesh 节点与各条腿的部署和撤回。",
  remote: "管理经 WireGuard 连回家中的设备，改动安装到网关后生效。",
};

export interface GuideGroup {
  label: string | null;
  routes: { key: string; label: string }[];
}

/** The guide's section id of a page ("" is the overview). */
export const guideId = (page: string) => `help-${page || "overview"}`;

export function HelpGuide({
  groups,
  page,
  slot,
  onClose,
}: {
  groups: GuideGroup[];
  /** The page whose section opens (and receives the page's own explanations). */
  page: string;
  /** The shell's node holding the current page's moved explanations. */
  slot: HTMLElement;
  onClose: () => void;
}) {
  const host = useRef<HTMLDivElement>(null);
  const panel = useRef<HTMLElement>(null);
  useEffect(() => {
    const h = host.current;
    if (!h) return;
    h.appendChild(slot);
    return () => {
      if (slot.parentNode === h) h.removeChild(slot);
    };
  }, [slot, page]);
  useEffect(() => {
    const el = document.getElementById(guideId(page));
    el?.scrollIntoView?.({ block: "start" });
    (el?.querySelector("h3") as HTMLElement | null)?.focus();
  }, [page]);
  const sectionOf = (key: string, label: string, level: "h2" | "h3"): ReactNode => {
    const H = level;
    return (
      <section key={key || "overview"} id={guideId(key)} className="help-section" data-testid={`help-section-${key || "overview"}`} aria-current={key === page ? "true" : undefined}>
        <H tabIndex={-1} className="help-section-title">
          {label}
        </H>
        {GUIDE_TEXT[key] ? <p>{GUIDE_TEXT[key]}</p> : null}
        {key === page ? <div ref={host} className="help-page-details" /> : null}
      </section>
    );
  };
  return (
    <aside
      ref={panel}
      className="help-guide"
      role="dialog"
      aria-label="使用说明"
      data-testid="help-guide"
      onKeyDown={(e) => {
        if (e.key === "Escape") onClose();
      }}
    >
      <div className="help-guide-head">
        <h2 className="help-guide-title">使用说明</h2>
        <Button type="text" icon={<CloseOutlined />} aria-label="关闭使用说明" onClick={onClose} />
      </div>
      <div className="help-guide-body">
        {groups.map((g, i) =>
          g.label ? (
            <div key={`g${i}`} className="help-group">
              <h2 className="help-group-title">{g.label}</h2>
              {g.routes.map((r) => sectionOf(r.key, r.label, "h3"))}
            </div>
          ) : (
            g.routes.map((r) => sectionOf(r.key, r.label, "h3"))
          ),
        )}
      </div>
    </aside>
  );
}

/** The header's question-mark icon (SVG, inherits the text colour). */
export function HelpIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true" focusable="false">
      <circle cx="8" cy="8" r="7" fill="none" stroke="currentColor" strokeWidth="1.4" />
      <path d="M6.1 6.2a1.95 1.95 0 1 1 2.7 1.8c-.5.2-.8.6-.8 1.1v.4" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
      <circle cx="8" cy="11.6" r=".85" fill="currentColor" />
    </svg>
  );
}
