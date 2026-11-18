// Panel theme: one palette per scheme, shared by the antd ConfigProvider
// (App.tsx) and the CSS custom properties in styles.css (`--m-*`). The two
// are kept in step by theme.test.ts. Light: cool gray page, white surfaces,
// thin borders, blue-cyan accent. Dark: slate "tech" palette. Status colours
// (ok / warn / bad) are for status only. Every text colour meets 4.5:1 on
// the backgrounds it sits on (checked in theme.test.ts). System fonts only.

import { theme as antdTheme, type ThemeConfig } from "antd";

export const FONT =
  '-apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", "Noto Sans SC", "Source Han Sans SC", sans-serif';
export const MONO = 'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace';

export interface Palette {
  bg: string; // page
  surface: string; // cards, header, sider
  surface2: string; // table head, subtle fills
  border: string;
  borderStrong: string;
  text: string;
  text2: string;
  accent: string;
  onAccent: string; // text on accent / status fills
  ok: string;
  warn: string;
  bad: string;
}

export const PALETTE: Record<"light" | "dark", Palette> = {
  light: {
    bg: "#f4f6f9",
    surface: "#ffffff",
    surface2: "#f1f4f8",
    border: "#e2e7ee",
    borderStrong: "#cbd3de",
    text: "#0f172a",
    text2: "#475569",
    accent: "#0369a1",
    onAccent: "#ffffff",
    ok: "#15803d",
    warn: "#b45309",
    bad: "#b91c1c",
  },
  dark: {
    bg: "#0b1120",
    surface: "#111827",
    surface2: "#172033",
    border: "#1f2a3c",
    borderStrong: "#334155",
    text: "#e2e8f0",
    text2: "#94a3b8",
    accent: "#38bdf8",
    onAccent: "#0b1120",
    ok: "#4ade80",
    warn: "#fbbf24",
    bad: "#f87171",
  },
};

export function themeConfig(dark: boolean): ThemeConfig {
  const p = PALETTE[dark ? "dark" : "light"];
  return {
    algorithm: dark ? antdTheme.darkAlgorithm : antdTheme.defaultAlgorithm,
    token: {
      colorPrimary: p.accent,
      colorInfo: p.accent,
      colorLink: p.accent,
      colorSuccess: p.ok,
      colorWarning: p.warn,
      colorError: p.bad,
      colorTextLightSolid: p.onAccent,
      colorText: p.text,
      colorTextSecondary: p.text2,
      colorTextDescription: p.text2,
      colorBgLayout: p.bg,
      colorBgContainer: p.surface,
      colorBgElevated: p.surface,
      colorBorder: p.borderStrong,
      colorBorderSecondary: p.border,
      borderRadius: 6,
      borderRadiusLG: 8,
      fontSize: 14,
      fontSizeSM: 12,
      fontFamily: FONT,
      fontFamilyCode: MONO,
      boxShadow: "none",
      boxShadowSecondary: dark ? "0 4px 16px rgba(0, 0, 0, 0.5)" : "0 4px 16px rgba(15, 23, 42, 0.08)",
      motionDurationMid: "0.15s",
      motionDurationSlow: "0.2s",
    },
    components: {
      Layout: {
        headerBg: p.surface,
        siderBg: p.surface,
        bodyBg: p.bg,
        headerHeight: 56,
        headerPadding: "0 16px",
      },
      Menu: { itemBg: "transparent", subMenuItemBg: "transparent", itemBorderRadius: 6, itemHeight: 36 },
      Table: { cellPaddingBlock: 10, cellPaddingInline: 12, headerBg: p.surface2, borderColor: p.border },
      Card: { colorBorderSecondary: p.border },
      Drawer: { footerPaddingBlock: 12 },
    },
  };
}

/** WCAG relative-luminance contrast ratio of two #rrggbb colours. */
export function contrast(a: string, b: string): number {
  const lum = (hex: string) => {
    const c = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
    return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
  };
  const [x, y] = [lum(a), lum(b)].sort((m, n) => n - m);
  return (x + 0.05) / (y + 0.05);
}
