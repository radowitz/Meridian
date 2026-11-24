// The panel theme: CSS tokens in styles.css equal the antd palette in
// theme.ts, text meets 4.5:1 in both schemes, and the stylesheets carry no
// external fonts or stray hard-coded colours.

import { describe, expect, it } from "vitest";
import styles from "./styles.css?raw";
import layoutB from "./layout_b.css?raw";
import layoutC from "./layout_c.css?raw";
import { PALETTE, STATUS_FILLS, contrast, themeConfig, type Palette } from "./theme";

const VAR: Record<keyof Palette, string> = {
  bg: "--m-bg",
  surface: "--m-surface",
  surface2: "--m-surface-2",
  border: "--m-border",
  borderStrong: "--m-border-strong",
  text: "--m-text",
  text2: "--m-text-2",
  accent: "--m-accent",
  onAccent: "--m-on-accent",
  ok: "--m-ok",
  warn: "--m-warn",
  bad: "--m-bad",
};

function block(selector: string): string {
  const i = styles.indexOf(`${selector} {`);
  expect(i).toBeGreaterThanOrEqual(0);
  return styles.slice(i, styles.indexOf("}", i));
}

function value(css: string, name: string): string | undefined {
  return new RegExp(`${name}:\\s*(#[0-9a-fA-F]{6})\\s*;`).exec(css)?.[1]?.toLowerCase();
}

describe("theme tokens", () => {
  const blocks = { light: block(':root,\n[data-theme="light"]'), dark: block('[data-theme="dark"]') };

  for (const scheme of ["light", "dark"] as const) {
    const p = PALETTE[scheme];
    it(`${scheme}: CSS variables mirror theme.ts`, () => {
      for (const [k, v] of Object.entries(VAR)) expect([v, value(blocks[scheme], v)]).toEqual([v, p[k as keyof Palette]]);
    });
    it(`${scheme}: text and status colours reach 4.5:1`, () => {
      for (const bg of [p.bg, p.surface, p.surface2]) {
        for (const fg of [p.text, p.text2, p.accent, p.ok, p.warn, p.bad]) expect(contrast(fg, bg)).toBeGreaterThanOrEqual(4.5);
      }
      for (const fill of [p.accent, p.ok, p.bad]) expect(contrast(p.onAccent, fill)).toBeGreaterThanOrEqual(4.5);
    });
    it(`${scheme}: antd config uses the palette`, () => {
      const t = themeConfig(scheme === "dark").token!;
      expect([t.colorPrimary, t.colorBgLayout, t.colorBgContainer, t.colorText, t.colorTextLightSolid]).toEqual([p.accent, p.bg, p.surface, p.text, p.onAccent]);
    });
  }

  it("no external fonts; colours outside the token blocks are tokens", () => {
    for (const css of [styles, layoutB, layoutC]) expect(css).not.toMatch(/@import|@font-face|fonts\.googleapis/);
    const rest = styles.slice(styles.indexOf("* { box-sizing"));
    // Allowed: the QR code's white quiet zone (scanners need it) and the React Flow minimap mask.
    const stray = (rest.match(/#[0-9a-fA-F]{3,8}\b|rgba?\([^)]*\)/g) ?? []).filter((c) => c !== "#fff" && c !== "rgba(11, 17, 32, 0.6)");
    expect(stray).toEqual([]);
    expect((layoutB + layoutC).match(/#[0-9a-fA-F]{3,8}\b|rgba?\(/g)).toBeNull();
  });

  for (const scheme of ["light", "dark"] as const) {
    it(`${scheme}: status fills mirror styles.css and keep status text readable`, () => {
      const f = STATUS_FILLS[scheme];
      const p = PALETTE[scheme];
      const css = { ok: ["--m-ok-bg", "--m-ok-border"], warn: ["--m-warn-bg", "--m-warn-border"], bad: ["--m-bad-bg", "--m-bad-border"], info: ["--m-info-bg", "--m-info-border"] } as const;
      for (const k of ["ok", "warn", "bad", "info"] as const) {
        expect([k, value(blocks[scheme], css[k][0])]).toEqual([k, f[k].bg]);
        expect([k, value(blocks[scheme], css[k][1])]).toEqual([k, f[k].border]);
      }
      for (const [fg, k] of [[p.ok, "ok"], [p.warn, "warn"], [p.bad, "bad"], [p.text, "info"]] as const) {
        expect([k, contrast(fg, f[k].bg) >= 4.5]).toEqual([k, true]);
      }
    });
  }
});
