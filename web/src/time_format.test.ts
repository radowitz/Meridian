// Times on the panel read the same everywhere: "2026-11-24 23:50:41"
// (formatAbsolute / absTime / TimeText). The browser's toLocale*String
// follows the system language and gave "11/24/2026, 11:50:41 PM" on an
// English system.

import { describe, expect, it } from "vitest";

describe("dates are formatted by the panel, not by the browser locale", () => {
  const sources = import.meta.glob(["./*.ts", "./*.tsx", "./demo/*.ts", "!./*.test.ts", "!./*.test.tsx"], { query: "?raw", import: "default", eager: true }) as Record<string, string>;
  it("no Date#toLocaleString / toLocaleTimeString / toLocaleDateString", () => {
    const bad: string[] = [];
    for (const [file, src] of Object.entries(sources)) {
      for (const m of src.matchAll(/new Date\([^)]*\)\s*\.\s*toLocale(?:Date|Time)?String\(/g)) bad.push(`${file}: ${m[0]}`);
      for (const m of src.matchAll(/\.toLocale(?:Date|Time)String\(/g)) bad.push(`${file}: ${m[0]}`);
    }
    // Use formatAbsolute(new Date(x)) (ui.tsx), absTime(x) (log_common.tsx) or <TimeText value={x} />.
    expect(bad).toEqual([]);
  });
});
