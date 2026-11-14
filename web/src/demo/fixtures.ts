// The demo's responses: web/src/demo/generated/<scenario>.json, written by
// the Go handlers on synthetic data (internal/api/demo_fixtures_test.go;
// regenerate with `npm run demo:fixtures`). Nothing here is hand-written.
//
// Every time in the files is an offset from a fixed anchor; loading shifts
// them so that the anchor is "now", which keeps the relative ages the
// handlers produced (a result checked 3 days ago still reads "3 天前").

export interface DemoResponse {
  status: number;
  body: unknown;
}

export interface DemoFixtureFile {
  scenario: string;
  /** The full scenario this one is applied to ("" for a full one). */
  base: string;
  anchor: string;
  generator: string;
  /** "METHOD /path" (detail reads include the object id) → response. */
  responses: Record<string, DemoResponse>;
}

// Lazy: only the chosen scenario and its base are loaded.
const files = import.meta.glob<DemoFixtureFile>("./generated/*.json", { import: "default" });

function loaderOf(id: string) {
  return files[`./generated/${id}.json`];
}

export function hasFixture(id: string): boolean {
  return !!loaderOf(id);
}

async function load(id: string): Promise<DemoFixtureFile> {
  const l = loaderOf(id);
  if (!l) throw new Error(`demo: no fixture file for scenario ${id}`);
  return l();
}

const TIME = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})/g;

function shiftValue(v: unknown, offset: number): unknown {
  if (typeof v === "string") {
    return v.replace(TIME, (m) => {
      const t = Date.parse(m);
      return Number.isNaN(t) ? m : new Date(t + offset).toISOString().replace(/\.\d{3}Z$/, "Z");
    });
  }
  if (Array.isArray(v)) return v.map((x) => shiftValue(x, offset));
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v)) out[k] = shiftValue(x, offset);
    return out;
  }
  return v;
}

/** Every response of a scenario (its base's, then its own), times shifted so that the anchor is `now`. */
export async function loadScenario(id: string, now = Date.now()): Promise<Record<string, DemoResponse>> {
  const doc = await load(id);
  const base = doc.base ? await load(doc.base) : null;
  const merged: Record<string, DemoResponse> = { ...(base?.responses ?? {}), ...doc.responses };
  const offset = Math.floor(now / 1000) * 1000 - Date.parse(doc.anchor);
  const out: Record<string, DemoResponse> = {};
  for (const [k, r] of Object.entries(merged)) out[k] = { status: r.status, body: shiftValue(r.body, offset) };
  return out;
}
