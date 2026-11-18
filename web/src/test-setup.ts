// Vitest setup (jsdom). Not imported by the app, so none of this is bundled.
import "@testing-library/jest-dom/vitest";
import { cleanup, configure } from "@testing-library/react";
import { afterEach, vi } from "vitest";
// The selector engine jsdom uses, as text (see installSelectorEngineCache).
import nwsapiSource from "nwsapi/src/nwsapi.js?raw";

// antd renders slowly in jsdom; give async queries room.
configure({ asyncUtilTimeout: 5000 });

// antd's responsive helpers and the theme toggle read matchMedia.
if (!window.matchMedia) {
  Object.defineProperty(window, "matchMedia", {
    writable: true,
    value: (query: string) => ({
      // Report a wide desktop screen so the sidebar layout renders.
      matches: /min-width/.test(query),
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }),
  });
}

// Node's own (experimental) web storage can shadow jsdom's and be unusable
// without --localstorage-file; give the tests a working in-memory Storage.
class MemoryStorage implements Storage {
  private m = new Map<string, string>();
  get length() {
    return this.m.size;
  }
  clear() {
    this.m.clear();
  }
  getItem(k: string) {
    return this.m.has(k) ? this.m.get(k)! : null;
  }
  key(i: number) {
    return [...this.m.keys()][i] ?? null;
  }
  removeItem(k: string) {
    this.m.delete(k);
  }
  setItem(k: string, v: string) {
    this.m.set(k, String(v));
  }
}
for (const name of ["localStorage", "sessionStorage"] as const) {
  let ok = false;
  try {
    ok = typeof window[name]?.getItem === "function";
  } catch {
    ok = false;
  }
  if (!ok) {
    const store = new MemoryStorage();
    Object.defineProperty(window, name, { configurable: true, value: store });
    Object.defineProperty(globalThis, name, { configurable: true, value: store });
  }
}

class RO {
  observe() {}
  unobserve() {}
  disconnect() {}
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).ResizeObserver ??= RO;

// jsdom does not implement pseudo-element styles; antd asks for them.
const gcs = window.getComputedStyle.bind(window);
window.getComputedStyle = ((el: Element) => gcs(el)) as typeof window.getComputedStyle;

// jsdom computes a style by testing the element against every rule of every
// stylesheet, through its selector engine (nwsapi). nwsapi keeps compiled
// selectors in an LRU cache of 1000 entries; antd's injected stylesheet has
// more distinct selectors than that, and the cascade walks them in the same
// order every time, so every lookup missed and every getComputedStyle call
// re-parsed and re-compiled every selector (about 25 ms per call; Testing
// Library's role queries call it for each candidate element on each waitFor
// poll). Measured, that was 80 % of the run time of the slowest tests; see
// "Front-end test time" in web/README.md.
//
// The fix: the nwsapi instance jsdom uses for that cascade
// (document._nwsapiDontThrow, created lazily by jsdom) is created here from
// the same nwsapi source with a cache large enough for the stylesheet. Same
// engine, same configuration as jsdom's; only the size of the cache of
// compiled selectors differs, which changes no match result.
installSelectorEngineCache(window, document);

function installSelectorEngineCache(win: Window & typeof globalThis, doc: Document) {
  const LIMIT = "CACHE_LIMIT = 1000,";
  if (!nwsapiSource.includes(LIMIT)) throw new Error("test-setup: nwsapi changed; review installSelectorEngineCache");
  const mod: { exports: unknown } = { exports: {} };
  new Function("module", "exports", nwsapiSource.replace(LIMIT, "CACHE_LIMIT = 100000,"))(mod, mod.exports);
  const factory = mod.exports as (g: { document: Document; DOMException: typeof DOMException }) => {
    configure: (o: Record<string, boolean>) => void;
  };
  const implKey = Object.getOwnPropertySymbols(doc).find((s) => s.description === "impl");
  const impl = implKey ? (doc as unknown as Record<symbol, Record<string, unknown>>)[implKey] : undefined;
  if (!impl) throw new Error("test-setup: jsdom changed; review installSelectorEngineCache");
  const engine = factory({ document: doc, DOMException: win.DOMException });
  // jsdom/lib/jsdom/living/helpers/selectors.js, matchesDontThrow
  engine.configure({ LOGERRORS: false, VERBOSITY: false, IDS_DUPES: true, MIXEDCASE: true });
  impl._nwsapiDontThrow = engine;
}

Element.prototype.scrollIntoView ??= function () {};

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  sessionStorage.clear();
  localStorage.clear();
  window.history.replaceState(null, "", "/");
});
