// Vitest setup (jsdom). Not imported by the app, so none of this is bundled.
import "@testing-library/jest-dom/vitest";
import { cleanup, configure } from "@testing-library/react";
import { afterEach, vi } from "vitest";

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

Element.prototype.scrollIntoView ??= function () {};

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  sessionStorage.clear();
  localStorage.clear();
  window.history.replaceState(null, "", "/");
});
