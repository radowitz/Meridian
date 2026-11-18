import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import { randomBytes } from "node:crypto";
import type { Plugin } from "vite";
import { vendorChunk } from "./chunks";

// Build id (docs/architecture.md「静态文件缓存与升级提示」): an opaque random
// value per production build, compiled into the bundle as __MERIDIAN_BUILD__
// and written next to index.html as version.json. The panel serves
// version.json with Cache-Control: no-cache and without the panel token;
// web/src/PanelUpdate.tsx compares it with the id the running bundle was
// built with. Not defined for the dev server or vitest (the check is off).
const BUILD_ID = randomBytes(9).toString("base64url");

function buildVersion(): Plugin {
  return {
    name: "meridian-build-version",
    apply: "build",
    generateBundle() {
      this.emitFile({ type: "asset", fileName: "version.json", source: JSON.stringify({ build: BUILD_ID }) + "\n" });
    },
  };
}

// Chunking (web/README.md「首屏与拆包」): third-party code is split by a rule
// on the module graph (chunks.ts): vendor-react, vendor-shell (what the
// entry needs), vendor-pages (what three or more lazy pages share); the rest
// travels with its pages. experimentalMinChunkSize folds the tiny shared
// chunks Rollup would otherwise emit (single icons, small helpers) into a
// neighbour, because the gateway serves every file over one connection.

export default defineConfig(({ command }) => ({
  plugins: [react(), buildVersion()],
  define: command === "build" ? { __MERIDIAN_BUILD__: JSON.stringify(BUILD_ID) } : {},
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8787",
    },
  },
  build: {
    outDir: "dist",
    // dist/.vite/manifest.json lists this build's hashed files; the panel
    // marks only those immutable (internal/api/static.go).
    manifest: true,
    sourcemap: false,
    // The largest chunk (vendor-pages) is about 600 kB before compression.
    chunkSizeWarningLimit: 700,
    rollupOptions: {
      output: {
        manualChunks: vendorChunk,
        experimentalMinChunkSize: 3000,
      },
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test-setup.ts"],
    include: ["src/**/*.test.tsx"],
    testTimeout: 30000,
    // CSS is not processed in tests, except the panel's own stylesheet: ui_layout.test.tsx reads it as text
    // (`styles.css?raw`) to guard the wrapping rules a browser found and jsdom cannot see.
    css: { include: [/\/src\/styles\.css/] },
  },
}));
