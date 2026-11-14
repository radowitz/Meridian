// Build of the demo preview (development and acceptance only; see
// web/README.md 「演示预览」): its own HTML entry (demo.html → index.html),
// its own output directory (dist-demo/, never dist/), relative asset paths
// so any static file server can serve it offline. The production build
// (vite.config.ts → dist/) does not see demo.html or src/demo/.
import { renameSync } from "node:fs";
import { join } from "node:path";
import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

/** dist-demo/demo.html → dist-demo/index.html, so a static server opens it at "/". */
function demoIndex(): Plugin {
  return {
    name: "meridian-demo-index",
    apply: "build",
    enforce: "post",
    writeBundle(options) {
      const dir = options.dir ?? "dist-demo";
      renameSync(join(dir, "demo.html"), join(dir, "index.html"));
    },
  };
}

export default defineConfig({
  plugins: [react(), demoIndex()],
  base: "./",
  server: { port: 5174, strictPort: true },
  preview: { port: 4174, strictPort: true },
  build: {
    outDir: "dist-demo",
    emptyOutDir: true,
    sourcemap: false,
    rollupOptions: { input: "demo.html" },
    // The generated responses are large JSON chunks, loaded per scenario.
    chunkSizeWarningLimit: 4000,
  },
});
