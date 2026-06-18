// Vite config for the calabi daemon UI.
//
// Build target: a single-page React app embedded into the calabi
// binary via go:embed all:ui/dist. The Go status server serves it at
// http://127.0.0.1:7400/.
//
// Key choices:
//   - base: "./" so the built bundle works whether mounted at "/" or
//     at "/ui/" (Go embed FS is stripped at /ui/ for back-compat).
//   - outDir: relative "./dist" (default), matching the go:embed path.
//   - server.proxy: in `npm run dev`, proxy /v1, /tunnels, /healthz,
//     /logs to a locally running `calabi daemon` so we get the same
//     wire shape as production without re-implementing endpoints.

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  base: "./",
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
    // Embed budget: the Go binary grew from ~5MB to ~10MB with this
    // SPA. Antd is the bulk; tree-shaking + minify gets us under 1MB
    // gzipped which is acceptable for a local-only asset (browser
    // loads once, no CDN).
    chunkSizeWarningLimit: 1200,
  },
  server: {
    port: 5173,
    strictPort: true,
    // The daemon now refuses requests whose User-Agent doesn't include
    // "CalabiDesktop" (so a plain browser can't hit :7400 directly).
    // In `npm run dev`, Vite reverse-proxies to :7400 — without this
    // header override the proxied request carries the dev browser's
    // UA and gets 403'd. Production loads through the Tauri webview,
    // which already sets the marker via tauri.conf.json.
    proxy: (() => {
      const desktopUA = { "User-Agent": "CalabiDesktop-Vite/dev" };
      const t = "http://127.0.0.1:7400";
      return {
        "/v1":      { target: t, changeOrigin: false, headers: desktopUA },
        "/tunnels": { target: t, changeOrigin: false, headers: desktopUA },
        "/healthz": { target: t, changeOrigin: false, headers: desktopUA },
        "/logs":    { target: t, changeOrigin: false, headers: desktopUA },
        "/metrics": { target: t, changeOrigin: false, headers: desktopUA },
      };
    })(),
  },
});
