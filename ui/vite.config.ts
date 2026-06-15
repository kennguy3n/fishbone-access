import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    // Emit straight into the Go embed package so `go build -tags embed_ui`
    // (see internal/webui) ships the console inside the ztna-api binary as a
    // single deployable. The directory is git-ignored — it's a build artifact.
    outDir: path.resolve(__dirname, "../internal/webui/dist"),
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      // Dev convenience: proxy API calls to a locally-running
      // ztna-api (cmd/ztna-api, ACCESS_HTTP_ADDR defaults to :8080) so the
      // UI can be developed without CORS config.
      "/api": {
        target: process.env.ACCESS_API_PROXY ?? "http://localhost:8080",
        changeOrigin: true,
        ws: true,
      },
    },
  },
});
