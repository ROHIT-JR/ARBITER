import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The dashboard talks to the FastAPI service through /api, proxied in dev and
// preview so no CORS configuration is needed on the backend.
const api = process.env.ARBITER_API ?? "http://127.0.0.1:8000";
const proxy = { "/api": { target: api, changeOrigin: true, rewrite: (p: string) => p.replace(/^\/api/, "") } };

export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy },
  preview: { port: 4173, proxy },
});
