import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/api": process.env.VITE_API_PROXY ?? "http://localhost:8000", "/swagger": process.env.VITE_API_PROXY ?? "http://localhost:8000" } },
});
