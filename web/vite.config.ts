import { defineConfig, type Plugin } from "vite";
/// <reference types="vitest" />
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";
import { writeFileSync } from "fs";

// Vite's emptyOutDir deletes .gitkeep before writing build output.
// This plugin restores it after the build so git tracks the directory.
function restoreGitkeep(): Plugin {
  return {
    name: "restore-gitkeep",
    closeBundle() {
      writeFileSync(path.resolve(__dirname, "../internal/web/dist/.gitkeep"), "");
    },
  };
}

export default defineConfig({
  plugins: [react(), tailwindcss(), restoreGitkeep()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    outDir: "../internal/web/dist",
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": "http://localhost:3000",
    },
  },
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: "./src/test/setup.ts",
  },
});
