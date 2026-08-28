import { defineConfig } from "@caido-community/dev";
import vue from "@vitejs/plugin-vue";

export default defineConfig({
  id: "mimic-upstream",
  name: "Mimic Upstream",
  description:
    "Routes selected Caido upstream connections through Mimic with live status and profile control.",
  version: "0.2.0",
  author: {
    name: "Mimic contributors",
    url: "https://github.com/0typos/mimic",
  },
  plugins: [
    {
      kind: "backend",
      id: "backend",
      root: "packages/backend",
    },
    {
      kind: "frontend",
      id: "frontend",
      root: "packages/frontend",
      backend: {
        id: "backend",
      },
      vite: {
        plugins: [vue()],
      },
    },
  ],
});
