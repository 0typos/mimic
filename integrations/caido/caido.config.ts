import { defineConfig } from "@caido-community/dev";

export default defineConfig({
  id: "mimic-upstream",
  name: "Mimic Upstream",
  description: "Routes selected Caido upstream connections through the Mimic fingerprint engine.",
  version: "0.1.0",
  author: {
    name: "Mimic contributors",
    url: "https://github.com/msmythe/mimic",
  },
  plugins: [
    {
      kind: "backend",
      id: "backend",
      root: "packages/backend",
    },
  ],
});
