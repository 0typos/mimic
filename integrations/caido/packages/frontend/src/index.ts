import { createApp } from "vue";

import App from "./views/App.vue";
import type { FrontendSDK } from "./types.js";

export const init = (sdk: FrontendSDK): void => {
  const root = document.createElement("div");
  root.id = "mimic-upstream-root";
  Object.assign(root.style, { height: "100%", width: "100%", overflow: "auto" });

  createApp(App, { sdk }).mount(root);
  sdk.navigation.addPage("/mimic-upstream", { body: root });
  sdk.sidebar.registerItem("Mimic", "/mimic-upstream", {
    icon: "fas fa-fingerprint",
  });
};
