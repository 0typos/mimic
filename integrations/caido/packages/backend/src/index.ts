import type { DefineAPI, SDK } from "caido:plugin";
import { ConnectionInfo, type RequestSpecRaw } from "caido:utils";

import { createPreface } from "./preface.js";

const MIMIC_HOST = "127.0.0.1";
const MIMIC_PORT = 7777;
const PROFILE = "";

export type API = DefineAPI<Record<string, never>>;

export function init(sdk: SDK<API>): void {
  sdk.events.onUpstream(async (eventSDK, request: RequestSpecRaw) => {
    const info = new ConnectionInfo(`http://${MIMIC_HOST}:${MIMIC_PORT}`);
    info.tls = false;
    const connection = await eventSDK.net.connect(info);
    const preface = createPreface(
      `${request.getHost()}:${request.getPort()}`,
      request.getTls(),
      PROFILE,
    );
    await connection.send(preface);
    return { connection };
  });

  sdk.console.log(`Mimic upstream bridge ready at ${MIMIC_HOST}:${MIMIC_PORT}`);
}
