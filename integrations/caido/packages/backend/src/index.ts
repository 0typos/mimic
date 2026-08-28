import type { SDK } from "caido:plugin";
import { ConnectionInfo, type RequestSpecRaw } from "caido:utils";
import { err, ok, type BridgeSettings, type Spec } from "mimic-caido-shared";

import { bridgeURL, getDaemonStatus, selectDaemonProfile } from "./control.js";
import { createPreface } from "./preface.js";
import { createSettingsManager, type SettingsManager } from "./settings.js";

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function connectControl(sdk: SDK<Spec>) {
  return (url: string) => sdk.net.connect(url);
}

export function init(sdk: SDK<Spec>): void {
  const managerPromise: Promise<SettingsManager> = sdk.meta
    .db()
    .then(createSettingsManager);

  sdk.api.register("getSettings", async () => {
    try {
      return ok((await managerPromise).get());
    } catch (error) {
      return err(message(error));
    }
  });

  sdk.api.register("saveSettings", async (_apiSDK, settings: BridgeSettings) => {
    try {
      return ok(await (await managerPromise).save(settings));
    } catch (error) {
      return err(message(error));
    }
  });

  sdk.api.register("getStatus", async (apiSDK) => {
    try {
      const settings = (await managerPromise).get();
      return ok(await getDaemonStatus(connectControl(apiSDK), settings));
    } catch (error) {
      return err(message(error));
    }
  });

  sdk.api.register("useProfile", async (apiSDK, name: string) => {
    try {
      const settings = (await managerPromise).get();
      return ok(await selectDaemonProfile(connectControl(apiSDK), settings, name));
    } catch (error) {
      return err(message(error));
    }
  });

  sdk.events.onUpstream(async (eventSDK, request: RequestSpecRaw) => {
    let settings: BridgeSettings;
    try {
      settings = (await managerPromise).get();
    } catch (error) {
      eventSDK.console.warn(`Mimic settings unavailable: ${message(error)}`);
      return undefined;
    }
    if (!settings.enabled) {
      return undefined;
    }

    const info = new ConnectionInfo(bridgeURL(settings));
    info.tls = false;
    const connection = await eventSDK.net.connect(info);
    const preface = createPreface(
      `${request.getHost()}:${request.getPort()}`,
      request.getTls(),
      settings.profileOverride,
    );
    await connection.send(preface);
    return { connection };
  });

  void managerPromise
    .then((manager) => {
      const settings = manager.get();
      sdk.console.log(`Mimic upstream bridge ready at ${bridgeURL(settings)}`);
    })
    .catch((error) => sdk.console.error(`Mimic settings failed: ${message(error)}`));
}
