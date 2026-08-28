import type { DefinePluginPackageSpec } from "@caido/sdk-shared";

export type Result<T> =
  | { kind: "Ok"; value: T }
  | { kind: "Error"; error: string };

export function ok<T>(value: T): Result<T> {
  return { kind: "Ok", value };
}

export function err<T>(error: string): Result<T> {
  return { kind: "Error", error };
}

export type BridgeSettings = {
  enabled: boolean;
  bridgeHost: string;
  bridgePort: number;
  controlHost: string;
  controlPort: number;
  profileOverride: string;
};

export const DEFAULT_BRIDGE_SETTINGS: BridgeSettings = {
  enabled: true,
  bridgeHost: "127.0.0.1",
  bridgePort: 7777,
  controlHost: "127.0.0.1",
  controlPort: 9090,
  profileOverride: "",
};

export type DaemonStatus = {
  started_at: string;
  uptime_seconds: number;
  profile: string;
  profiles: string[];
  connections: number;
  requests: number;
  tls_fallbacks: number;
  config_path: string;
};

export type Spec = DefinePluginPackageSpec<{
  manifestId: "mimic-upstream";
  api: {
    getSettings: () => Promise<Result<BridgeSettings>>;
    saveSettings: (settings: BridgeSettings) => Promise<Result<BridgeSettings>>;
    getStatus: () => Promise<Result<DaemonStatus>>;
    useProfile: (name: string) => Promise<Result<DaemonStatus>>;
  };
  events: Record<string, never>;
}>;
