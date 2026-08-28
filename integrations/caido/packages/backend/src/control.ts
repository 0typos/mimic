import { Buffer } from "buffer";

import type { BridgeSettings, DaemonStatus } from "mimic-caido-shared";

const MAX_RESPONSE_BYTES = 1024 * 1024;

type ControlConnection = {
  send(bytes: string): Promise<void>;
  receive(size?: number): Promise<Uint8Array>;
};

export type ConnectControl = (url: string) => Promise<ControlConnection>;

type ControlResponse = {
  id?: unknown;
  result?: unknown;
  error?: unknown;
};

function endpointHost(host: string): string {
  return host.includes(":") ? `[${host}]` : host;
}

export function bridgeURL(settings: BridgeSettings): string {
  return `http://${endpointHost(settings.bridgeHost)}:${settings.bridgePort}`;
}

export function controlURL(settings: BridgeSettings): string {
  return `http://${endpointHost(settings.controlHost)}:${settings.controlPort}`;
}

function append(left: Uint8Array, right: Uint8Array): Uint8Array {
  const combined = new Uint8Array(left.length + right.length);
  combined.set(left);
  combined.set(right, left.length);
  return combined;
}

async function readLine(connection: ControlConnection): Promise<string> {
  let received: Uint8Array<ArrayBufferLike> = new Uint8Array();
  while (true) {
    const chunk = await connection.receive(16 * 1024);
    if (chunk.length === 0) {
      throw new Error("Mimic closed the control connection before replying");
    }
    received = append(received, chunk);
    if (received.length > MAX_RESPONSE_BYTES) {
      throw new Error("Mimic control response exceeded 1 MiB");
    }
    const newline = received.indexOf(10);
    if (newline >= 0) {
      return Buffer.from(received.slice(0, newline)).toString("utf8");
    }
  }
}

export async function callControl(
  connect: ConnectControl,
  settings: BridgeSettings,
  method: string,
  params: Record<string, unknown> = {},
): Promise<unknown> {
  const id = Date.now();
  const connection = await connect(controlURL(settings));
  await connection.send(`${JSON.stringify({ id, method, params })}\n`);
  const response = JSON.parse(await readLine(connection)) as ControlResponse;
  if (response.id !== id) {
    throw new Error("Mimic returned a mismatched control response");
  }
  if (typeof response.error === "string" && response.error !== "") {
    throw new Error(response.error);
  }
  if (!("result" in response)) {
    throw new Error("Mimic returned a control response without a result");
  }
  return response.result;
}

function requireNumber(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`Mimic status has invalid ${field}`);
  }
  return value;
}

export function parseDaemonStatus(value: unknown): DaemonStatus {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("Mimic returned an invalid status object");
  }
  const status = value as Record<string, unknown>;
  if (
    typeof status.started_at !== "string" ||
    typeof status.profile !== "string" ||
    typeof status.config_path !== "string" ||
    !Array.isArray(status.profiles) ||
    !status.profiles.every((profile) => typeof profile === "string")
  ) {
    throw new Error("Mimic returned incomplete status metadata");
  }
  return {
    started_at: status.started_at,
    uptime_seconds: requireNumber(status.uptime_seconds, "uptime_seconds"),
    profile: status.profile,
    profiles: [...status.profiles],
    connections: requireNumber(status.connections, "connections"),
    requests: requireNumber(status.requests, "requests"),
    tls_fallbacks: requireNumber(status.tls_fallbacks, "tls_fallbacks"),
    config_path: status.config_path,
  };
}

export async function getDaemonStatus(
  connect: ConnectControl,
  settings: BridgeSettings,
): Promise<DaemonStatus> {
  return parseDaemonStatus(await callControl(connect, settings, "status"));
}

export async function selectDaemonProfile(
  connect: ConnectControl,
  settings: BridgeSettings,
  name: string,
): Promise<DaemonStatus> {
  const profile = name.trim();
  if (profile === "") {
    throw new Error("profile name cannot be empty");
  }
  return parseDaemonStatus(
    await callControl(connect, settings, "profile.use", { name: profile }),
  );
}
