import type { Database } from "sqlite";

import {
  DEFAULT_BRIDGE_SETTINGS,
  type BridgeSettings,
} from "mimic-caido-shared";

export const DEFAULT_SETTINGS = DEFAULT_BRIDGE_SETTINGS;

type SettingsRow = { value: string };

function cloneSettings(settings: BridgeSettings): BridgeSettings {
  return { ...settings };
}

function normalizeLoopbackHost(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new Error(`${field} must be a string`);
  }
  const host = value.trim().toLowerCase();
  if (host === "[::1]") {
    return "::1";
  }
  if (host !== "localhost" && host !== "127.0.0.1" && host !== "::1") {
    throw new Error(`${field} must be localhost, 127.0.0.1, or ::1`);
  }
  return host;
}

function normalizePort(value: unknown, field: string): number {
  if (
    typeof value !== "number" ||
    !Number.isInteger(value) ||
    value < 1 ||
    value > 65535
  ) {
    throw new Error(`${field} must be an integer from 1 through 65535`);
  }
  return value;
}

function normalizeProfile(value: unknown): string {
  if (typeof value !== "string") {
    throw new Error("profileOverride must be a string");
  }
  const profile = value.trim();
  if (profile.length > 128 || /[\u0000-\u001f\u007f]/u.test(profile)) {
    throw new Error(
      "profileOverride must be at most 128 characters without control characters",
    );
  }
  return profile;
}

export function validateSettings(value: unknown): BridgeSettings {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("settings must be an object");
  }
  const input = value as Record<string, unknown>;
  if (typeof input.enabled !== "boolean") {
    throw new Error("enabled must be a boolean");
  }
  return {
    enabled: input.enabled,
    bridgeHost: normalizeLoopbackHost(input.bridgeHost, "bridgeHost"),
    bridgePort: normalizePort(input.bridgePort, "bridgePort"),
    controlHost: normalizeLoopbackHost(input.controlHost, "controlHost"),
    controlPort: normalizePort(input.controlPort, "controlPort"),
    profileOverride: normalizeProfile(input.profileOverride),
  };
}

export async function loadSettings(db: Database): Promise<BridgeSettings> {
  await db.exec(
    "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL)",
  );
  const statement = await db.prepare("SELECT value FROM settings WHERE key = ?");
  const row = await statement.get<SettingsRow>("bridge");
  if (row === undefined) {
    return cloneSettings(DEFAULT_SETTINGS);
  }
  return validateSettings(JSON.parse(row.value));
}

export async function persistSettings(
  db: Database,
  settings: BridgeSettings,
): Promise<void> {
  const statement = await db.prepare(
    "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
  );
  await statement.run("bridge", JSON.stringify(settings));
}

export class SettingsManager {
  readonly #db: Database;
  #settings: BridgeSettings;

  constructor(db: Database, settings: BridgeSettings) {
    this.#db = db;
    this.#settings = cloneSettings(settings);
  }

  get(): BridgeSettings {
    return cloneSettings(this.#settings);
  }

  async save(value: unknown): Promise<BridgeSettings> {
    const settings = validateSettings(value);
    await persistSettings(this.#db, settings);
    this.#settings = settings;
    return this.get();
  }
}

export async function createSettingsManager(
  db: Database,
): Promise<SettingsManager> {
  return new SettingsManager(db, await loadSettings(db));
}
