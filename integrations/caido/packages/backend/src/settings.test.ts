import assert from "node:assert/strict";
import test from "node:test";

import type { Database, Statement } from "sqlite";

import type { BridgeSettings } from "mimic-caido-shared";

import {
  createSettingsManager,
  DEFAULT_SETTINGS,
  loadSettings,
  persistSettings,
  validateSettings,
} from "./settings.js";

type FakeDatabase = Database & {
  executed: string[];
  stored?: string;
  failWrites: boolean;
};

function fakeDatabase(stored?: unknown): FakeDatabase {
  const db = {
    executed: [] as string[],
    stored: stored === undefined ? undefined : JSON.stringify(stored),
    failWrites: false,
    exec: async (sql: string) => {
      db.executed.push(sql);
    },
    prepare: async (sql: string) =>
      ({
        all: async () => [],
        get: async () =>
          sql.startsWith("SELECT") && db.stored !== undefined ? { value: db.stored } : undefined,
        run: async (_key: string, value: string) => {
          if (db.failWrites) {
            throw new Error("disk full");
          }
          db.stored = value;
          return { changes: 1, lastInsertRowid: 1 };
        },
      }) as Statement,
  } as FakeDatabase;
  return db;
}

test("validateSettings normalizes safe loopback settings", () => {
  assert.deepEqual(
    validateSettings({
      ...DEFAULT_SETTINGS,
      bridgeHost: " LOCALHOST ",
      controlHost: "[::1]",
      profileOverride: " firefox-154-linux ",
    }),
    {
      ...DEFAULT_SETTINGS,
      bridgeHost: "localhost",
      controlHost: "::1",
      profileOverride: "firefox-154-linux",
    },
  );
});

test("validateSettings rejects unsafe or malformed settings", async (t) => {
  const cases: Array<[string, unknown, RegExp]> = [
    ["non-object", null, /object/],
    ["enabled", { ...DEFAULT_SETTINGS, enabled: "yes" }, /boolean/],
    ["remote bridge", { ...DEFAULT_SETTINGS, bridgeHost: "example.com" }, /loopback|localhost/],
    ["remote control", { ...DEFAULT_SETTINGS, controlHost: "10.0.0.1" }, /loopback|localhost/],
    ["small port", { ...DEFAULT_SETTINGS, bridgePort: 0 }, /1 through 65535/],
    ["large port", { ...DEFAULT_SETTINGS, controlPort: 65536 }, /1 through 65535/],
    ["fractional port", { ...DEFAULT_SETTINGS, bridgePort: 7.7 }, /integer/],
    ["profile type", { ...DEFAULT_SETTINGS, profileOverride: 7 }, /string/],
    ["profile control", { ...DEFAULT_SETTINGS, profileOverride: "bad\nname" }, /control/],
  ];
  for (const [name, value, expected] of cases) {
    await t.test(name, () => assert.throws(() => validateSettings(value), expected));
  }
});

test("loadSettings creates storage and returns independent defaults", async () => {
  const db = fakeDatabase();
  const first = await loadSettings(db);
  first.bridgePort = 1234;
  assert.deepEqual(await loadSettings(db), DEFAULT_SETTINGS);
  assert.match(db.executed[0] ?? "", /CREATE TABLE IF NOT EXISTS/);
});

test("loadSettings validates stored JSON", async () => {
  const stored: BridgeSettings = { ...DEFAULT_SETTINGS, enabled: false, bridgePort: 7788 };
  assert.deepEqual(await loadSettings(fakeDatabase(stored)), stored);
  const malformed = fakeDatabase();
  malformed.stored = "not-json";
  await assert.rejects(loadSettings(malformed), /JSON/);
});

test("persistSettings and manager save update durable and in-memory state", async () => {
  const db = fakeDatabase();
  await persistSettings(db, DEFAULT_SETTINGS);
  assert.deepEqual(JSON.parse(db.stored ?? ""), DEFAULT_SETTINGS);

  const manager = await createSettingsManager(db);
  const updated = await manager.save({ ...DEFAULT_SETTINGS, enabled: false, controlPort: 9191 });
  assert.equal(updated.enabled, false);
  assert.equal(manager.get().controlPort, 9191);
  updated.controlPort = 1;
  assert.equal(manager.get().controlPort, 9191);

  db.failWrites = true;
  await assert.rejects(manager.save({ ...DEFAULT_SETTINGS, bridgePort: 8888 }), /disk full/);
  assert.equal(manager.get().bridgePort, DEFAULT_SETTINGS.bridgePort);
});
