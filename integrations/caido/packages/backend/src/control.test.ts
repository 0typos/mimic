import assert from "node:assert/strict";
import test from "node:test";

import type { BridgeSettings, DaemonStatus } from "mimic-caido-shared";

import {
  bridgeURL,
  callControl,
  controlURL,
  getDaemonStatus,
  parseDaemonStatus,
  selectDaemonProfile,
  type ConnectControl,
} from "./control.js";
import { DEFAULT_SETTINGS } from "./settings.js";

const STATUS: DaemonStatus = {
  started_at: "2026-08-28T00:00:00Z",
  uptime_seconds: 42,
  profile: "chrome-152-linux",
  profiles: ["chrome-152-linux", "firefox-154-linux"],
  connections: 7,
  requests: 6,
  tls_fallbacks: 1,
  config_path: "/etc/mimic/config.toml",
};

function fakeConnect(
  reply: (request: Record<string, unknown>) => unknown,
  splitAt = Number.POSITIVE_INFINITY,
): { connect: ConnectControl; sent: string[]; urls: string[] } {
  const sent: string[] = [];
  const urls: string[] = [];
  let chunks: Uint8Array[] = [];
  const encoder = new TextEncoder();
  return {
    sent,
    urls,
    connect: async (url) => {
      urls.push(url);
      return {
        send: async (bytes) => {
          sent.push(bytes);
          const request = JSON.parse(bytes) as Record<string, unknown>;
          const raw = encoder.encode(`${JSON.stringify(reply(request))}\n`);
          const boundary = Math.min(splitAt, raw.length);
          chunks = [raw.slice(0, boundary), raw.slice(boundary)].filter(
            (chunk) => chunk.length > 0,
          );
        },
        receive: async () => chunks.shift() ?? new Uint8Array(),
      };
    },
  };
}

test("bridge and control URLs bracket IPv6 loopback", () => {
  const settings: BridgeSettings = {
    ...DEFAULT_SETTINGS,
    bridgeHost: "::1",
    controlHost: "::1",
  };
  assert.equal(bridgeURL(settings), "http://[::1]:7777");
  assert.equal(controlURL(settings), "http://[::1]:9090");
});

test("callControl reads fragmented newline-framed responses", async () => {
  const fake = fakeConnect(
    (request) => ({ id: request.id, result: { ok: true } }),
    4,
  );
  assert.deepEqual(await callControl(fake.connect, DEFAULT_SETTINGS, "ping"), { ok: true });
  assert.deepEqual(fake.urls, ["http://127.0.0.1:9090"]);
  const request = JSON.parse(fake.sent[0] ?? "") as Record<string, unknown>;
  assert.equal(request.method, "ping");
  assert.deepEqual(request.params, {});
});

test("callControl reports daemon and framing errors", async (t) => {
  await t.test("daemon error", async () => {
    const fake = fakeConnect((request) => ({ id: request.id, error: "unknown profile" }));
    await assert.rejects(
      callControl(fake.connect, DEFAULT_SETTINGS, "profile.use"),
      /unknown profile/,
    );
  });
  await t.test("mismatched id", async () => {
    const fake = fakeConnect(() => ({ id: -1, result: {} }));
    await assert.rejects(callControl(fake.connect, DEFAULT_SETTINGS, "status"), /mismatched/);
  });
  await t.test("missing result", async () => {
    const fake = fakeConnect((request) => ({ id: request.id }));
    await assert.rejects(callControl(fake.connect, DEFAULT_SETTINGS, "status"), /without a result/);
  });
  await t.test("closed connection", async () => {
    const connect: ConnectControl = async () => ({
      send: async () => undefined,
      receive: async () => new Uint8Array(),
    });
    await assert.rejects(callControl(connect, DEFAULT_SETTINGS, "status"), /closed/);
  });
  await t.test("oversized response", async () => {
    const connect: ConnectControl = async () => ({
      send: async () => undefined,
      receive: async () => new Uint8Array(1024 * 1024 + 1),
    });
    await assert.rejects(callControl(connect, DEFAULT_SETTINGS, "status"), /exceeded 1 MiB/);
  });
});

test("status and profile helpers validate daemon responses", async () => {
  const fake = fakeConnect((request) => ({ id: request.id, result: STATUS }), 17);
  assert.deepEqual(await getDaemonStatus(fake.connect, DEFAULT_SETTINGS), STATUS);
  assert.deepEqual(
    await selectDaemonProfile(fake.connect, DEFAULT_SETTINGS, " firefox-154-linux "),
    STATUS,
  );
  const profileRequest = JSON.parse(fake.sent[1] ?? "") as {
    params: { name: string };
  };
  assert.equal(profileRequest.params.name, "firefox-154-linux");
  await assert.rejects(
    selectDaemonProfile(fake.connect, DEFAULT_SETTINGS, "  "),
    /cannot be empty/,
  );
});

test("parseDaemonStatus rejects malformed status fields", () => {
  assert.deepEqual(parseDaemonStatus(STATUS), STATUS);
  assert.throws(() => parseDaemonStatus(null), /invalid status object/);
  assert.throws(() => parseDaemonStatus({ ...STATUS, profiles: [7] }), /incomplete/);
  assert.throws(() => parseDaemonStatus({ ...STATUS, requests: -1 }), /invalid requests/);
  assert.throws(() => parseDaemonStatus({ ...STATUS, requests: 1.5 }), /invalid requests/);
});
