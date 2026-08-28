import assert from "node:assert/strict";
import test from "node:test";

import type { DaemonStatus } from "mimic-caido-shared";

import { availableProfiles, formatUptime } from "./model.js";

const STATUS: DaemonStatus = {
  started_at: "2026-08-28T00:00:00Z",
  uptime_seconds: 1,
  profile: "firefox",
  profiles: ["firefox", "chrome"],
  connections: 0,
  requests: 0,
  tls_fallbacks: 0,
  config_path: "/etc/mimic/config.toml",
};

test("formatUptime presents useful compact units", () => {
  assert.equal(formatUptime(-3), "0s");
  assert.equal(formatUptime(42.9), "42s");
  assert.equal(formatUptime(125), "2m 5s");
  assert.equal(formatUptime(7500), "2h 5m");
  assert.equal(formatUptime(180000), "2d 2h");
});

test("availableProfiles sorts profiles and retains an offline override", () => {
  assert.deepEqual(availableProfiles(STATUS, ""), ["chrome", "firefox"]);
  assert.deepEqual(availableProfiles(STATUS, "safari"), ["chrome", "firefox", "safari"]);
  assert.deepEqual(availableProfiles(null, "custom"), ["custom"]);
});
