import assert from "node:assert/strict";
import test from "node:test";

import { createPreface } from "./preface.js";

test("createPreface emits one MIMIC/1 JSON line", () => {
  assert.equal(
    createPreface("example.test:443", true, "firefox-120"),
    'MIMIC/1 {"target":"example.test:443","tls":true,"profile":"firefox-120"}\n',
  );
});

test("createPreface safely JSON-escapes fields", () => {
  const preface = createPreface("example.test:80", false, 'profile"name');
  assert.equal(preface.split("\n").length, 2);
  assert.deepEqual(JSON.parse(preface.slice("MIMIC/1 ".length)), {
    target: "example.test:80",
    tls: false,
    profile: 'profile"name',
  });
});
