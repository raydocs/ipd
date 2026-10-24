import { createRequire } from "node:module";
import assert from "node:assert/strict";
import test from "node:test";

const require = createRequire(import.meta.url);
const { judgeLeak } = require("./judge.js");

test("private candidates are ignored and public mismatches leak", () => {
  const same = judgeLeak(["1.1.1.1"], ["candidate:1 1 udp 1 1.1.1.1 9 typ host", "192.168.1.5", "10.0.0.2"]);
  assert.equal(same.leak, false);
  assert.equal(same.candidate_count, 1);
  const leak = judgeLeak(["1.1.1.1"], ["8.8.8.8"]);
  assert.equal(leak.leak, true);
  assert.equal(leak.candidate_count, 1);
  const body = { leak: leak.leak, candidate_count: leak.candidate_count };
  assert.equal("candidate" in body, false);
  assert.equal(JSON.stringify(body).includes("8.8.8.8"), false);
});
