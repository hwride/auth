import assert from "node:assert/strict";
import test from "node:test";
import { isUuidV4 } from "./uuid.ts";

test("isUuidV4 returns true for UUID v4 values", function () {
  assert.equal(isUuidV4("550e8400-e29b-41d4-a716-446655440000"), true);
  assert.equal(isUuidV4("550E8400-E29B-41D4-A716-446655440000"), true);
});

test("isUuidV4 returns false for non-UUID-v4 values", function () {
  assert.equal(isUuidV4("550e8400-e29b-11d4-a716-446655440000"), false);
  assert.equal(isUuidV4("550e8400-e29b-41d4-c716-446655440000"), false);
  assert.equal(isUuidV4("00000000-0000-0000-0000-000000000000"), false);
  assert.equal(isUuidV4("550e8400e29b41d4a716446655440000"), false);
  assert.equal(isUuidV4("not-a-uuid"), false);
});
