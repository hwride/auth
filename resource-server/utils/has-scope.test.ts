import assert from "node:assert/strict";
import test from "node:test";
import { hasScope } from "./has-scope.ts";

test("hasScope returns true when the expected scope is present", function () {
  assert.equal(hasScope("openid orders:read profile", "orders:read"), true);
});

test("hasScope returns false when the expected scope is missing", function () {
  assert.equal(hasScope("openid profile", "orders:read"), false);
});

test("hasScope returns false when scope is undefined", function () {
  assert.equal(hasScope(undefined, "orders:read"), false);
});

test("hasScope matches whole scope values only", function () {
  assert.equal(hasScope("orders:read:any notorders:read", "orders:read"), false);
});

test("hasScope handles repeated whitespace between scopes", function () {
  assert.equal(hasScope("openid   orders:read\nprofile", "orders:read"), true);
});
