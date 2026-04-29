import assert from "node:assert/strict";
import test from "node:test";
import type { Role, Scope } from "../config/rbac-config.ts";
import type { UserRecord } from "../stores/user-store.ts";
import { getAllowedScopesForUser } from "./rbac-utils.ts";

test("getAllowedScopesForUser returns scopes for assigned roles", function () {
  assert.deepEqual(
    getAllowedScopesForUser(createUserRecord({ roles: ["customer"] })),
    ["orders:read"],
  );
});

test("getAllowedScopesForUser returns products scope for admin role", function () {
  assert.deepEqual(
    getAllowedScopesForUser(createUserRecord({ roles: ["admin"] })),
    ["orders:read", "orders:read:any", "products:read"],
  );
});

test("getAllowedScopesForUser merges role scopes with user allowed scopes", function () {
  assert.deepEqual(
    getAllowedScopesForUser(
      createUserRecord({
        roles: ["customer"],
        allowedScopes: ["orders:read:any"],
      }),
    ),
    ["orders:read", "orders:read:any"],
  );
});

test("getAllowedScopesForUser deduplicates scopes", function () {
  assert.deepEqual(
    getAllowedScopesForUser(
      createUserRecord({
        roles: ["customer", "admin"],
        allowedScopes: ["orders:read:any"],
      }),
    ),
    ["orders:read", "orders:read:any", "products:read"],
  );
});

test("getAllowedScopesForUser returns an empty list without roles or allowed scopes", function () {
  assert.deepEqual(getAllowedScopesForUser(createUserRecord()), []);
});

function createUserRecord({
  roles,
  allowedScopes,
}: {
  roles?: Role[];
  allowedScopes?: Scope[];
} = {}): UserRecord {
  const user: UserRecord = {
    userId: "user-id",
    username: "user",
    password: "password",
    name: "Test User",
  };

  if (roles) {
    user.roles = roles;
  }
  if (allowedScopes) {
    user.allowedScopes = allowedScopes;
  }

  return user;
}
