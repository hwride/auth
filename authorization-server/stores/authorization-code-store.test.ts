import assert from "node:assert/strict";
import test from "node:test";
import { createAuthorizationCodeStore } from "./authorization-code-store.ts";

test("authorization code store saves and loads authorization code records", function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const authorizationCodeRecord = {
    clientId: "client-id-opaque",
    subject: "test-user",
    redirectUri: "http://localhost:3000/callback",
    expiresAt: Date.now() + 60_000,
  };

  authorizationCodeStore.saveAuthorizationCode(
    "test-auth-code",
    authorizationCodeRecord,
  );

  assert.equal(authorizationCodeStore.isEmpty(), false);
  assert.equal(
    authorizationCodeStore.hasAuthorizationCode("test-auth-code"),
    true,
  );
  assert.deepEqual(
    authorizationCodeStore.loadAuthorizationCode("test-auth-code"),
    authorizationCodeRecord,
  );
});

test("authorization code store returns undefined for missing authorization codes", function () {
  const authorizationCodeStore = createAuthorizationCodeStore();

  assert.equal(authorizationCodeStore.isEmpty(), true);
  assert.equal(
    authorizationCodeStore.hasAuthorizationCode("missing-auth-code"),
    false,
  );
  assert.equal(
    authorizationCodeStore.loadAuthorizationCode("missing-auth-code"),
    undefined,
  );
});

test("authorization code store deletes stored authorization codes", function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  authorizationCodeStore.saveAuthorizationCode("test-auth-code", {
    clientId: "client-id-opaque",
    subject: "test-user",
    redirectUri: "http://localhost:3000/callback",
    expiresAt: Date.now() + 60_000,
  });

  assert.equal(
    authorizationCodeStore.deleteAuthorizationCode("test-auth-code"),
    true,
  );
  assert.equal(
    authorizationCodeStore.hasAuthorizationCode("test-auth-code"),
    false,
  );
  assert.equal(
    authorizationCodeStore.loadAuthorizationCode("test-auth-code"),
    undefined,
  );
  assert.equal(authorizationCodeStore.isEmpty(), true);
  assert.equal(
    authorizationCodeStore.deleteAuthorizationCode("test-auth-code"),
    false,
  );
});
