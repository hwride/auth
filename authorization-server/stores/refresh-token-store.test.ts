import assert from "node:assert/strict";
import test from "node:test";
import { createRefreshTokenStore } from "./refresh-token-store.ts";

test("refresh token store generates a token and stores refresh token record with expiry", function () {
  const refreshTokenStore = createRefreshTokenStore();

  const refreshToken = refreshTokenStore.generateNew(
    {
      clientId: "client-id-opaque",
      resource: "https://orders-api.example.test",
      scope: "openid offline_access email",
      subject: "test-user",
    },
    172800,
  );

  assert.equal(refreshTokenStore.hasToken(refreshToken), true);

  const refreshTokenRecord = refreshTokenStore.get(refreshToken);
  assert.notEqual(refreshTokenRecord, undefined);
  assert.equal(refreshTokenRecord.clientId, "client-id-opaque");
  assert.equal(refreshTokenRecord.resource, "https://orders-api.example.test");
  assert.equal(refreshTokenRecord.scope, "openid offline_access email");
  assert.equal(refreshTokenRecord.subject, "test-user");
  assert.ok(
    refreshTokenRecord.expiresAt >= Date.now() + 172_790_000 &&
      refreshTokenRecord.expiresAt <= Date.now() + 172_810_000,
  );
});

test("refresh token store hasToken returns false for unknown token", function () {
  const refreshTokenStore = createRefreshTokenStore();

  assert.equal(refreshTokenStore.hasToken("missing-token"), false);
});

test("refresh token store deletes stored tokens", function () {
  const refreshTokenStore = createRefreshTokenStore();
  const refreshToken = refreshTokenStore.generateNew(
    {
      clientId: "client-id-opaque",
      subject: "test-user",
    },
    172800,
  );

  assert.equal(refreshTokenStore.delete(refreshToken), true);
  assert.equal(refreshTokenStore.hasToken(refreshToken), false);
  assert.equal(refreshTokenStore.get(refreshToken), undefined);
  assert.equal(refreshTokenStore.delete(refreshToken), false);
});
