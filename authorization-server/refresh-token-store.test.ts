import assert from "node:assert/strict";
import test from "node:test";
import { createRefreshTokenStore } from "./refresh-token-store.ts";

test("refresh token store generates a token and stores authorization request with expiry", function () {
  const refreshTokenStore = createRefreshTokenStore(172800);

  const refreshToken = refreshTokenStore.generateNew({
    subject: "test-user",
    authorizationRequest: {
      clientId: "client-id-opaque",
      responseType: "code",
      redirectUri: "http://localhost:3000/callback",
      scope: "openid offline_access email",
      nonce: "nonce-value-123",
      state: "state-value-123",
      codeChallenge: "challenge-value",
      codeChallengeMethod: "S256",
    },
  });

  assert.equal(refreshTokenStore.hasToken(refreshToken), true);

  const refreshTokenRecord = refreshTokenStore.get(refreshToken);
  assert.notEqual(refreshTokenRecord, undefined);
  assert.equal(refreshTokenRecord.subject, "test-user");
  assert.deepEqual(refreshTokenRecord.authorizationRequest, {
    clientId: "client-id-opaque",
    responseType: "code",
    redirectUri: "http://localhost:3000/callback",
    scope: "openid offline_access email",
    nonce: "nonce-value-123",
    state: "state-value-123",
    codeChallenge: "challenge-value",
    codeChallengeMethod: "S256",
  });
  assert.ok(
    refreshTokenRecord.expiresAt >= Date.now() + 172_790_000 &&
      refreshTokenRecord.expiresAt <= Date.now() + 172_810_000,
  );
});

test("refresh token store hasToken returns false for unknown token", function () {
  const refreshTokenStore = createRefreshTokenStore(172800);

  assert.equal(refreshTokenStore.hasToken("missing-token"), false);
});
