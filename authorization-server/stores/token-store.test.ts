import assert from "node:assert/strict";
import test from "node:test";
import { createTokenStore } from "./token-store.ts";

test("token store saves and loads access token records", function () {
  const tokenStore = createTokenStore();
  const accessTokenRecord = {
    clientId: "client-id-opaque",
    scope: "openid email",
  };

  tokenStore.saveAccessToken("test-access-token", accessTokenRecord);

  assert.equal(tokenStore.isEmpty(), false);
  assert.deepEqual(
    tokenStore.loadAccessToken("test-access-token"),
    accessTokenRecord,
  );
});

test("token store returns undefined for missing access tokens", function () {
  const tokenStore = createTokenStore();

  assert.equal(tokenStore.isEmpty(), true);
  assert.equal(tokenStore.loadAccessToken("missing-access-token"), undefined);
});
