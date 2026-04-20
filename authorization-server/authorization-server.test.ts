import assert from "node:assert/strict";
import test from "node:test";
import { createAuthorizationCodeStore } from "./authorization-code-store.ts";
import type { ServerConfig } from "./config/server-config.ts";
import { createServer } from "./server.ts";
import { createTokenStore } from "./token-store.ts";

/*
  This test file is for testing more end to end flows of the authorization server.
 */

const defaultServerConfig: ServerConfig = {
  issuer: "https://issuer.example.test",
  authorizationEndpoint: "https://issuer.example.test/authorize",
  tokenEndpoint: "https://issuer.example.test/token",
  jwksUri: "https://issuer.example.test/.well-known/jwks.json",
  authorizationCodeLifetimeSeconds: 600,
};

test("authorization code can be issued and exchanged for an access token", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const tokenStore = createTokenStore();
  const fastify = createServer(
    defaultServerConfig,
    authorizationCodeStore,
    tokenStore,
  );
  const address = await fastify.listen({
    host: "127.0.0.1",
    port: 0,
  });

  try {
    const authorizationResponse = await fetchAuthorizationEndpoint(address);
    assert.equal(authorizationResponse.status, 302);

    const redirectUrl = getRedirectUrl(authorizationResponse);
    const code = redirectUrl.searchParams.get("code");

    assert.equal(
      redirectUrl.toString(),
      `http://localhost:3000/callback?code=${code}`,
    );
    assert.notEqual(code, null);
    assert.equal(authorizationCodeStore.has(code), true);

    const tokenResponse = await fetchTokenEndpoint(address, code);
    assert.equal(tokenResponse.status, 200);

    const tokenResponseBody = (await tokenResponse.json()) as {
      access_token: string;
      token_type: string;
    };

    assert.equal(tokenResponseBody.token_type, "Bearer");
    assert.equal(typeof tokenResponseBody.access_token, "string");
    assert.notEqual(tokenResponseBody.access_token.length, 0);

    // Check auth code was removed.
    assert.equal(authorizationCodeStore.has(code), false);
    // Check new access token is in the token store, for this client.
    assert.deepEqual(tokenStore.get(tokenResponseBody.access_token), {
      clientId: "test-client-id",
    });
  } finally {
    await fastify.close();
  }
});

async function fetchAuthorizationEndpoint(address: string) {
  const authorizationPath = new URL(defaultServerConfig.authorizationEndpoint)
    .pathname;
  const queryString = new URLSearchParams({
    client_id: "test-client-id",
    response_type: "code",
    redirect_uri: "http://localhost:3000/callback",
  }).toString();

  return await fetch(`${address}${authorizationPath}?${queryString}`, {
    redirect: "manual",
  });
}

async function fetchTokenEndpoint(address: string, code: string) {
  const tokenPath = new URL(defaultServerConfig.tokenEndpoint).pathname;
  const requestBody = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: "http://localhost:3000/callback",
  }).toString();

  return await fetch(`${address}${tokenPath}`, {
    headers: {
      authorization: createBasicAuthHeader(
        "test-client-id",
        "test-client-secret",
      ),
      "content-type": "application/x-www-form-urlencoded",
    },
    method: "POST",
    body: requestBody,
  });
}

function getRedirectUrl(response: Response) {
  const location = response.headers.get("location");
  assert.notEqual(location, null);
  return new URL(location);
}

function createBasicAuthHeader(clientId: string, clientSecret: string) {
  const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString(
    "base64",
  );
  return `Basic ${basicAuth}`;
}
