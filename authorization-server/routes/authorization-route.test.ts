import assert from "node:assert/strict";
import test from "node:test";
import {
  createAuthorizationCodeStore,
  type AuthorizationCodeStore,
} from "../authorization-code-store.ts";
import type { ServerConfig } from "../config/server-config.ts";
import { createServer } from "../server.ts";

const defaultServerConfig: ServerConfig = {
  issuer: "https://issuer.example.test",
  authorizationEndpoint: "https://issuer.example.test/authorize",
  tokenEndpoint: "https://issuer.example.test/token",
  jwksUri: "https://issuer.example.test/.well-known/jwks.json",
  authorizationCodeLifetimeSeconds: 600,
};

test("GET authorization endpoint redirects with an authorization code", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const response = await fetchAuthorizationEndpoint(
    {
      client_id: "test-client-id",
      response_type: "code",
      redirect_uri: "http://localhost:3000/callback",
    },
    defaultServerConfig,
    authorizationCodeStore,
  );

  assert.equal(response.status, 302);

  const redirectUrl = getRedirectUrl(response);
  const code = redirectUrl.searchParams.get("code");

  assert.equal(redirectUrl.origin, "http://localhost:3000");
  assert.equal(redirectUrl.pathname, "/callback");
  assert.notEqual(code, null);
  const codeRecord = authorizationCodeStore.get(code);
  assert.deepEqual(
    {
      clientId: codeRecord.clientId,
      redirectUri: codeRecord.redirectUri,
    },
    {
      clientId: "test-client-id",
      redirectUri: "http://localhost:3000/callback",
    },
  );
  assert.equal(typeof codeRecord.expiresAt, "number");
  assert.ok(codeRecord.expiresAt > Date.now());
});

test("GET authorization endpoint sets code expiry from configured lifetime", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const response = await fetchAuthorizationEndpoint(
    {
      client_id: "test-client-id",
      response_type: "code",
      redirect_uri: "http://localhost:3000/callback",
    },
    {
      ...defaultServerConfig,
      authorizationCodeLifetimeSeconds: 2,
    },
    authorizationCodeStore,
  );

  assert.equal(response.status, 302);

  const redirectUrl = getRedirectUrl(response);
  const code = redirectUrl.searchParams.get("code");
  assert.notEqual(code, null);

  const codeRecord = authorizationCodeStore.get(code);
  assert.ok(codeRecord.expiresAt > Date.now());
  assert.ok(codeRecord.expiresAt <= Date.now() + 2_000);
});

test("GET authorization endpoint rejects requests missing redirect_uri", async function () {
  const response = await fetchAuthorizationEndpoint({
    client_id: "test-client-id",
    response_type: "code",
  });

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), {
    error: "invalid_request",
    error_description: "Missing redirect_uri",
  });
});

test("GET authorization endpoint rejects invalid client_id", async function () {
  const response = await fetchAuthorizationEndpoint({
    client_id: "not-test-client-id",
    response_type: "code",
    redirect_uri: "http://localhost:3000/callback",
  });

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), {
    error: "invalid_request",
    error_description: "Invalid client_id",
  });
});

test("GET authorization endpoint rejects invalid redirect_uri", async function () {
  const response = await fetchAuthorizationEndpoint({
    client_id: "test-client-id",
    response_type: "code",
    redirect_uri: "https://client.example.test/callback",
  });

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), {
    error: "invalid_request",
    error_description: "Invalid redirect_uri",
  });
});

test("GET authorization endpoint rejects unsupported response_type", async function () {
  const response = await fetchAuthorizationEndpoint({
    client_id: "test-client-id",
    response_type: "token",
    redirect_uri: "http://localhost:3000/callback",
  });

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), {
    error: "unsupported_response_type",
  });
});

test("GET authorization endpoint uses the configured endpoint path", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const response = await fetchAuthorizationEndpoint(
    {
      client_id: "test-client-id",
      response_type: "code",
      redirect_uri: "http://localhost:3000/callback",
    },
    {
      ...defaultServerConfig,
      authorizationEndpoint: "https://login.example.test/oauth2/authorize",
    },
    authorizationCodeStore,
  );

  assert.equal(response.status, 302);

  const redirectUrl = getRedirectUrl(response);
  const code = redirectUrl.searchParams.get("code");

  assert.notEqual(code, null);
  const codeRecord = authorizationCodeStore.get(code);
  assert.deepEqual(
    {
      clientId: codeRecord.clientId,
      redirectUri: codeRecord.redirectUri,
    },
    {
      clientId: "test-client-id",
      redirectUri: "http://localhost:3000/callback",
    },
  );
});

async function fetchAuthorizationEndpoint(
  queryParams: Record<string, string>,
  serverConfig: ServerConfig = defaultServerConfig,
  authorizationCodeStore: AuthorizationCodeStore = createAuthorizationCodeStore(),
) {
  const fastify = createServer(serverConfig, authorizationCodeStore);
  const address = await fastify.listen({
    host: "127.0.0.1",
    port: 0,
  });

  try {
    const authorizationPath = new URL(serverConfig.authorizationEndpoint)
      .pathname;
    const queryString = new URLSearchParams(queryParams).toString();

    return await fetch(`${address}${authorizationPath}?${queryString}`, {
      redirect: "manual",
    });
  } finally {
    await fastify.close();
  }
}

function getRedirectUrl(response: Response) {
  const location = response.headers.get("location");
  assert.notEqual(location, null);
  return new URL(location);
}
