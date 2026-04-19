import assert from "node:assert/strict";
import test from "node:test";
import type { ServerConfig } from "../config/server-config.ts";
import { createServer } from "../server.ts";

const defaultServerConfig: ServerConfig = {
  issuer: "https://issuer.example.test",
  authorizationEndpoint: "https://issuer.example.test/authorize",
  tokenEndpoint: "https://issuer.example.test/token",
  jwksUri: "https://issuer.example.test/.well-known/jwks.json",
};

test("GET authorization endpoint returns not implemented for response_type=code", async function () {
  const response = await fetchAuthorizationEndpoint({
    client_id: "test-client-id",
    response_type: "code",
    redirect_uri: "https://client.example.test/callback",
  });

  assert.equal(response.status, 501);
  assert.equal(
    response.headers.get("content-type"),
    "application/json; charset=utf-8",
  );
  assert.deepEqual(await response.json(), {
    error: "not_implemented",
  });
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
    redirect_uri: "https://client.example.test/callback",
  });

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), {
    error: "invalid_request",
    error_description: "Invalid client_id",
  });
});

test("GET authorization endpoint rejects unsupported response_type", async function () {
  const response = await fetchAuthorizationEndpoint({
    client_id: "test-client-id",
    response_type: "token",
    redirect_uri: "https://client.example.test/callback",
  });

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), {
    error: "unsupported_response_type",
  });
});

test("GET authorization endpoint uses the configured endpoint path", async function () {
  const response = await fetchAuthorizationEndpoint(
    {
      client_id: "test-client-id",
      response_type: "code",
      redirect_uri: "https://client.example.test/callback",
    },
    {
      ...defaultServerConfig,
      authorizationEndpoint: "https://login.example.test/oauth2/authorize",
    },
  );

  assert.equal(response.status, 501);
  assert.deepEqual(await response.json(), {
    error: "not_implemented",
  });
});

async function fetchAuthorizationEndpoint(
  queryParams: Record<string, string>,
  serverConfig: ServerConfig = defaultServerConfig,
) {
  const fastify = createServer(serverConfig);
  const address = await fastify.listen({
    host: "127.0.0.1",
    port: 0,
  });

  try {
    const authorizationPath = new URL(serverConfig.authorizationEndpoint)
      .pathname;
    const queryString = new URLSearchParams(queryParams).toString();

    return await fetch(`${address}${authorizationPath}?${queryString}`);
  } finally {
    await fastify.close();
  }
}
