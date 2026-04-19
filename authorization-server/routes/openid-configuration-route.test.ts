import assert from "node:assert/strict";
import test from "node:test";
import type { ServerConfig } from "../config/server-config.ts";
import { createServer } from "../server.ts";

test("GET /.well-known/openid-configuration defaults endpoints from the issuer", async function () {
  const response = await fetchOpenIdConfiguration({
    issuer: "https://issuer.example.test",
    authorizationEndpoint: "https://issuer.example.test/authorize",
    tokenEndpoint: "https://issuer.example.test/token",
    jwksUri: "https://issuer.example.test/.well-known/jwks.json",
  });

  assert.equal(response.status, 200);
  assert.equal(
    response.headers.get("content-type"),
    "application/json; charset=utf-8",
  );
  assert.deepEqual(await response.json(), {
    issuer: "https://issuer.example.test",
    authorization_endpoint: "https://issuer.example.test/authorize",
    token_endpoint: "https://issuer.example.test/token",
    jwks_uri: "https://issuer.example.test/.well-known/jwks.json",
  });
});

test("GET /.well-known/openid-configuration uses endpoint overrides when provided", async function () {
  const response = await fetchOpenIdConfiguration({
    issuer: "https://issuer.example.test",
    authorizationEndpoint: "https://login.example.test/oauth2/authorize",
    tokenEndpoint: "https://tokens.example.test/oauth2/token",
    jwksUri: "https://keys.example.test/oauth2/jwks.json",
  });

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    issuer: "https://issuer.example.test",
    authorization_endpoint: "https://login.example.test/oauth2/authorize",
    token_endpoint: "https://tokens.example.test/oauth2/token",
    jwks_uri: "https://keys.example.test/oauth2/jwks.json",
  });
});

async function fetchOpenIdConfiguration(serverConfig: ServerConfig) {
  const fastify = createServer(serverConfig);

  const address = await fastify.listen({
    host: "127.0.0.1",
    port: 0,
  });

  try {
    return await fetch(`${address}/.well-known/openid-configuration`);
  } finally {
    await fastify.close();
  }
}
