import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "../server.ts";

test("GET authorization endpoint returns not implemented", async function () {
  const fastify = createServer({
    issuer: "https://issuer.example.test",
    authorizationEndpoint: "https://issuer.example.test/authorize",
    tokenEndpoint: "https://issuer.example.test/token",
    jwksUri: "https://issuer.example.test/.well-known/jwks.json",
  });

  const address = await fastify.listen({
    host: "127.0.0.1",
    port: 0,
  });

  try {
    const response = await fetch(`${address}/authorize`);

    assert.equal(response.status, 501);
    assert.equal(
      response.headers.get("content-type"),
      "application/json; charset=utf-8",
    );
    assert.deepEqual(await response.json(), {
      error: "not_implemented",
    });
  } finally {
    await fastify.close();
  }
});

test("GET authorization endpoint uses the configured endpoint path", async function () {
  const fastify = createServer({
    issuer: "https://issuer.example.test",
    authorizationEndpoint: "https://login.example.test/oauth2/authorize",
    tokenEndpoint: "https://issuer.example.test/token",
    jwksUri: "https://issuer.example.test/.well-known/jwks.json",
  });

  const address = await fastify.listen({
    host: "127.0.0.1",
    port: 0,
  });

  try {
    const response = await fetch(`${address}/oauth2/authorize`);

    assert.equal(response.status, 501);
    assert.deepEqual(await response.json(), {
      error: "not_implemented",
    });
  } finally {
    await fastify.close();
  }
});
