import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "../server.ts";

test("GET /.well-known/jwks.json returns an empty JWK set", async function () {
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
    const response = await fetch(`${address}/.well-known/jwks.json`);

    assert.equal(response.status, 200);
    assert.equal(
      response.headers.get("content-type"),
      "application/json; charset=utf-8",
    );
    assert.deepEqual(await response.json(), {
      keys: [],
    });
  } finally {
    await fastify.close();
  }
});
