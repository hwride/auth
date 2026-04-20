import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPair } from "jose";
import { createServer } from "../server.ts";

const testSigningKeys = await generateKeyPair("RS256");

test("GET /.well-known/jwks.json returns the signing JWK", async function () {
  const fastify = await createServer({
    jwtSigningAlg: "RS256",
    publicKey: testSigningKeys.publicKey,
    privateKey: testSigningKeys.privateKey,
    issuer: "https://issuer.example.test",
    authorizationEndpoint: "https://issuer.example.test/authorize",
    tokenEndpoint: "https://issuer.example.test/token",
    jwksUri: "https://issuer.example.test/.well-known/jwks.json",
    authorizationCodeLifetimeSeconds: 600,
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
    const body = (await response.json()) as {
      keys: Array<Record<string, string>>;
    };
    assert.equal(body.keys.length, 1);
    assert.equal(body.keys[0].alg, "RS256");
    assert.equal(body.keys[0].use, "sig");
    assert.equal(body.keys[0].kty, "RSA");
  } finally {
    await fastify.close();
  }
});
