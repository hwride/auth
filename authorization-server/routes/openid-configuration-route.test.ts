import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import test from "node:test";
import { createServer } from "../server.ts";

test("GET /.well-known/openid-configuration defaults endpoints from the issuer", async function () {
  await withEnvVars(
    {
      ISSUER: "https://issuer.example.test",
      AUTHORIZATION_ENDPOINT: undefined,
      TOKEN_ENDPOINT: undefined,
    },
    async function () {
      const response = await fetchOpenIdConfiguration();

      assert.equal(response.status, 200);
      assert.equal(
        response.headers.get("content-type"),
        "application/json; charset=utf-8",
      );
      assert.deepEqual(await response.json(), {
        issuer: "https://issuer.example.test",
        authorization_endpoint: "https://issuer.example.test/authorize",
        token_endpoint: "https://issuer.example.test/token",
      });
    },
  );
});

test("GET /.well-known/openid-configuration uses endpoint overrides when provided", async function () {
  await withEnvVars(
    {
      ISSUER: "https://issuer.example.test",
      AUTHORIZATION_ENDPOINT: "https://login.example.test/oauth2/authorize",
      TOKEN_ENDPOINT: "https://tokens.example.test/oauth2/token",
    },
    async function () {
      const response = await fetchOpenIdConfiguration();

      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), {
        issuer: "https://issuer.example.test",
        authorization_endpoint: "https://login.example.test/oauth2/authorize",
        token_endpoint: "https://tokens.example.test/oauth2/token",
      });
    },
  );
});

async function fetchOpenIdConfiguration() {
  const fastify = createServer();

  await fastify.listen({
    host: "127.0.0.1",
    port: 0,
  });

  try {
    const address = getServerAddress(fastify.server.address());

    return await fetch(
      `http://127.0.0.1:${address.port}/.well-known/openid-configuration`,
    );
  } finally {
    await fastify.close();
  }
}

async function withEnvVars(
  envVars: Record<string, string | undefined>,
  callback: () => Promise<void>,
) {
  // Save original env vars.
  const originalEnvVars = new Map(
    Object.keys(envVars).map(function (key) {
      return [key, process.env[key]];
    }),
  );

  // Set provided env vars.
  for (const [key, value] of Object.entries(envVars)) {
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }

  try {
    await callback();
  } finally {
    // Restore env vars.
    for (const [key, value] of originalEnvVars.entries()) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
}

function getServerAddress(address: string | AddressInfo | null): AddressInfo {
  if (address === null || typeof address === "string") {
    throw new Error(
      "Expected the Fastify server to be listening on a TCP port",
    );
  }

  return address;
}
