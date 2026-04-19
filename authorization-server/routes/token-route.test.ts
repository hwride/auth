import assert from "node:assert/strict";
import test from "node:test";
import {
  createAuthorizationCodeStore,
  type AuthorizationCodeStore,
} from "../authorization-code-store.ts";
import type { ServerConfig } from "../config/server-config.ts";
import { createServer } from "../server.ts";
import { createTokenStore, type TokenStore } from "../token-store.ts";

const defaultServerConfig: ServerConfig = {
  issuer: "https://issuer.example.test",
  authorizationEndpoint: "https://issuer.example.test/authorize",
  tokenEndpoint: "https://issuer.example.test/token",
  jwksUri: "https://issuer.example.test/.well-known/jwks.json",
};

test("POST token endpoint rejects unsupported grant_type", async function () {
  const authorizationCodeStore = createAuthorizationCodeStoreWithCode();
  const response = await fetchTokenEndpoint(
    {
      grant_type: "refresh_token",
      redirect_uri: "http://localhost:3000/callback",
    },
    defaultServerConfig,
    authorizationCodeStore,
    createBasicAuthHeader("test-client-id", "test-client-secret"),
  );

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), {
    error: "unsupported_grant_type",
  });
});

test("POST token endpoint rejects requests missing code", async function () {
  const response = await fetchTokenEndpoint(
    {
      grant_type: "authorization_code",
    },
    defaultServerConfig,
    createAuthorizationCodeStore(),
    createBasicAuthHeader("test-client-id", "test-client-secret"),
  );

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), {
    error: "invalid_request",
    error_description: "Missing code",
  });
});

test("POST token endpoint rejects missing client auth", async function () {
  const response = await fetchTokenEndpoint({
    grant_type: "authorization_code",
    code: "test-auth-code",
  });

  assert.equal(response.status, 401);
  assert.equal(response.headers.get("www-authenticate"), 'Basic realm="token"');
  assert.deepEqual(await response.json(), {
    error: "invalid_client",
  });
});

test("POST token endpoint rejects invalid client auth", async function () {
  const response = await fetchTokenEndpoint(
    {
      grant_type: "authorization_code",
      code: "test-auth-code",
    },
    defaultServerConfig,
    createAuthorizationCodeStoreWithCode(),
    createBasicAuthHeader("test-client-id", "wrong-secret"),
  );

  assert.equal(response.status, 401);
  assert.equal(response.headers.get("www-authenticate"), 'Basic realm="token"');
  assert.deepEqual(await response.json(), {
    error: "invalid_client",
  });
});

test("POST token endpoint rejects unknown authorization code", async function () {
  const response = await fetchTokenEndpoint(
    {
      grant_type: "authorization_code",
      code: "missing-auth-code",
    },
    defaultServerConfig,
    createAuthorizationCodeStore(),
    createBasicAuthHeader("test-client-id", "test-client-secret"),
  );

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), {
    error: "invalid_grant",
    error_description: "Unknown code",
  });
});

test("POST token endpoint rejects authorization code issued to a different client", async function () {
  const response = await fetchTokenEndpoint(
    {
      grant_type: "authorization_code",
      code: "test-auth-code",
      redirect_uri: "http://localhost:3000/callback",
    },
    defaultServerConfig,
    createAuthorizationCodeStoreWithCode(),
    createBasicAuthHeader("other-test-client-id", "other-test-client-secret"),
  );

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), {
    error: "invalid_grant",
    error_description: "Code does not match client",
  });
});

test("POST token endpoint rejects mismatched redirect_uri", async function () {
  const response = await fetchTokenEndpoint(
    {
      grant_type: "authorization_code",
      code: "test-auth-code",
      redirect_uri: "http://localhost:3000/wrong-callback",
    },
    defaultServerConfig,
    createAuthorizationCodeStoreWithCode(),
    createBasicAuthHeader("test-client-id", "test-client-secret"),
  );

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), {
    error: "invalid_grant",
    error_description: "Invalid redirect_uri",
  });
});

test("POST token endpoint returns an opaque access token for valid code exchange", async function () {
  const authorizationCodeStore = createAuthorizationCodeStoreWithCode();
  const tokenStore = createTokenStore();
  const response = await fetchTokenEndpoint(
    {
      grant_type: "authorization_code",
      code: "test-auth-code",
      redirect_uri: "http://localhost:3000/callback",
    },
    defaultServerConfig,
    authorizationCodeStore,
    createBasicAuthHeader("test-client-id", "test-client-secret"),
    tokenStore,
  );

  assert.equal(response.status, 200);

  const tokenResponse = (await response.json()) as {
    access_token: string;
    token_type: string;
  };

  assert.equal(tokenResponse.token_type, "Bearer");
  assert.equal(typeof tokenResponse.access_token, "string");
  assert.notEqual(tokenResponse.access_token.length, 0);
  assert.deepEqual(tokenStore.get(tokenResponse.access_token), {
    clientId: "test-client-id",
  });
  assert.equal(authorizationCodeStore.has("test-auth-code"), false);
});

test("POST token endpoint makes authorization codes one-time use", async function () {
  const authorizationCodeStore = createAuthorizationCodeStoreWithCode();
  const tokenStore = createTokenStore();

  const firstResponse = await fetchTokenEndpoint(
    {
      grant_type: "authorization_code",
      code: "test-auth-code",
      redirect_uri: "http://localhost:3000/callback",
    },
    defaultServerConfig,
    authorizationCodeStore,
    createBasicAuthHeader("test-client-id", "test-client-secret"),
    tokenStore,
  );
  assert.equal(firstResponse.status, 200);

  const secondResponse = await fetchTokenEndpoint(
    {
      grant_type: "authorization_code",
      code: "test-auth-code",
      redirect_uri: "http://localhost:3000/callback",
    },
    defaultServerConfig,
    authorizationCodeStore,
    createBasicAuthHeader("test-client-id", "test-client-secret"),
    tokenStore,
  );

  assert.equal(secondResponse.status, 400);
  assert.deepEqual(await secondResponse.json(), {
    error: "invalid_grant",
    error_description: "Unknown code",
  });
});

async function fetchTokenEndpoint(
  queryParams: Record<string, string>,
  serverConfig: ServerConfig = defaultServerConfig,
  authorizationCodeStore: AuthorizationCodeStore = createAuthorizationCodeStore(),
  authorizationHeader?: string,
  tokenStore: TokenStore = createTokenStore(),
) {
  const fastify = createServer(serverConfig, authorizationCodeStore, tokenStore);
  const address = await fastify.listen({
    host: "127.0.0.1",
    port: 0,
  });

  try {
    const tokenPath = new URL(serverConfig.tokenEndpoint).pathname;
    const requestBody = new URLSearchParams(queryParams).toString();

    return await fetch(`${address}${tokenPath}`, {
      headers: {
        ...(authorizationHeader
          ? {
              authorization: authorizationHeader,
            }
          : {}),
        "content-type": "application/x-www-form-urlencoded",
      },
      method: "POST",
      body: requestBody,
    });
  } finally {
    await fastify.close();
  }
}

function createAuthorizationCodeStoreWithCode() {
  const authorizationCodeStore = createAuthorizationCodeStore();
  authorizationCodeStore.set("test-auth-code", {
    clientId: "test-client-id",
    redirectUri: "http://localhost:3000/callback",
  });
  return authorizationCodeStore;
}

function createBasicAuthHeader(clientId: string, clientSecret: string) {
  const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString(
    "base64",
  );
  return `Basic ${basicAuth}`;
}
