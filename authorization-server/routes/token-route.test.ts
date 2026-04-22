import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { generateKeyPair, jwtVerify } from "jose";
import {
  createAuthorizationCodeStore,
  type AuthorizationCodeStore,
} from "../authorization-code-store.ts";
import type { ServerConfig } from "../config/server-config.ts";
import { createServer } from "../server.ts";
import { createTokenStore, type TokenStore } from "../token-store.ts";

const testSigningKeys = await generateKeyPair("RS256");

const defaultServerConfig: ServerConfig = {
  jwtSigningAlg: "RS256",
  publicKey: testSigningKeys.publicKey,
  privateKey: testSigningKeys.privateKey,
  issuer: "https://issuer.example.test",
  authorizationEndpoint: "https://issuer.example.test/authorize",
  tokenEndpoint: "https://issuer.example.test/token",
  jwksUri: "https://issuer.example.test/.well-known/jwks.json",
  authorizationCodeLifetimeSeconds: 600,
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
    createBasicAuthHeader("client-id-opaque", "test-client-secret"),
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
    createBasicAuthHeader("client-id-opaque", "test-client-secret"),
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
    createBasicAuthHeader("client-id-opaque", "wrong-secret"),
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
    createBasicAuthHeader("client-id-opaque", "test-client-secret"),
  );

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), {
    error: "invalid_grant",
    error_description: "Unknown code",
  });
});

test("POST token endpoint rejects expired authorization code", async function () {
  const response = await fetchTokenEndpoint(
    {
      grant_type: "authorization_code",
      code: "test-auth-code",
    },
    defaultServerConfig,
    createAuthorizationCodeStoreWithCodeExpiresAt(Date.now() - 1),
    createBasicAuthHeader("client-id-opaque", "test-client-secret"),
  );

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), {
    error: "invalid_grant",
    error_description: "Code expired",
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
    createBasicAuthHeader("client-id-jwt", "other-test-client-secret"),
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
    createBasicAuthHeader("client-id-opaque", "test-client-secret"),
  );

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), {
    error: "invalid_grant",
    error_description: "Invalid redirect_uri",
  });
});

test("POST token endpoint rejects mismatched plain PKCE code_verifier", async function () {
  const response = await fetchTokenEndpoint(
    {
      grant_type: "authorization_code",
      code: "test-auth-code",
      redirect_uri: "http://localhost:3000/callback",
      code_verifier: "wrong-verifier",
    },
    defaultServerConfig,
    createAuthorizationCodeStoreWithCodeAndPkce({
      codeChallenge: "expected-verifier",
      codeChallengeMethod: "plain",
    }),
    createBasicAuthHeader("client-id-opaque", "test-client-secret"),
  );

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), {
    error: "invalid_grant",
    error_description: "plain code_verifier does not match",
  });
});

test("POST token endpoint rejects mismatched S256 PKCE code_verifier", async function () {
  const response = await fetchTokenEndpoint(
    {
      grant_type: "authorization_code",
      code: "test-auth-code",
      redirect_uri: "http://localhost:3000/callback",
      code_verifier: "wrong-verifier",
    },
    defaultServerConfig,
    createAuthorizationCodeStoreWithCodeAndPkce({
      codeChallenge: createS256CodeChallenge("expected-verifier"),
      codeChallengeMethod: "S256",
    }),
    createBasicAuthHeader("client-id-opaque", "test-client-secret"),
  );

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), {
    error: "invalid_grant",
    error_description: "S256 code_verifier does not match",
  });
});

test("POST token endpoint returns an opaque access token for valid plain PKCE exchange", async function () {
  const authorizationCodeStore = createAuthorizationCodeStoreWithCodeAndPkce({
    codeChallenge: "expected-verifier",
    codeChallengeMethod: "plain",
  });
  const tokenStore = createTokenStore();
  const response = await fetchTokenEndpoint(
    {
      grant_type: "authorization_code",
      code: "test-auth-code",
      redirect_uri: "http://localhost:3000/callback",
      code_verifier: "expected-verifier",
    },
    defaultServerConfig,
    authorizationCodeStore,
    createBasicAuthHeader("client-id-opaque", "test-client-secret"),
    tokenStore,
  );

  assert.equal(response.status, 200);
  assertSensitiveTokenResponseHeaders(response);

  const tokenResponse = (await response.json()) as {
    access_token: string;
    expires_in: number;
    token_type: string;
  };

  assert.equal(tokenResponse.token_type, "Bearer");
  assert.equal(tokenResponse.expires_in, 3600);
  assert.equal(typeof tokenResponse.access_token, "string");
  assert.notEqual(tokenResponse.access_token.length, 0);
  assert.deepEqual(tokenStore.get(tokenResponse.access_token), {
    clientId: "client-id-opaque",
  });
  assert.equal(authorizationCodeStore.has("test-auth-code"), false);
});

test("POST token endpoint returns an opaque access token for valid S256 PKCE exchange", async function () {
  const codeVerifier = "expected-verifier";
  const authorizationCodeStore = createAuthorizationCodeStoreWithCodeAndPkce({
    codeChallenge: createS256CodeChallenge(codeVerifier),
    codeChallengeMethod: "S256",
  });
  const tokenStore = createTokenStore();
  const response = await fetchTokenEndpoint(
    {
      grant_type: "authorization_code",
      code: "test-auth-code",
      redirect_uri: "http://localhost:3000/callback",
      code_verifier: codeVerifier,
    },
    defaultServerConfig,
    authorizationCodeStore,
    createBasicAuthHeader("client-id-opaque", "test-client-secret"),
    tokenStore,
  );

  assert.equal(response.status, 200);
  assertSensitiveTokenResponseHeaders(response);

  const tokenResponse = (await response.json()) as {
    access_token: string;
    expires_in: number;
    token_type: string;
  };

  assert.equal(tokenResponse.token_type, "Bearer");
  assert.equal(tokenResponse.expires_in, 3600);
  assert.equal(typeof tokenResponse.access_token, "string");
  assert.notEqual(tokenResponse.access_token.length, 0);
  assert.deepEqual(tokenStore.get(tokenResponse.access_token), {
    clientId: "client-id-opaque",
  });
  assert.equal(authorizationCodeStore.has("test-auth-code"), false);
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
    createBasicAuthHeader("client-id-opaque", "test-client-secret"),
    tokenStore,
  );

  assert.equal(response.status, 200);
  assertSensitiveTokenResponseHeaders(response);

  const tokenResponse = (await response.json()) as {
    access_token: string;
    expires_in: number;
    token_type: string;
  };

  assert.equal(tokenResponse.token_type, "Bearer");
  assert.equal(tokenResponse.expires_in, 3600);
  assert.equal(typeof tokenResponse.access_token, "string");
  assert.notEqual(tokenResponse.access_token.length, 0);
  assert.deepEqual(tokenStore.get(tokenResponse.access_token), {
    clientId: "client-id-opaque",
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
    createBasicAuthHeader("client-id-opaque", "test-client-secret"),
    tokenStore,
  );
  assert.equal(firstResponse.status, 200);
  assertSensitiveTokenResponseHeaders(firstResponse);

  const secondResponse = await fetchTokenEndpoint(
    {
      grant_type: "authorization_code",
      code: "test-auth-code",
      redirect_uri: "http://localhost:3000/callback",
    },
    defaultServerConfig,
    authorizationCodeStore,
    createBasicAuthHeader("client-id-opaque", "test-client-secret"),
    tokenStore,
  );

  assert.equal(secondResponse.status, 400);
  assert.deepEqual(await secondResponse.json(), {
    error: "invalid_grant",
    error_description: "Unknown code",
  });
});

test("POST token endpoint returns a signed jwt for jwt access token type", async function () {
  const authorizationCodeStore =
    createAuthorizationCodeStoreWithCodeForClient("client-id-jwt");
  const tokenStore = createTokenStore();
  const response = await fetchTokenEndpoint(
    {
      grant_type: "authorization_code",
      code: "test-auth-code",
      redirect_uri: "http://localhost:3000/callback",
    },
    defaultServerConfig,
    authorizationCodeStore,
    createBasicAuthHeader("client-id-jwt", "other-test-client-secret"),
    tokenStore,
  );

  assert.equal(response.status, 200);
  assertSensitiveTokenResponseHeaders(response);
  const tokenResponse = (await response.json()) as {
    access_token: string;
    expires_in: number;
    token_type: string;
  };
  assert.equal(tokenResponse.token_type, "Bearer");
  assert.equal(tokenResponse.expires_in, 3600);

  const verified = await jwtVerify(
    tokenResponse.access_token,
    defaultServerConfig.publicKey,
    {
      algorithms: ["RS256"],
      issuer: defaultServerConfig.issuer,
      audience: defaultServerConfig.issuer,
    },
  );
  assert.equal(verified.protectedHeader.alg, "RS256");
  assert.equal(verified.protectedHeader.typ, "at+jwt");
  assert.equal(verified.payload.iss, defaultServerConfig.issuer);
  assert.equal(verified.payload.aud, defaultServerConfig.issuer);
  assert.equal(verified.payload.sub, "test-user");
  assert.equal(verified.payload.client_id, "client-id-jwt");
  assert.equal(typeof verified.payload.jti, "string");
  assert.notEqual(verified.payload.jti.length, 0);
  assert.equal(typeof verified.payload.iat, "number");
  assert.equal(typeof verified.payload.exp, "number");
  assert.ok(verified.payload.exp > verified.payload.iat);
  assert.equal(authorizationCodeStore.has("test-auth-code"), false);
  assert.equal(tokenStore.size, 0);
});

test("POST token endpoint includes scope in access tokens when present on auth code", async function () {
  const authorizationCodeStore = createAuthorizationCodeStoreWithCodeForClient(
    "client-id-jwt",
    "openid profile",
  );
  const tokenStore = createTokenStore();
  const response = await fetchTokenEndpoint(
    {
      grant_type: "authorization_code",
      code: "test-auth-code",
      redirect_uri: "http://localhost:3000/callback",
    },
    defaultServerConfig,
    authorizationCodeStore,
    createBasicAuthHeader("client-id-jwt", "other-test-client-secret"),
    tokenStore,
  );

  assert.equal(response.status, 200);
  assertSensitiveTokenResponseHeaders(response);
  const tokenResponse = (await response.json()) as {
    access_token: string;
    expires_in: number;
  };

  assert.equal(tokenResponse.expires_in, 3600);
  const verified = await jwtVerify(
    tokenResponse.access_token,
    defaultServerConfig.publicKey,
    {
      algorithms: ["RS256"],
      issuer: defaultServerConfig.issuer,
      audience: defaultServerConfig.issuer,
    },
  );

  assert.equal(verified.payload.scope, "openid profile");
  assert.equal(tokenStore.size, 0);
});

test("POST token endpoint returns an ID token when scope includes openid token", async function () {
  const authorizationCodeStore = createAuthorizationCodeStoreWithCodeForClient(
    "client-id-jwt",
    "profile openid email",
  );
  const response = await fetchTokenEndpoint(
    {
      grant_type: "authorization_code",
      code: "test-auth-code",
      redirect_uri: "http://localhost:3000/callback",
    },
    defaultServerConfig,
    authorizationCodeStore,
    createBasicAuthHeader("client-id-jwt", "other-test-client-secret"),
  );

  assert.equal(response.status, 200);
  assertSensitiveTokenResponseHeaders(response);
  const tokenResponse = (await response.json()) as {
    access_token: string;
    expires_in: number;
    id_token: string;
    token_type: string;
  };

  assert.equal(tokenResponse.token_type, "Bearer");
  assert.equal(tokenResponse.expires_in, 3600);
  assert.equal(typeof tokenResponse.id_token, "string");
  assert.notEqual(tokenResponse.id_token.length, 0);

  const verified = await jwtVerify(
    tokenResponse.id_token,
    defaultServerConfig.publicKey,
    {
      algorithms: ["RS256"],
      issuer: defaultServerConfig.issuer,
      audience: "client-id-jwt",
    },
  );

  assert.equal(verified.protectedHeader.alg, "RS256");
  assert.equal(verified.payload.iss, defaultServerConfig.issuer);
  assert.equal(verified.payload.aud, "client-id-jwt");
  assert.equal(verified.payload.sub, "test-user");
  assert.equal(typeof verified.payload.jti, "string");
  assert.notEqual(verified.payload.jti.length, 0);
});

test("POST token endpoint includes nonce in ID token when present on auth code", async function () {
  const authorizationCodeStore = createAuthorizationCodeStoreWithCodeForClient(
    "client-id-jwt",
    "profile openid email",
    "nonce-value-123",
  );
  const response = await fetchTokenEndpoint(
    {
      grant_type: "authorization_code",
      code: "test-auth-code",
      redirect_uri: "http://localhost:3000/callback",
    },
    defaultServerConfig,
    authorizationCodeStore,
    createBasicAuthHeader("client-id-jwt", "other-test-client-secret"),
  );

  assert.equal(response.status, 200);
  assertSensitiveTokenResponseHeaders(response);
  const tokenResponse = (await response.json()) as {
    id_token: string;
  };

  const verifiedIdToken = await jwtVerify(
    tokenResponse.id_token,
    defaultServerConfig.publicKey,
    {
      algorithms: ["RS256"],
      issuer: defaultServerConfig.issuer,
      audience: "client-id-jwt",
    },
  );

  assert.equal(verifiedIdToken.payload.nonce, "nonce-value-123");
});

test("POST token endpoint does not return an ID token when scope only contains openid as a substring", async function () {
  const authorizationCodeStore = createAuthorizationCodeStoreWithCodeForClient(
    "client-id-jwt",
    "profile notopenid email",
  );
  const response = await fetchTokenEndpoint(
    {
      grant_type: "authorization_code",
      code: "test-auth-code",
      redirect_uri: "http://localhost:3000/callback",
    },
    defaultServerConfig,
    authorizationCodeStore,
    createBasicAuthHeader("client-id-jwt", "other-test-client-secret"),
  );

  assert.equal(response.status, 200);
  assertSensitiveTokenResponseHeaders(response);
  const tokenResponse = (await response.json()) as {
    access_token: string;
    id_token?: string;
    expires_in: number;
    token_type: string;
  };

  assert.equal(tokenResponse.token_type, "Bearer");
  assert.equal(tokenResponse.expires_in, 3600);
  assert.equal(tokenResponse.id_token, undefined);
});

async function fetchTokenEndpoint(
  queryParams: Record<string, string>,
  serverConfig: ServerConfig = defaultServerConfig,
  authorizationCodeStore: AuthorizationCodeStore = createAuthorizationCodeStore(),
  authorizationHeader?: string,
  tokenStore: TokenStore = createTokenStore(),
) {
  const fastify = await createServer(
    serverConfig,
    authorizationCodeStore,
    tokenStore,
  );
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
  return createAuthorizationCodeStoreWithCodeExpiresAtForClient(
    Date.now() + 60_000,
    "client-id-opaque",
  );
}

function createAuthorizationCodeStoreWithCodeExpiresAt(expiresAt: number) {
  return createAuthorizationCodeStoreWithCodeExpiresAtForClient(
    expiresAt,
    "client-id-opaque",
  );
}

function createAuthorizationCodeStoreWithCodeForClient(
  clientId: string,
  scope?: string,
  nonce?: string,
) {
  return createAuthorizationCodeStoreWithCodeExpiresAtForClient(
    Date.now() + 60_000,
    clientId,
    scope,
    nonce,
  );
}

function createAuthorizationCodeStoreWithCodeExpiresAtForClient(
  expiresAt: number,
  clientId: string,
  scope?: string,
  nonce?: string,
) {
  const authorizationCodeStore = createAuthorizationCodeStore();
  authorizationCodeStore.set("test-auth-code", {
    clientId,
    subject: "test-user",
    redirectUri: "http://localhost:3000/callback",
    scope,
    nonce,
    expiresAt,
  });
  return authorizationCodeStore;
}

function createAuthorizationCodeStoreWithCodeAndPkce({
  codeChallenge,
  codeChallengeMethod,
  expiresAt = Date.now() + 60_000,
  clientId = "client-id-opaque",
}: {
  codeChallenge: string;
  codeChallengeMethod: "plain" | "S256";
  expiresAt?: number;
  clientId?: string;
}) {
  const authorizationCodeStore = createAuthorizationCodeStore();
  authorizationCodeStore.set("test-auth-code", {
    clientId,
    subject: "test-user",
    redirectUri: "http://localhost:3000/callback",
    expiresAt,
    codeChallenge,
    codeChallengeMethod,
  });
  return authorizationCodeStore;
}

function createBasicAuthHeader(clientId: string, clientSecret: string) {
  const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString(
    "base64",
  );
  return `Basic ${basicAuth}`;
}

function assertSensitiveTokenResponseHeaders(response: Response) {
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("pragma"), "no-cache");
}

function createS256CodeChallenge(codeVerifier: string) {
  return createHash("sha256").update(codeVerifier).digest("base64url");
}
