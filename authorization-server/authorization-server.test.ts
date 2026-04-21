import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { createRemoteJWKSet, generateKeyPair, jwtVerify } from "jose";
import { createAuthorizationCodeStore } from "./authorization-code-store.ts";
import type { ServerConfig } from "./config/server-config.ts";
import { createServer } from "./server.ts";
import { createTokenStore } from "./token-store.ts";
import { createUserStore } from "./user-store.ts";

/*
  This test file is for testing more end to end flows of the authorization server.
 */

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

test("authorization code can be issued and exchanged for an opaque access token", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const tokenStore = createTokenStore();
  const fastify = await createServer(
    defaultServerConfig,
    authorizationCodeStore,
    tokenStore,
  );
  const address = await fastify.listen({
    host: "127.0.0.1",
    port: 0,
  });

  try {
    const authorizationResponse = await authorizeClient(
      address,
      "client-id-opaque",
    );
    assert.equal(authorizationResponse.status, 302);

    const redirectUrl = getRedirectUrl(authorizationResponse);
    const code = redirectUrl.searchParams.get("code");

    assert.equal(
      redirectUrl.toString(),
      `http://localhost:3000/callback?code=${code}`,
    );
    assert.notEqual(code, null);
    assert.equal(authorizationCodeStore.has(code), true);

    const tokenResponse = await fetchTokenEndpoint(
      address,
      code,
      "client-id-opaque",
      "test-client-secret",
    );
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
      clientId: "client-id-opaque",
    });
  } finally {
    await fastify.close();
  }
});

test("authorization code can be issued and exchanged for a jwt access token verified via the auth server jwks url", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const tokenStore = createTokenStore();
  const fastify = await createServer(
    defaultServerConfig,
    authorizationCodeStore,
    tokenStore,
  );
  const address = await fastify.listen({
    host: "127.0.0.1",
    port: 0,
  });

  try {
    const authorizationResponse = await authorizeClient(
      address,
      "client-id-jwt",
    );
    assert.equal(authorizationResponse.status, 302);

    const redirectUrl = getRedirectUrl(authorizationResponse);
    const code = redirectUrl.searchParams.get("code");

    assert.equal(
      redirectUrl.toString(),
      `http://localhost:3000/callback?code=${code}`,
    );
    assert.notEqual(code, null);
    assert.equal(authorizationCodeStore.has(code), true);

    const tokenResponse = await fetchTokenEndpoint(
      address,
      code,
      "client-id-jwt",
      "other-test-client-secret",
    );
    assert.equal(tokenResponse.status, 200);

    const tokenResponseBody = (await tokenResponse.json()) as {
      access_token: string;
      token_type: string;
    };

    assert.equal(tokenResponseBody.token_type, "Bearer");
    assert.equal(typeof tokenResponseBody.access_token, "string");
    assert.notEqual(tokenResponseBody.access_token.length, 0);

    const jwks = createRemoteJWKSet(
      new URL(`${address}${new URL(defaultServerConfig.jwksUri).pathname}`),
    );
    const verified = await jwtVerify(tokenResponseBody.access_token, jwks, {
      algorithms: ["RS256"],
      issuer: defaultServerConfig.issuer,
      audience: defaultServerConfig.issuer,
    });

    assert.equal(verified.protectedHeader.alg, "RS256");
    assert.equal(verified.payload.iss, defaultServerConfig.issuer);
    assert.equal(verified.payload.aud, defaultServerConfig.issuer);
    assert.equal(verified.payload.sub, "test-user");
    assert.equal(verified.payload.client_id, "client-id-jwt");
    assert.equal(typeof verified.payload.jti, "string");
    assert.notEqual(verified.payload.jti.length, 0);
    assert.equal(typeof verified.payload.iat, "number");
    assert.equal(typeof verified.payload.exp, "number");
    assert.ok(verified.payload.exp > verified.payload.iat);

    // Check auth code was removed.
    assert.equal(authorizationCodeStore.has(code), false);
    // JWT access tokens are self-contained and are not stored server-side.
    assert.equal(tokenStore.size, 0);
  } finally {
    await fastify.close();
  }
});

test("authorization code flow supports PKCE and state together", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const tokenStore = createTokenStore();
  const fastify = await createServer(
    defaultServerConfig,
    authorizationCodeStore,
    tokenStore,
  );
  const address = await fastify.listen({
    host: "127.0.0.1",
    port: 0,
  });

  const codeVerifier = "pkce-verifier-1234567890abcdefghijklmnopqrstuvwxyz";
  const codeChallenge = createS256CodeChallenge(codeVerifier);
  const state = "state-value-123";

  try {
    const authorizationResponse = await authorizeClient(address, "client-id-jwt", {
      authorizationRequest: {
        state,
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
      },
    });
    assert.equal(authorizationResponse.status, 302);

    const redirectUrl = getRedirectUrl(authorizationResponse);
    const code = redirectUrl.searchParams.get("code");

    assert.notEqual(code, null);
    assert.equal(redirectUrl.origin, "http://localhost:3000");
    assert.equal(redirectUrl.pathname, "/callback");
    assert.equal(redirectUrl.searchParams.get("state"), state);

    const codeRecord = authorizationCodeStore.get(code);
    assert.notEqual(codeRecord, undefined);
    assert.equal(codeRecord.codeChallenge, codeChallenge);
    assert.equal(codeRecord.codeChallengeMethod, "S256");

    const tokenResponse = await fetchTokenEndpoint(
      address,
      code,
      "client-id-jwt",
      "other-test-client-secret",
      {
        code_verifier: codeVerifier,
      },
    );
    assert.equal(tokenResponse.status, 200);

    const tokenResponseBody = (await tokenResponse.json()) as {
      access_token: string;
      token_type: string;
    };

    assert.equal(tokenResponseBody.token_type, "Bearer");
    assert.equal(typeof tokenResponseBody.access_token, "string");
    assert.notEqual(tokenResponseBody.access_token.length, 0);

    const jwks = createRemoteJWKSet(
      new URL(`${address}${new URL(defaultServerConfig.jwksUri).pathname}`),
    );
    const verified = await jwtVerify(tokenResponseBody.access_token, jwks, {
      algorithms: ["RS256"],
      issuer: defaultServerConfig.issuer,
      audience: defaultServerConfig.issuer,
    });

    assert.equal(verified.protectedHeader.alg, "RS256");
    assert.equal(verified.payload.iss, defaultServerConfig.issuer);
    assert.equal(verified.payload.aud, defaultServerConfig.issuer);
    assert.equal(verified.payload.sub, "test-user");
    assert.equal(verified.payload.client_id, "client-id-jwt");

    assert.equal(authorizationCodeStore.has(code), false);
    assert.equal(tokenStore.size, 0);
  } finally {
    await fastify.close();
  }
});

test("signup route creates a user who can then log in and receive a valid jwt access token", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const tokenStore = createTokenStore();
  const userStore = createUserStore([]);
  const fastify = await createServer(
    defaultServerConfig,
    authorizationCodeStore,
    tokenStore,
    userStore,
  );
  const address = await fastify.listen({
    host: "127.0.0.1",
    port: 0,
  });

  try {
    const signupResponse = await submitSignupForm(address, {
      client_id: "client-id-jwt",
      response_type: "code",
      redirect_uri: "http://localhost:3000/callback",
      username: "new-user",
      password: "new-password",
    });

    assert.equal(signupResponse.status, 302);
    assert.equal(userStore.loadUser("new-user")?.password, "new-password");

    const authorizationResponse = await authorizeClient(
      address,
      "client-id-jwt",
      {
        credentials: {
          username: "new-user",
          password: "new-password",
        },
      },
    );

    assert.equal(authorizationResponse.status, 302);

    const redirectUrl = getRedirectUrl(authorizationResponse);
    const code = redirectUrl.searchParams.get("code");
    assert.notEqual(code, null);
    assert.equal(authorizationCodeStore.has(code), true);

    const tokenResponse = await fetchTokenEndpoint(
      address,
      code,
      "client-id-jwt",
      "other-test-client-secret",
    );

    assert.equal(tokenResponse.status, 200);

    const tokenResponseBody = (await tokenResponse.json()) as {
      access_token: string;
      token_type: string;
    };

    assert.equal(tokenResponseBody.token_type, "Bearer");
    assert.equal(typeof tokenResponseBody.access_token, "string");
    assert.notEqual(tokenResponseBody.access_token.length, 0);

    const jwks = createRemoteJWKSet(
      new URL(`${address}${new URL(defaultServerConfig.jwksUri).pathname}`),
    );
    // Check JWT is valid according to our published JWKS public keys.
    const verified = await jwtVerify(tokenResponseBody.access_token, jwks, {
      algorithms: ["RS256"],
      issuer: defaultServerConfig.issuer,
      audience: defaultServerConfig.issuer,
    });

    assert.equal(verified.protectedHeader.alg, "RS256");
    assert.equal(verified.payload.iss, defaultServerConfig.issuer);
    assert.equal(verified.payload.aud, defaultServerConfig.issuer);
    assert.equal(verified.payload.sub, "new-user"); // Check sub matches our new user.
    assert.equal(verified.payload.client_id, "client-id-jwt");
    assert.equal(typeof verified.payload.jti, "string");
    assert.notEqual(verified.payload.jti.length, 0);
    assert.equal(typeof verified.payload.iat, "number");
    assert.equal(typeof verified.payload.exp, "number");
    assert.ok(verified.payload.exp > verified.payload.iat);

    assert.equal(authorizationCodeStore.has(code), false);
    assert.equal(tokenStore.size, 0);
  } finally {
    await fastify.close();
  }
});

async function authorizeClient(
  address: string,
  clientId: string,
  {
    credentials = {
      username: "test-user",
      password: "test-password",
    },
    authorizationRequest = {},
  }: {
    credentials?: {
      username: string;
      password: string;
    };
    authorizationRequest?: Record<string, string>;
  } = {
    credentials: {
      username: "test-user",
      password: "test-password",
    },
  },
) {
  const authorizationPath = new URL(defaultServerConfig.authorizationEndpoint)
    .pathname;
  const requestParams = {
    client_id: clientId,
    response_type: "code",
    redirect_uri: "http://localhost:3000/callback",
    ...authorizationRequest,
  };

  // Fetch the authorization request.
  const queryString = new URLSearchParams(requestParams).toString();
  const loginPageResponse = await fetch(
    `${address}${authorizationPath}?${queryString}`,
    {
      redirect: "manual",
    },
  );
  assert.equal(loginPageResponse.status, 200);

  // Submit the login form.
  const loginRequestBody = new URLSearchParams({
    ...requestParams,
    username: credentials.username,
    password: credentials.password,
  }).toString();
  return await fetch(`${address}${authorizationPath}`, {
    headers: {
      "content-type": "application/x-www-form-urlencoded",
    },
    method: "POST",
    body: loginRequestBody,
    redirect: "manual",
  });
}

async function fetchTokenEndpoint(
  address: string,
  code: string,
  clientId: string,
  clientSecret: string,
  tokenRequestBody: Record<string, string> = {},
) {
  const tokenPath = new URL(defaultServerConfig.tokenEndpoint).pathname;
  const requestBody = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: "http://localhost:3000/callback",
    ...tokenRequestBody,
  }).toString();

  return await fetch(`${address}${tokenPath}`, {
    headers: {
      authorization: createBasicAuthHeader(clientId, clientSecret),
      "content-type": "application/x-www-form-urlencoded",
    },
    method: "POST",
    body: requestBody,
  });
}

async function submitSignupForm(
  address: string,
  formData: Record<string, string>,
) {
  const requestBody = new URLSearchParams(formData).toString();

  return await fetch(`${address}/signup`, {
    headers: {
      "content-type": "application/x-www-form-urlencoded",
    },
    method: "POST",
    body: requestBody,
    redirect: "manual",
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

function createS256CodeChallenge(codeVerifier: string) {
  return createHash("sha256").update(codeVerifier).digest("base64url");
}
