import assert from "node:assert/strict";
import test from "node:test";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { createServer } from "./server.ts";
import { ordersApiResource } from "./config/resources-config.ts";
import { createAuthorizationCodeStore } from "./stores/authorization-code-store.ts";
import { createTokenStore } from "./stores/token-store.ts";
import { getTestServerConfig } from "./test/test-utils.ts";

const defaultServerConfig = getTestServerConfig();

test("authorization code flow defaults access token aud to issuer when no resource indicator is requested", async function () {
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
    const authorizationResponse = await authorizeClient(address);
    assert.equal(authorizationResponse.status, 302);

    const redirectUrl = getRedirectUrl(authorizationResponse);
    const code = redirectUrl.searchParams.get("code");
    assert.notEqual(code, null);

    const tokenResponse = await fetchTokenEndpoint(address, code);
    assert.equal(tokenResponse.status, 200);

    const tokenResponseBody = (await tokenResponse.json()) as {
      access_token: string;
    };

    const verified = await verifyAccessToken(
      address,
      tokenResponseBody.access_token,
      defaultServerConfig.issuer,
    );
    assert.equal(verified.payload.aud, defaultServerConfig.issuer);
  } finally {
    await fastify.close();
  }
});

test("authorization code flow sets access token aud to orders API resource when resource indicator is requested without openid scope", async function () {
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
    const authorizationResponse = await authorizeClient(address, {
      resource: ordersApiResource,
    });
    assert.equal(authorizationResponse.status, 302);

    const redirectUrl = getRedirectUrl(authorizationResponse);
    const code = redirectUrl.searchParams.get("code");
    assert.notEqual(code, null);

    const tokenResponse = await fetchTokenEndpoint(address, code);
    assert.equal(tokenResponse.status, 200);

    const tokenResponseBody = (await tokenResponse.json()) as {
      access_token: string;
    };

    const verified = await verifyAccessToken(
      address,
      tokenResponseBody.access_token,
      ordersApiResource,
    );
    assert.equal(verified.payload.aud, ordersApiResource);
  } finally {
    await fastify.close();
  }
});

test("authorization code flow includes issuer and orders API resource audiences when openid scope and resource indicator are requested", async function () {
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
    const authorizationResponse = await authorizeClient(address, {
      resource: ordersApiResource,
      scope: "openid",
    });
    assert.equal(authorizationResponse.status, 302);

    const redirectUrl = getRedirectUrl(authorizationResponse);
    const code = redirectUrl.searchParams.get("code");
    assert.notEqual(code, null);

    const tokenResponse = await fetchTokenEndpoint(address, code);
    assert.equal(tokenResponse.status, 200);

    const tokenResponseBody = (await tokenResponse.json()) as {
      access_token: string;
    };

    const verified = await verifyAccessToken(
      address,
      tokenResponseBody.access_token,
      ordersApiResource,
    );
    assert.deepEqual(verified.payload.aud, [
      defaultServerConfig.issuer,
      ordersApiResource,
    ]);
  } finally {
    await fastify.close();
  }
});

test("refresh token flow preserves resource audience from the original authorization request", async function () {
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
    const authorizationResponse = await authorizeClient(address, {
      resource: ordersApiResource,
      scope: "offline_access orders:read",
    });
    assert.equal(authorizationResponse.status, 302);

    const redirectUrl = getRedirectUrl(authorizationResponse);
    const code = redirectUrl.searchParams.get("code");
    assert.notEqual(code, null);

    const tokenResponse = await fetchTokenEndpoint(address, code);
    assert.equal(tokenResponse.status, 200);

    const tokenResponseBody = (await tokenResponse.json()) as {
      access_token: string;
      refresh_token: string;
    };
    assert.equal(typeof tokenResponseBody.refresh_token, "string");

    const initialAccessToken = await verifyAccessToken(
      address,
      tokenResponseBody.access_token,
      ordersApiResource,
    );
    assert.equal(initialAccessToken.payload.aud, ordersApiResource);

    const refreshResponse = await fetchRefreshTokenEndpoint(
      address,
      tokenResponseBody.refresh_token,
    );
    assert.equal(refreshResponse.status, 200);

    const refreshResponseBody = (await refreshResponse.json()) as {
      access_token: string;
    };

    const refreshedAccessToken = await verifyAccessToken(
      address,
      refreshResponseBody.access_token,
      ordersApiResource,
    );
    assert.equal(refreshedAccessToken.payload.aud, ordersApiResource);
  } finally {
    await fastify.close();
  }
});

test("authorization endpoint rejects unknown resource indicators", async function () {
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
    const response = await fetchAuthorizationRequest(address, {
      resource: "https://payments-api.example.test",
    });

    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), {
      error: "invalid_target",
      error_description: "Unsupported resource indicator",
    });
    assert.equal(authorizationCodeStore.isEmpty(), true);
  } finally {
    await fastify.close();
  }
});

async function authorizeClient(
  address: string,
  authorizationRequest: Record<string, string> = {},
) {
  const loginPageResponse = await fetchAuthorizationRequest(
    address,
    authorizationRequest,
  );
  assert.equal(loginPageResponse.status, 200);

  const authorizationPath = new URL(defaultServerConfig.authorizationEndpoint)
    .pathname;
  const requestParams = getAuthorizationRequestParams(authorizationRequest);
  const loginRequestBody = new URLSearchParams({
    ...requestParams,
    username: "user",
    password: "password",
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

async function fetchAuthorizationRequest(
  address: string,
  authorizationRequest: Record<string, string>,
) {
  const authorizationPath = new URL(defaultServerConfig.authorizationEndpoint)
    .pathname;
  const queryString = new URLSearchParams(
    getAuthorizationRequestParams(authorizationRequest),
  ).toString();

  return await fetch(`${address}${authorizationPath}?${queryString}`, {
    redirect: "manual",
  });
}

async function fetchTokenEndpoint(address: string, code: string) {
  const tokenPath = new URL(defaultServerConfig.tokenEndpoint).pathname;
  const requestBody = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: "http://localhost:3000/callback",
  }).toString();

  return await fetch(`${address}${tokenPath}`, {
    headers: {
      authorization: createBasicAuthHeader(
        "client-id-jwt",
        "other-test-client-secret",
      ),
      "content-type": "application/x-www-form-urlencoded",
    },
    method: "POST",
    body: requestBody,
  });
}

async function fetchRefreshTokenEndpoint(address: string, refreshToken: string) {
  const tokenPath = new URL(defaultServerConfig.tokenEndpoint).pathname;
  const requestBody = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
  }).toString();

  return await fetch(`${address}${tokenPath}`, {
    headers: {
      authorization: createBasicAuthHeader(
        "client-id-jwt",
        "other-test-client-secret",
      ),
      "content-type": "application/x-www-form-urlencoded",
    },
    method: "POST",
    body: requestBody,
  });
}

async function verifyAccessToken(
  address: string,
  accessToken: string,
  audience: string,
) {
  const jwks = createRemoteJWKSet(
    new URL(`${address}${new URL(defaultServerConfig.jwksUri).pathname}`),
  );

  return await jwtVerify(accessToken, jwks, {
    algorithms: ["RS256"],
    issuer: defaultServerConfig.issuer,
    audience,
  });
}

function getAuthorizationRequestParams(
  authorizationRequest: Record<string, string>,
) {
  return {
    client_id: "client-id-jwt",
    response_type: "code",
    redirect_uri: "http://localhost:3000/callback",
    ...authorizationRequest,
  };
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
