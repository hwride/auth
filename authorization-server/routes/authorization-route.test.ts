import assert from "node:assert/strict";
import test from "node:test";
import {
  createAuthorizationCodeStore,
  type AuthorizationCodeStore,
} from "../stores/authorization-code-store.ts";
import { ordersApiResource } from "../config/resources-config.ts";
import type { ServerConfig } from "../config/server-config.ts";
import { testUserId, defaultUsers } from "../default-users.ts";
import { createServer } from "../server.ts";
import { getTestServerConfig } from "../test/test-utils.ts";
import { createUserStore, type UserStore } from "../stores/user-store.ts";

const defaultServerConfig = getTestServerConfig();

test("GET authorization endpoint renders a login form for a valid request", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const response = await fetchAuthorizationLoginPage(
    {
      client_id: "client-id-opaque",
      response_type: "code",
      redirect_uri: "http://localhost:3000/callback",
    },
    defaultServerConfig,
    authorizationCodeStore,
  );

  assert.equal(response.status, 200);
  assert.equal(
    response.headers.get("content-type"),
    "text/html; charset=utf-8",
  );
  assert.match(await response.text(), /<form method="post"/);
  assert.equal(authorizationCodeStore.isEmpty(), true);
});

test("POST authorization endpoint redirects with an authorization code after login", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const response = await submitAuthorizationLogin(
    {
      client_id: "client-id-opaque",
      response_type: "code",
      redirect_uri: "http://localhost:3000/callback",
    },
    defaultServerConfig,
    authorizationCodeStore,
  );

  assert.equal(response.status, 302);

  const redirectUrl = getRedirectUrl(response);
  const code = redirectUrl.searchParams.get("code");
  assert.equal(redirectUrl.origin, "http://localhost:3000");
  assert.equal(redirectUrl.pathname, "/callback");
  assert.notEqual(code, null);

  const codeRecord = authorizationCodeStore.loadAuthorizationCode(code);
  assert.deepEqual(
    {
      clientId: codeRecord.clientId,
      subject: codeRecord.subject,
      redirectUri: codeRecord.redirectUri,
    },
    {
      clientId: "client-id-opaque",
      subject: testUserId,
      redirectUri: "http://localhost:3000/callback",
    },
  );
  assert.ok(codeRecord.expiresAt > Date.now());
});

test("POST authorization endpoint echoes state in the redirect when provided", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const response = await submitAuthorizationLogin(
    {
      client_id: "client-id-opaque",
      response_type: "code",
      redirect_uri: "http://localhost:3000/callback",
      state: "state-value-123",
    },
    defaultServerConfig,
    authorizationCodeStore,
  );

  assert.equal(response.status, 302);

  const redirectUrl = getRedirectUrl(response);
  assert.notEqual(redirectUrl.searchParams.get("code"), null);
  assert.equal(redirectUrl.searchParams.get("state"), "state-value-123");
});

test("POST authorization endpoint stores PKCE parameters with the authorization code", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const response = await submitAuthorizationLogin(
    {
      client_id: "client-id-opaque",
      response_type: "code",
      redirect_uri: "http://localhost:3000/callback",
      code_challenge: "challenge-value-123",
      code_challenge_method: "S256",
    },
    defaultServerConfig,
    authorizationCodeStore,
  );

  assert.equal(response.status, 302);

  const redirectUrl = getRedirectUrl(response);
  const code = redirectUrl.searchParams.get("code");
  assert.notEqual(code, null);

  const codeRecord = authorizationCodeStore.loadAuthorizationCode(code);
  assert.deepEqual(
    {
      clientId: codeRecord.clientId,
      subject: codeRecord.subject,
      redirectUri: codeRecord.redirectUri,
      codeChallenge: codeRecord.codeChallenge,
      codeChallengeMethod: codeRecord.codeChallengeMethod,
    },
    {
      clientId: "client-id-opaque",
      subject: testUserId,
      redirectUri: "http://localhost:3000/callback",
      codeChallenge: "challenge-value-123",
      codeChallengeMethod: "S256",
    },
  );
  assert.ok(codeRecord.expiresAt > Date.now());
});

test("POST authorization endpoint stores scope with the authorization code", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const response = await submitAuthorizationLogin(
    {
      client_id: "client-id-opaque",
      response_type: "code",
      redirect_uri: "http://localhost:3000/callback",
      scope: "read:profile write:profile",
    },
    defaultServerConfig,
    authorizationCodeStore,
  );

  assert.equal(response.status, 302);

  const redirectUrl = getRedirectUrl(response);
  const code = redirectUrl.searchParams.get("code");
  assert.notEqual(code, null);

  const codeRecord = authorizationCodeStore.loadAuthorizationCode(code);
  assert.equal(codeRecord.scope, "read:profile write:profile");
  assert.ok(codeRecord.expiresAt > Date.now());
});

test("POST authorization endpoint strips orders:read scope for users that do not have it", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const response = await submitAuthorizationLogin(
    {
      client_id: "client-id-opaque",
      response_type: "code",
      redirect_uri: "http://localhost:3000/callback",
      scope: "openid orders:read profile",
    },
    defaultServerConfig,
    authorizationCodeStore,
    {
      username: "jane",
      password: "password",
    },
  );

  assert.equal(response.status, 302);

  const redirectUrl = getRedirectUrl(response);
  const code = redirectUrl.searchParams.get("code");
  assert.notEqual(code, null);

  const codeRecord = authorizationCodeStore.loadAuthorizationCode(code);
  assert.equal(codeRecord.scope, "openid profile");
  assert.ok(codeRecord.expiresAt > Date.now());
});

test("POST authorization endpoint stores nonce with the authorization code", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const response = await submitAuthorizationLogin(
    {
      client_id: "client-id-opaque",
      response_type: "code",
      redirect_uri: "http://localhost:3000/callback",
      scope: "openid profile",
      nonce: "nonce-value-123",
    },
    defaultServerConfig,
    authorizationCodeStore,
  );

  assert.equal(response.status, 302);

  const redirectUrl = getRedirectUrl(response);
  const code = redirectUrl.searchParams.get("code");
  assert.notEqual(code, null);

  const codeRecord = authorizationCodeStore.loadAuthorizationCode(code);
  assert.equal(codeRecord.nonce, "nonce-value-123");
  assert.ok(codeRecord.expiresAt > Date.now());
});

test("POST authorization endpoint sets code expiry from configured lifetime", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const response = await submitAuthorizationLogin(
    {
      client_id: "client-id-opaque",
      response_type: "code",
      redirect_uri: "http://localhost:3000/callback",
    },
    getTestServerConfig({
      authorizationCodeLifetimeSeconds: 2,
    }),
    authorizationCodeStore,
  );

  assert.equal(response.status, 302);

  const redirectUrl = getRedirectUrl(response);
  const code = redirectUrl.searchParams.get("code");
  assert.notEqual(code, null);

  const codeRecord = authorizationCodeStore.loadAuthorizationCode(code);
  assert.ok(codeRecord.expiresAt > Date.now());
  assert.ok(codeRecord.expiresAt <= Date.now() + 2_000);
});

test("GET authorization endpoint rejects requests missing redirect_uri", async function () {
  const response = await fetchAuthorizationLoginPage({
    client_id: "client-id-opaque",
    response_type: "code",
  });

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), {
    error: "invalid_request",
    error_description: "Missing redirect_uri",
  });
});

test("GET authorization endpoint rejects invalid client_id", async function () {
  const response = await fetchAuthorizationLoginPage({
    client_id: "not-client-id-opaque",
    response_type: "code",
    redirect_uri: "http://localhost:3000/callback",
  });

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), {
    error: "invalid_request",
    error_description: "Invalid client_id",
  });
});

test("GET authorization endpoint rejects invalid redirect_uri", async function () {
  const response = await fetchAuthorizationLoginPage({
    client_id: "client-id-opaque",
    response_type: "code",
    redirect_uri: "https://client.example.test/callback",
  });

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), {
    error: "invalid_request",
    error_description: "Invalid redirect_uri",
  });
});

test("GET authorization endpoint rejects unsupported response_type", async function () {
  const response = await fetchAuthorizationLoginPage({
    client_id: "client-id-opaque",
    response_type: "token",
    redirect_uri: "http://localhost:3000/callback",
  });

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), {
    error: "unsupported_response_type",
  });
});

test("GET authorization endpoint rejects unsupported code_challenge_method", async function () {
  const response = await fetchAuthorizationLoginPage({
    client_id: "client-id-opaque",
    response_type: "code",
    redirect_uri: "http://localhost:3000/callback",
    code_challenge: "test-challenge",
    code_challenge_method: "S512",
  });

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), {
    error: "invalid_request",
    error_description: "Unsupported code_challenge_method",
  });
});

test("GET authorization endpoint sign up link preserves PKCE parameters", async function () {
  const response = await fetchAuthorizationLoginPage({
    client_id: "client-id-opaque",
    response_type: "code",
    redirect_uri: "http://localhost:3000/callback",
    state: "state-value-123",
    code_challenge: "challenge-value-123",
    code_challenge_method: "S256",
  });

  assert.equal(response.status, 200);

  const html = await response.text();
  assert.match(
    html,
    /href="\/signup\?client_id=client-id-opaque&amp;response_type=code&amp;redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&amp;state=state-value-123&amp;code_challenge=challenge-value-123&amp;code_challenge_method=S256"/,
  );
});

test("GET authorization endpoint sign up link preserves scope parameter", async function () {
  const response = await fetchAuthorizationLoginPage({
    client_id: "client-id-opaque",
    response_type: "code",
    redirect_uri: "http://localhost:3000/callback",
    scope: "openid profile",
  });

  assert.equal(response.status, 200);

  const html = await response.text();
  assert.match(
    html,
    /href="\/signup\?client_id=client-id-opaque&amp;response_type=code&amp;redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&amp;scope=openid\+profile"/,
  );
});

test("GET authorization endpoint sign up link preserves nonce parameter", async function () {
  const response = await fetchAuthorizationLoginPage({
    client_id: "client-id-opaque",
    response_type: "code",
    redirect_uri: "http://localhost:3000/callback",
    scope: "openid profile",
    nonce: "nonce-value-123",
  });

  assert.equal(response.status, 200);

  const html = await response.text();
  assert.match(html, /name="nonce" value="nonce-value-123"/);
  assert.match(
    html,
    /href="\/signup\?client_id=client-id-opaque&amp;response_type=code&amp;redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&amp;scope=openid\+profile&amp;nonce=nonce-value-123"/,
  );
});

test("POST authorization endpoint stores orders API resource indicator with the authorization code", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const response = await submitAuthorizationLogin(
    {
      client_id: "client-id-opaque",
      response_type: "code",
      redirect_uri: "http://localhost:3000/callback",
      resource: ordersApiResource,
    },
    defaultServerConfig,
    authorizationCodeStore,
  );

  assert.equal(response.status, 302);

  const redirectUrl = getRedirectUrl(response);
  const code = redirectUrl.searchParams.get("code");
  assert.notEqual(code, null);

  const codeRecord = authorizationCodeStore.loadAuthorizationCode(code);
  assert.equal(codeRecord.resource, ordersApiResource);
});

test("POST authorization endpoint rejects unsupported resource indicators", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const response = await submitAuthorizationLogin(
    {
      client_id: "client-id-opaque",
      response_type: "code",
      redirect_uri: "http://localhost:3000/callback",
      resource: "https://payments-api.example.test",
    },
    defaultServerConfig,
    authorizationCodeStore,
  );

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), {
    error: "invalid_target",
    error_description: "Unsupported resource indicator",
  });
  assert.equal(authorizationCodeStore.isEmpty(), true);
});

test("POST authorization endpoint rejects resource indicators that are not absolute URIs", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const response = await submitAuthorizationLogin(
    {
      client_id: "client-id-opaque",
      response_type: "code",
      redirect_uri: "http://localhost:3000/callback",
      resource: "orders-api",
    },
    defaultServerConfig,
    authorizationCodeStore,
  );

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), {
    error: "invalid_target",
    error_description: "Unsupported resource indicator",
  });
  assert.equal(authorizationCodeStore.isEmpty(), true);
});

test("POST authorization endpoint rejects resource indicators with fragments", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const response = await submitAuthorizationLogin(
    {
      client_id: "client-id-opaque",
      response_type: "code",
      redirect_uri: "http://localhost:3000/callback",
      resource: `${ordersApiResource}#orders`,
    },
    defaultServerConfig,
    authorizationCodeStore,
  );

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), {
    error: "invalid_target",
    error_description: "Unsupported resource indicator",
  });
  assert.equal(authorizationCodeStore.isEmpty(), true);
});

test("POST authorization endpoint rejects invalid login credentials", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const response = await submitAuthorizationLogin(
    {
      client_id: "client-id-opaque",
      response_type: "code",
      redirect_uri: "http://localhost:3000/callback",
    },
    defaultServerConfig,
    authorizationCodeStore,
    {
      username: "wrong-user",
      password: "wrong-password",
    },
  );

  assert.equal(response.status, 401);
  assert.equal(
    response.headers.get("content-type"),
    "text/html; charset=utf-8",
  );
  assert.match(await response.text(), /Invalid username or password/);
  assert.equal(authorizationCodeStore.isEmpty(), true);
});

test("GET authorization endpoint includes a sign up link", async function () {
  const response = await fetchAuthorizationLoginPage({
    client_id: "client-id-opaque",
    response_type: "code",
    redirect_uri: "http://localhost:3000/callback",
  });

  assert.equal(response.status, 200);
  assert.match(await response.text(), /Sign up/);
});

test("GET authorization endpoint uses the configured endpoint path", async function () {
  const authorizationCodeStore = createAuthorizationCodeStore();
  const response = await fetchAuthorizationLoginPage(
    {
      client_id: "client-id-opaque",
      response_type: "code",
      redirect_uri: "http://localhost:3000/callback",
    },
    getTestServerConfig({
      authorizationEndpoint: "https://login.example.test/oauth2/authorize",
    }),
    authorizationCodeStore,
  );

  assert.equal(response.status, 200);
  assert.match(await response.text(), /<form method="post"/);
});

async function fetchAuthorizationLoginPage(
  queryParams: Record<string, string>,
  serverConfig: ServerConfig = defaultServerConfig,
  authorizationCodeStore: AuthorizationCodeStore = createAuthorizationCodeStore(),
  userStore: UserStore = createUserStore(defaultUsers()),
) {
  const fastify = await createServer(
    serverConfig,
    authorizationCodeStore,
    undefined,
    userStore,
  );
  const address = await fastify.listen({
    host: "127.0.0.1",
    port: 0,
  });

  try {
    const authorizationPath = new URL(serverConfig.authorizationEndpoint)
      .pathname;
    const queryString = new URLSearchParams(queryParams).toString();

    return await fetch(`${address}${authorizationPath}?${queryString}`, {
      redirect: "manual",
    });
  } finally {
    await fastify.close();
  }
}

async function submitAuthorizationLogin(
  formData: Record<string, string>,
  serverConfig: ServerConfig = defaultServerConfig,
  authorizationCodeStore: AuthorizationCodeStore = createAuthorizationCodeStore(),
  credentials: {
    username: string;
    password: string;
  } = {
    username: "user",
    password: "password",
  },
  userStore: UserStore = createUserStore(defaultUsers()),
) {
  const fastify = await createServer(
    serverConfig,
    authorizationCodeStore,
    undefined,
    userStore,
  );
  const address = await fastify.listen({
    host: "127.0.0.1",
    port: 0,
  });

  try {
    const authorizationPath = new URL(serverConfig.authorizationEndpoint)
      .pathname;
    const requestBody = new URLSearchParams({
      ...formData,
      username: credentials.username,
      password: credentials.password,
    }).toString();

    return await fetch(`${address}${authorizationPath}`, {
      headers: {
        "content-type": "application/x-www-form-urlencoded",
      },
      method: "POST",
      body: requestBody,
      redirect: "manual",
    });
  } finally {
    await fastify.close();
  }
}

function getRedirectUrl(response: Response) {
  const location = response.headers.get("location");
  assert.notEqual(location, null);
  return new URL(location);
}
