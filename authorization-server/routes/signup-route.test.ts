import assert from "node:assert/strict";
import test from "node:test";
import { createAuthorizationCodeStore } from "../stores/authorization-code-store.ts";
import { ordersApiResource } from "../config/resources-config.ts";
import type { ServerConfig } from "../config/server-config.ts";
import { createServer } from "../server.ts";
import { getTestServerConfig } from "../test/test-utils.ts";
import { createUserStore } from "../stores/user-store.ts";
import { isUuidV4 } from "../utils/uuid.ts";

const defaultServerConfig = getTestServerConfig();

test("GET signup route renders a signup form that preserves the authorization request", async function () {
  const response = await fetchSignupPage({
    client_id: "client-id-opaque",
    response_type: "code",
    redirect_uri: "http://localhost:3000/callback",
    scope: "openid profile",
    resource: ordersApiResource,
    nonce: "nonce-value-123",
    state: "state-value-123",
    code_challenge: "challenge-value-123",
    code_challenge_method: "S256",
  });

  assert.equal(response.status, 200);
  assert.equal(
    response.headers.get("content-type"),
    "text/html; charset=utf-8",
  );

  const html = await response.text();
  assert.match(html, /<form method="post" action="\/signup">/);
  assert.match(html, /name="client_id" value="client-id-opaque"/);
  assert.match(html, /name="response_type" value="code"/);
  assert.match(
    html,
    /name="redirect_uri" value="http:\/\/localhost:3000\/callback"/,
  );
  assert.match(html, /name="scope" value="openid profile"/);
  assert.match(
    html,
    /name="resource" value="https:\/\/orders-api.example.test"/,
  );
  assert.match(html, /name="nonce" value="nonce-value-123"/);
  assert.match(html, /name="state" value="state-value-123"/);
  assert.match(html, /name="code_challenge" value="challenge-value-123"/);
  assert.match(html, /name="code_challenge_method" value="S256"/);
  assert.match(html, /name="name" autocomplete="name" value="" required/);
  assert.match(
    html,
    /href="\/authorize\?client_id=client-id-opaque&amp;response_type=code&amp;redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&amp;state=state-value-123&amp;scope=openid\+profile&amp;resource=https%3A%2F%2Forders-api.example.test&amp;nonce=nonce-value-123&amp;code_challenge=challenge-value-123&amp;code_challenge_method=S256"/,
  );
});

test("POST signup route requires username, name and password", async function () {
  const response = await submitSignupForm({
    client_id: "client-id-opaque",
    response_type: "code",
    redirect_uri: "http://localhost:3000/callback",
    username: "new-user",
    name: "New User",
  });

  assert.equal(response.status, 400);
  assert.equal(
    response.headers.get("content-type"),
    "text/html; charset=utf-8",
  );

  const html = await response.text();
  assert.match(html, /Username, name and password are required/);
  assert.match(html, /name="username" autocomplete="username" required/);
  assert.match(
    html,
    /name="name" autocomplete="name" value="New User" required/,
  );
});

test("POST signup route rejects duplicate usernames", async function () {
  const response = await submitSignupForm(
    {
      client_id: "client-id-opaque",
      response_type: "code",
      redirect_uri: "http://localhost:3000/callback",
      username: "existing-user",
      name: "New User",
      password: "new-password",
    },
    createUserStore([
      {
        userId: "existing-user-id",
        username: "existing-user",
        password: "existing-password",
        name: "Jane Smith",
      },
    ]),
  );

  assert.equal(response.status, 409);
  assert.equal(
    response.headers.get("content-type"),
    "text/html; charset=utf-8",
  );

  const html = await response.text();
  assert.match(html, /That username already exists/);
  assert.match(html, /name="username" autocomplete="username" required/);
});

test("POST signup route creates a user and redirects back to the authorization endpoint", async function () {
  const userStore = createUserStore([]);
  const response = await submitSignupForm(
    {
      client_id: "client-id-opaque",
      response_type: "code",
      redirect_uri: "http://localhost:3000/callback",
      scope: "openid profile",
      resource: ordersApiResource,
      nonce: "nonce-value-123",
      state: "state-value-123",
      code_challenge: "challenge-value-123",
      code_challenge_method: "S256",
      username: "new-user",
      name: "New User",
      password: "new-password",
    },
    userStore,
  );

  assert.equal(response.status, 302);
  const newUser = userStore.loadUserByUsername("new-user");
  assert.notEqual(newUser, undefined);
  assert.equal(isUuidV4(newUser.userId), true);
  assert.equal(newUser.password, "new-password");
  assert.equal(newUser.name, "New User");
  assert.equal(
    response.headers.get("location"),
    "/authorize?client_id=client-id-opaque&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&state=state-value-123&scope=openid+profile&resource=https%3A%2F%2Forders-api.example.test&nonce=nonce-value-123&code_challenge=challenge-value-123&code_challenge_method=S256",
  );
});

async function fetchSignupPage(
  queryParams: Record<string, string>,
  serverConfig: ServerConfig = defaultServerConfig,
) {
  const fastify = await createServer(
    serverConfig,
    createAuthorizationCodeStore(),
  );
  const address = await fastify.listen({
    host: "127.0.0.1",
    port: 0,
  });

  try {
    const queryString = new URLSearchParams(queryParams).toString();
    return await fetch(`${address}/signup?${queryString}`, {
      redirect: "manual",
    });
  } finally {
    await fastify.close();
  }
}

async function submitSignupForm(
  formData: Record<string, string>,
  userStore = createUserStore(),
  serverConfig: ServerConfig = defaultServerConfig,
) {
  const fastify = await createServer(
    serverConfig,
    createAuthorizationCodeStore(),
    undefined,
    userStore,
  );
  const address = await fastify.listen({
    host: "127.0.0.1",
    port: 0,
  });

  try {
    const requestBody = new URLSearchParams(formData).toString();

    return await fetch(`${address}/signup`, {
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
