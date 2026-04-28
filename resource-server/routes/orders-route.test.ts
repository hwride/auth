import assert from "node:assert/strict";
import type { OutgoingHttpHeaders } from "node:http";
import test from "node:test";
import { createServer } from "../resource-server.ts";
import { janeUserId, testUserId } from "../stores/order-store.ts";
import {
  createMockAuthServer,
  type MockAuthServer,
} from "../test-utils/mock-auth-server.ts";

const resourceId = "https://orders-api.example.test";

test("GET /orders returns orders for the authenticated user from the order store", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: testUserId,
      scope: "orders:read",
      aud: resourceId,
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 200);
    assert.equal(
      response.headers["content-type"],
      "application/json; charset=utf-8",
    );

    const body = response.json() as {
      orders: Array<{ orderId: string; userId: string }>;
    };

    assert.deepEqual(body.orders, [
      { orderId: "order-001", userId: testUserId },
      { orderId: "order-002", userId: testUserId },
    ]);
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders/:id returns an individual order when it is owned by the authenticated user", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: testUserId,
      scope: "orders:read",
      aud: resourceId,
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders/order-001",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 200);
    assert.deepEqual(response.json(), {
      order: { orderId: "order-001", userId: testUserId },
    });
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders/:id returns 403 when the order is owned by a different user", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: testUserId,
      scope: "orders:read",
      aud: resourceId,
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders/order-003",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 403);
    assert.deepEqual(response.json(), { error: "forbidden" });
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders/:id returns 404 when no order with the given id exists", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: testUserId,
      scope: "orders:read",
      aud: resourceId,
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders/order-999",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 404);
    assert.deepEqual(response.json(), { error: "not_found" });
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders returns 403 when the access token does not include orders:read scope", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: testUserId,
      scope: "openid profile",
      aud: resourceId,
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 403);
    assert.equal(
      getHeader(response.headers, "www-authenticate"),
      `Bearer realm="resource-server", error="insufficient_scope", scope="orders:read"`,
    );
    assert.deepEqual(response.json(), { error: "insufficient_scope" });
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders/:id returns 403 when the access token does not include orders:read scope", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: janeUserId,
      scope: "openid profile",
      aud: resourceId,
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders/order-003",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 403);
    assert.equal(
      getHeader(response.headers, "www-authenticate"),
      `Bearer realm="resource-server", error="insufficient_scope", scope="orders:read"`,
    );
    assert.deepEqual(response.json(), { error: "insufficient_scope" });
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders returns 401 when authorization header is missing", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders",
    });

    assert.equal(response.statusCode, 401);
    assert.equal(
      getHeader(response.headers, "www-authenticate"),
      `Bearer realm="resource-server"`,
    );
    assert.equal(response.body, "");
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders returns 401 without error details when auth scheme is unsupported", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders",
      headers: {
        authorization: "Basic abc123",
      },
    });

    assert.equal(response.statusCode, 401);
    assert.equal(
      getHeader(response.headers, "www-authenticate"),
      `Bearer realm="resource-server"`,
    );
    assert.equal(response.body, "");
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders returns 401 when token verification fails", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders",
      headers: {
        authorization: "Bearer not-a-jwt",
      },
    });

    assert.equal(response.statusCode, 401);
    assert.match(
      getHeader(response.headers, "www-authenticate"),
      /ERR_JWS_INVALID/,
    );
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders returns 401 when issuer does not match", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      iss: "https://different-issuer.example.test",
      sub: testUserId,
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 401);
    assert.match(
      getHeader(response.headers, "www-authenticate"),
      /ERR_JWT_CLAIM_VALIDATION_FAILED/,
    );
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders returns 401 when aud is missing", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: testUserId,
      scope: "orders:read",
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 401);
    assert.match(
      getHeader(response.headers, "www-authenticate"),
      /ERR_JWT_CLAIM_VALIDATION_FAILED/,
    );
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders returns 401 when aud does not match", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: testUserId,
      scope: "orders:read",
      aud: "invalid-aud",
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 401);
    assert.match(
      getHeader(response.headers, "www-authenticate"),
      /ERR_JWT_CLAIM_VALIDATION_FAILED/,
    );
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /orders rejects expired tokens", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: testUserId,
      exp: Math.floor(Date.now() / 1000) - 10,
      nbf: Math.floor(Date.now() / 1000) - 60,
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/orders",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 401);
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

function createTestResourceServer(authServer: MockAuthServer) {
  return createServer({
    resourceId,
    acceptedAccessTokenAlgorithms: ["RS256"],
    authServerBase: authServer.authServerBase,
    issuer: authServer.issuer,
    jwksUri: authServer.jwksUri,
  });
}

function getHeader(headers: OutgoingHttpHeaders, headerName: string): string {
  const header = headers[headerName];

  if (Array.isArray(header)) {
    return header.join(", ");
  }

  return header === undefined ? "" : String(header);
}
