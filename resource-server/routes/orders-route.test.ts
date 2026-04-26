import assert from "node:assert/strict";
import type { OutgoingHttpHeaders } from "node:http";
import test from "node:test";
import { createServer } from "../resource-server.ts";
import {
  createMockAuthServer,
  type MockAuthServer,
} from "../test-utils/mock-auth-server.ts";

test("GET /orders returns orders with user ID from token subject", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: "user-123",
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
    assert.equal(body.orders.length, 2);
    assert.equal(body.orders[0].userId, "user-123");
    assert.equal(body.orders[1].userId, "user-123");
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
      /Invalid access token/,
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
      sub: "user-123",
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
      /Invalid access token/,
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
      sub: "user-123",
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
