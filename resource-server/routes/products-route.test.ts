import assert from "node:assert/strict";
import type { OutgoingHttpHeaders } from "node:http";
import test from "node:test";
import { createServer } from "../resource-server.ts";
import {
  createMockAuthServer,
  type MockAuthServer,
} from "../test-utils/mock-auth-server.ts";

const adminUserId = "00000000-0000-0000-0000-000000000000";
const ordersApiResourceId = "https://orders-api.example.test";
const productsApiResourceId = "https://products-api.example.test";

test("GET /products returns all products when the access token has products audience and products:read scope", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: adminUserId,
      scope: "products:read",
      aud: productsApiResourceId,
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/products",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 200);
    assert.deepEqual(response.json(), {
      products: [
        { productId: "product-001", name: "Keyboard" },
        { productId: "product-002", name: "Mouse" },
      ],
    });
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /products/:id returns a product when the access token has products audience and products:read scope", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: adminUserId,
      scope: "products:read",
      aud: productsApiResourceId,
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/products/product-001",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 200);
    assert.deepEqual(response.json(), {
      product: { productId: "product-001", name: "Keyboard" },
    });
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /products returns 401 when the access token has the orders audience", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: adminUserId,
      scope: "products:read",
      aud: ordersApiResourceId,
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/products",
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

test("GET /products/:id returns 401 when the access token has the orders audience", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: adminUserId,
      scope: "products:read",
      aud: ordersApiResourceId,
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/products/product-001",
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

test("GET /products returns 403 when the access token does not include products:read scope", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: adminUserId,
      scope: "orders:read",
      aud: productsApiResourceId,
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/products",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 403);
    assert.equal(
      getHeader(response.headers, "www-authenticate"),
      `Bearer realm="resource-server", error="insufficient_scope", scope="products:read"`,
    );
    assert.deepEqual(response.json(), { error: "insufficient_scope" });
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /products/:id returns 403 when the access token does not include products:read scope", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: adminUserId,
      scope: "orders:read",
      aud: productsApiResourceId,
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/products/product-001",
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    assert.equal(response.statusCode, 403);
    assert.equal(
      getHeader(response.headers, "www-authenticate"),
      `Bearer realm="resource-server", error="insufficient_scope", scope="products:read"`,
    );
    assert.deepEqual(response.json(), { error: "insufficient_scope" });
  } finally {
    await resourceServer.close();
    await authServer.close();
  }
});

test("GET /products/:id returns 404 when no product with the given id exists", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const token = await authServer.createAccessToken({
      sub: adminUserId,
      scope: "products:read",
      aud: productsApiResourceId,
    });

    const response = await resourceServer.inject({
      method: "GET",
      url: "/products/product-999",
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

test("GET /products/:id returns 401 when authorization header is missing", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const response = await resourceServer.inject({
      method: "GET",
      url: "/products/product-001",
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

test("GET /products returns 401 when authorization header is missing", async () => {
  const authServer = await createMockAuthServer();
  const resourceServer = createTestResourceServer(authServer);

  try {
    const response = await resourceServer.inject({
      method: "GET",
      url: "/products",
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

function createTestResourceServer(authServer: MockAuthServer) {
  return createServer({
    resourceIds: {
      ordersApi: ordersApiResourceId,
      productsApi: productsApiResourceId,
    },
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
