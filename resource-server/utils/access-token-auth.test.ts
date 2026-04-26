import assert from "node:assert/strict";
import test from "node:test";
import type { FastifyReply, FastifyRequest } from "fastify";
import { createMockAuthServer } from "../test-utils/mock-auth-server.ts";
import { authenticateAccessToken } from "./access-token-auth.ts";

const verificationConfig = {
  issuer: "https://issuer.example",
  jwksUri: "https://issuer.example/.well-known/jwks.json",
};

test("authenticateAccessToken returns a bearer challenge when authorization header is missing", async () => {
  const response = createResponse();

  const authenticatedUser = await authenticateAccessToken(
    createRequest(),
    response.fastifyReply,
    verificationConfig,
  );

  assert.equal(authenticatedUser, undefined);
  assert.equal(response.statusCode, 401);
  assert.equal(
    response.headers["WWW-Authenticate"],
    `Bearer realm="resource-server"`,
  );
  assert.equal(response.body, undefined);
});

test("authenticateAccessToken returns a bearer challenge when auth scheme is unsupported", async () => {
  const response = createResponse();

  const authenticatedUser = await authenticateAccessToken(
    createRequest("Basic abc123"),
    response.fastifyReply,
    verificationConfig,
  );

  assert.equal(authenticatedUser, undefined);
  assert.equal(response.statusCode, 401);
  assert.equal(
    response.headers["WWW-Authenticate"],
    `Bearer realm="resource-server"`,
  );
  assert.equal(response.body, undefined);
});

test("authenticateAccessToken returns invalid_token when bearer token verification fails", async () => {
  const response = createResponse();

  const authenticatedUser = await authenticateAccessToken(
    createRequest("Bearer not-a-jwt"),
    response.fastifyReply,
    verificationConfig,
  );

  assert.equal(authenticatedUser, undefined);
  assert.equal(response.statusCode, 401);
  assert.equal(
    response.headers["WWW-Authenticate"],
    `Bearer realm="resource-server", error="invalid_token", error_description="Invalid access token"`,
  );
  assert.deepEqual(response.body, { error: "invalid_token" });
});

test("authenticateAccessToken returns the token subject when bearer token is valid", async () => {
  const authServer = await createMockAuthServer();
  const response = createResponse();

  try {
    const token = await authServer.createAccessToken({
      sub: "user-123",
    });

    const authenticatedUser = await authenticateAccessToken(
      createRequest(`Bearer ${token}`),
      response.fastifyReply,
      {
        issuer: authServer.issuer,
        jwksUri: authServer.jwksUri,
      },
    );

    assert.deepEqual(authenticatedUser, { sub: "user-123" });
    assert.equal(response.statusCode, undefined);
    assert.deepEqual(response.headers, {});
    assert.equal(response.body, undefined);
  } finally {
    await authServer.close();
  }
});

type MockResponse = {
  body: unknown;
  fastifyReply: FastifyReply;
  headers: Record<string, string>;
  statusCode: number | undefined;
};

function createResponse(): MockResponse {
  const reply: MockResponse = {
    fastifyReply: undefined as unknown as FastifyReply,
    body: undefined,
    headers: {},
    statusCode: undefined,
  };

  const fastifyReply = {
    header(name: string, value: string) {
      reply.headers[name] = value;
      return fastifyReply;
    },
    status(statusCode: number) {
      reply.statusCode = statusCode;
      return fastifyReply;
    },
    send(body?: unknown) {
      reply.body = body;
      return fastifyReply;
    },
  } as FastifyReply;

  reply.fastifyReply = fastifyReply;
  return reply;
}

function createRequest(authorization?: string): FastifyRequest {
  const headers: { authorization?: string } = {};

  if (authorization !== undefined) {
    headers.authorization = authorization;
  }

  return { headers } as FastifyRequest;
}
