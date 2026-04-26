import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPair, SignJWT } from "jose";
import type { ServerConfig } from "../config/server-config.ts";
import { createServer } from "../server.ts";
import { getTestServerConfig } from "../test/test-utils.ts";

const defaultServerConfig = getTestServerConfig();
type UserinfoResponse = Awaited<
  ReturnType<Awaited<ReturnType<typeof createServer>>["inject"]>
>;

test("GET /userinfo returns a bearer challenge when authorization is missing", async function () {
  const response = await fetchUserinfo();

  assert.equal(response.statusCode, 401);
  assert.equal(
    response.headers["www-authenticate"],
    'Bearer realm="userinfo"',
  );
  assert.equal(response.body, "");
});

test("GET /userinfo rejects malformed bearer tokens", async function () {
  const response = await fetchUserinfo("Bearer not-a-jwt");

  assertInvalidTokenResponse(response);
});

test("GET /userinfo rejects access tokens signed by another key", async function () {
  const wrongSigningKeys = await generateKeyPair(
    defaultServerConfig.jwtSigningAlg,
  );
  const accessToken = await signAccessToken({
    privateKey: wrongSigningKeys.privateKey,
  });

  const response = await fetchUserinfo(`Bearer ${accessToken}`);

  assertInvalidTokenResponse(response);
});

test("GET /userinfo rejects signed tokens that are not access tokens", async function () {
  const accessToken = await signAccessToken({
    tokenType: "JWT",
  });

  const response = await fetchUserinfo(`Bearer ${accessToken}`);

  assertInvalidTokenResponse(response);
});

test("GET /userinfo rejects access tokens without a subject", async function () {
  const accessToken = await signAccessToken({
    includeSubject: false,
  });

  const response = await fetchUserinfo(`Bearer ${accessToken}`);

  assertInvalidTokenResponse(response);
});

test("GET /userinfo rejects access tokens for unknown users", async function () {
  const accessToken = await signAccessToken({
    subject: "missing-user",
  });

  const response = await fetchUserinfo(`Bearer ${accessToken}`);

  assertInvalidTokenResponse(response);
});

test("GET /userinfo returns the subject for valid access tokens without profile scope", async function () {
  const accessToken = await signAccessToken();

  const response = await fetchUserinfo(`Bearer ${accessToken}`);

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.json(), {
    sub: "user",
  });
});

test("GET /userinfo returns the subject and name for valid access tokens with profile scope", async function () {
  const accessToken = await signAccessToken({
    scope: "openid profile",
  });

  const response = await fetchUserinfo(`Bearer ${accessToken}`);

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.json(), {
    sub: "user",
    name: "John Smith",
  });
});

test("GET /userinfo does not return name when profile is only a substring", async function () {
  const accessToken = await signAccessToken({
    scope: "openid notprofile",
  });

  const response = await fetchUserinfo(`Bearer ${accessToken}`);

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.json(), {
    sub: "user",
  });
});

test("GET /userinfo returns profile claims for the matching user", async function () {
  const accessToken = await signAccessToken({
    subject: "jane",
    scope: "profile",
  });

  const response = await fetchUserinfo(`Bearer ${accessToken}`);

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.json(), {
    sub: "jane",
    name: "Jane Smith",
  });
});

test("POST /userinfo returns a bearer challenge when authorization is missing", async function () {
  const response = await fetchUserinfo(undefined, "POST");

  assert.equal(response.statusCode, 401);
  assert.equal(
    response.headers["www-authenticate"],
    'Bearer realm="userinfo"',
  );
  assert.equal(response.body, "");
});

test("POST /userinfo returns the subject and name for valid access tokens with profile scope", async function () {
  const accessToken = await signAccessToken({
    scope: "profile",
  });

  const response = await fetchUserinfo(`Bearer ${accessToken}`, "POST");

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.json(), {
    sub: "user",
    name: "John Smith",
  });
});

async function fetchUserinfo(
  authorizationHeader?: string,
  method: "GET" | "POST" = "GET",
): Promise<UserinfoResponse> {
  const fastify = await createServer(defaultServerConfig);

  try {
    return await fastify.inject({
      method,
      url: "/userinfo",
      headers: {
        ...(authorizationHeader
          ? {
              authorization: authorizationHeader,
            }
          : {}),
      },
    });
  } finally {
    await fastify.close();
  }
}

async function signAccessToken({
  serverConfig = defaultServerConfig,
  privateKey = serverConfig.privateKey,
  subject = "user",
  includeSubject = true,
  scope,
  tokenType = "at+jwt",
}: {
  serverConfig?: ServerConfig;
  privateKey?: ServerConfig["privateKey"];
  subject?: string;
  includeSubject?: boolean;
  scope?: string;
  tokenType?: string;
} = {}) {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const protectedHeader: {
    alg: ServerConfig["jwtSigningAlg"];
    typ?: string;
  } = {
    alg: serverConfig.jwtSigningAlg,
  };

  if (tokenType) {
    protectedHeader.typ = tokenType;
  }

  const payload: {
    iss: string;
    aud: string;
    sub?: string;
    scope?: string;
  } = {
    iss: serverConfig.issuer,
    aud: serverConfig.issuer,
  };
  if (includeSubject) {
    payload.sub = subject;
  }
  if (scope) {
    payload.scope = scope;
  }

  return await new SignJWT(payload)
    .setProtectedHeader(protectedHeader)
    .setIssuedAt(nowSeconds)
    .setExpirationTime(nowSeconds + 3600)
    .sign(privateKey);
}

function assertInvalidTokenResponse(response: UserinfoResponse) {
  assert.equal(response.statusCode, 401);
  assert.equal(
    response.headers["www-authenticate"],
    'Bearer realm="userinfo", error="invalid_token"',
  );
  assert.deepEqual(response.json(), {
    error: "invalid_token",
  });
}
