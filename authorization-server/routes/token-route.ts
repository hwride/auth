import { createHash, randomUUID } from "node:crypto";
import type { FastifyInstance, FastifyReply } from "fastify";
import { type JWTPayload, SignJWT } from "jose";
import { type ClientConfig, clientsConfig } from "../config/clients-config.ts";
import type { ServerConfig } from "../config/server-config.ts";
import type { AuthorizationCodeStore } from "../stores/authorization-code-store.ts";
import type { RefreshTokenStore } from "../stores/refresh-token-store.ts";
import type { AccessTokenRecord, TokenStore } from "../stores/token-store.ts";
import type { UserStore } from "../stores/user-store.ts";

type TokenRequestBody = {
  grant_type?: string;
  // Authorization code grant.
  code?: string;
  redirect_uri?: string;
  code_verifier?: string;
  // Refresh token grant.
  refresh_token?: string;
};

type AuthorizationCodeGrantResponse = {
  token_type: "Bearer";
  access_token: string;
  expires_in: number;
  id_token?: string;
  refresh_token?: string;
  scope?: string;
};

type RefreshTokenGrantResponse = {
  token_type: "Bearer";
  access_token: string;
  expires_in: number;
  id_token?: string;
  scope?: string;
};

/**
 * OAuth 2.0, Authorization Code Grant, Access Token Request
 * https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
 *
 * OAuth 2.0, Issuing an Access Token, Successful Response
 * https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
 * OAuth 2.0, Issuing an Access Token, Error Response
 * https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
 */
export function registerTokenRoute(
  fastify: FastifyInstance,
  serverConfig: ServerConfig,
  authorizationCodeStore: AuthorizationCodeStore,
  tokenStore: TokenStore,
  refreshTokenStore: RefreshTokenStore,
  userStore: UserStore,
) {
  const tokenEndpointPath = new URL(serverConfig.tokenEndpoint).pathname;

  fastify.post<{
    Body: TokenRequestBody;
  }>(tokenEndpointPath, async function (request, reply) {
    // Check client authentication
    // OAuth 2.3, Client Authentication
    // https://datatracker.ietf.org/doc/html/rfc6749#section-2.3
    const clientCredentials = parseBasicAuthorizationHeader(
      request.headers.authorization,
    );
    if (!clientCredentials) {
      return reply
        .code(401)
        .header("www-authenticate", 'Basic realm="token"')
        .send({
          error: "invalid_client",
        });
    }

    const clientConfig = clientsConfig.find(function (client) {
      return client.clientId === clientCredentials.clientId;
    });
    if (
      !clientConfig ||
      clientConfig.clientSecret !== clientCredentials.clientSecret
    ) {
      return reply
        .code(401)
        .header("www-authenticate", 'Basic realm="token"')
        .send({
          error: "invalid_client",
        });
    }

    // Switch on grant type.
    if (request.body.grant_type === "authorization_code") {
      return await authCodeGrant({
        body: request.body,
        reply,
        serverConfig,
        clientConfig,
        authorizationCodeStore,
        tokenStore,
        refreshTokenStore,
        userStore,
      });
    } else if (request.body.grant_type === "refresh_token") {
      return await refreshTokenGrant({
        body: request.body,
        reply,
        serverConfig,
        clientConfig,
        tokenStore,
        refreshTokenStore,
        userStore,
      });
    } else {
      return reply.code(400).send({
        error: "unsupported_grant_type",
      });
    }
  });
}

async function authCodeGrant({
  body,
  reply,
  serverConfig,
  clientConfig,
  authorizationCodeStore,
  tokenStore,
  refreshTokenStore,
  userStore,
}: {
  body: TokenRequestBody;
  reply: FastifyReply;
  serverConfig: ServerConfig;
  clientConfig: ClientConfig;
  authorizationCodeStore: AuthorizationCodeStore;
  tokenStore: TokenStore;
  refreshTokenStore: RefreshTokenStore;
  userStore: UserStore;
}) {
  if (!body.code) {
    return reply.code(400).send({
      error: "invalid_request",
      error_description: "Missing code",
    });
  }

  // Check we have a record of the given auth code.
  const authCodeRecord = authorizationCodeStore.loadAuthorizationCode(
    body.code,
  );
  if (authCodeRecord == null) {
    return reply.code(400).send({
      error: "invalid_grant",
      error_description: "Unknown code",
    });
  }

  if (Date.now() > authCodeRecord.expiresAt) {
    authorizationCodeStore.deleteAuthorizationCode(body.code);
    return reply.code(400).send({
      error: "invalid_grant",
      error_description: "Code expired",
    });
  }

  // Check the client that authenticated matches the one that asked for the auth code.
  if (authCodeRecord.clientId !== clientConfig.clientId) {
    return reply.code(400).send({
      error: "invalid_grant",
      error_description: "Code does not match client",
    });
  }

  // redirect_uri is optional, but if it does exist, it must match the value from the authorization request.
  if (
    body.redirect_uri != null &&
    body.redirect_uri !== authCodeRecord.redirectUri
  ) {
    return reply.code(400).send({
      error: "invalid_grant",
      error_description: "Invalid redirect_uri",
    });
  }

  // PKCE check. https://datatracker.ietf.org/doc/html/rfc7636
  if (
    authCodeRecord.codeChallengeMethod === "plain" &&
    body.code_verifier !== authCodeRecord.codeChallenge
  ) {
    return reply.code(400).send({
      error: "invalid_grant",
      error_description: "plain code_verifier does not match",
    });
  } else if (authCodeRecord.codeChallengeMethod === "S256") {
    const codeChallengeFromBody = createHash("sha256")
      .update(body.code_verifier)
      .digest("base64url");
    if (codeChallengeFromBody !== authCodeRecord.codeChallenge) {
      return reply.code(400).send({
        error: "invalid_grant",
        error_description: "S256 code_verifier does not match",
      });
    }
  }

  // Validation passed.
  // Remove the authorization code so it can't be re-used.
  authorizationCodeStore.deleteAuthorizationCode(body.code);

  const access_token = await generateAccessToken({
    serverConfig,
    clientConfig,
    tokenStore,
    scope: authCodeRecord.scope,
    subject: authCodeRecord.subject,
  });

  const response: AuthorizationCodeGrantResponse = {
    token_type: "Bearer",
    access_token,
    // OAuth 2.0 Token Response: expires_in
    // https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
    expires_in: clientConfig.accessTokenLifetimeSeconds,
  };
  // https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
  // Scope is required if different to requested, otherwise optional.
  // Just always include will satisfy the spec.
  if (authCodeRecord.scope) {
    response.scope = authCodeRecord.scope;
  }

  // OpenID Connect ID token
  if (hasOpenIdScope(authCodeRecord.scope)) {
    response.id_token = await generateIdToken({
      serverConfig,
      clientConfig,
      scope: authCodeRecord.scope,
      subject: authCodeRecord.subject,
      nonce: authCodeRecord.nonce,
      userStore,
    });
  }

  // Refresh token
  if (hasScope(authCodeRecord.scope, "offline_access")) {
    response.refresh_token = refreshTokenStore.generateNew(
      {
        clientId: authCodeRecord.clientId,
        scope: authCodeRecord.scope,
        subject: authCodeRecord.subject,
      },
      clientConfig.refreshTokenLifetimeSeconds,
    );
  }

  return (
    reply
      // https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
      // These headers are required by spec for token responses.
      .header("Cache-Control", "no-store")
      .header("Pragma", "no-cache")
      .send(response)
  );
}

async function refreshTokenGrant({
  body,
  reply,
  serverConfig,
  clientConfig,
  tokenStore,
  refreshTokenStore,
  userStore,
}: {
  body: TokenRequestBody;
  reply: FastifyReply;
  serverConfig: ServerConfig;
  clientConfig: ClientConfig;
  tokenStore: TokenStore;
  refreshTokenStore: RefreshTokenStore;
  userStore: UserStore;
}) {
  if (!body.refresh_token) {
    return reply.code(400).send({
      error: "invalid_request",
      error_description: "Missing refresh_token",
    });
  }

  // Check a matching refresh token exists.
  const refreshRecord = refreshTokenStore.get(body.refresh_token);
  if (refreshRecord == null) {
    return reply.code(400).send({
      error: "invalid_grant",
      error_description: "Invalid refresh_token",
    });
  }

  // If the refresh token is expired delete it and fail the request.
  const expiresAt = new Date(refreshRecord.expiresAt);
  const now = new Date();
  if (now > expiresAt) {
    refreshTokenStore.delete(body.refresh_token);
    return reply.code(400).send({
      error: "invalid_grant",
      error_description: "Refresh token expired",
    });
  }

  // Check the refresh token matches the client.
  if (refreshRecord.clientId !== clientConfig.clientId) {
    return reply.code(400).send({
      error: "invalid_grant",
      error_description: "Invalid client",
    });
  }

  // Issue a new access token.
  const access_token = await generateAccessToken({
    serverConfig,
    clientConfig,
    tokenStore,
    scope: refreshRecord.scope,
    subject: refreshRecord.subject,
  });
  // https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
  const response: RefreshTokenGrantResponse = {
    token_type: "Bearer",
    access_token,
    expires_in: clientConfig.accessTokenLifetimeSeconds,
  };
  // https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
  // Scope is required if different to requested, otherwise optional.
  // Just always include will satisfy the spec.
  if (refreshRecord.scope) {
    response.scope = refreshRecord.scope;
  }

  // OpenID Connect ID token
  // https://openid.net/specs/openid-connect-core-1_0.html#RefreshingAccessToken
  if (hasOpenIdScope(refreshRecord.scope)) {
    response.id_token = await generateIdToken({
      serverConfig,
      clientConfig,
      scope: refreshRecord.scope,
      subject: refreshRecord.subject,
      // no nonce on refresh requests
      userStore,
    });
  }

  return (
    reply
      // https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
      // These headers are required by spec for token responses.
      .header("Cache-Control", "no-store")
      .header("Pragma", "no-cache")
      .send(response)
  );
}

function parseBasicAuthorizationHeader(
  authorizationHeader: string | undefined,
) {
  if (!authorizationHeader?.startsWith("Basic ")) {
    return undefined;
  }

  const encodedCredentials = authorizationHeader.slice("Basic ".length);
  const decodedCredentials = Buffer.from(encodedCredentials, "base64").toString(
    "utf8",
  );
  const separatorIndex = decodedCredentials.indexOf(":");
  if (separatorIndex < 0) {
    return undefined;
  }

  return {
    clientId: decodedCredentials.slice(0, separatorIndex),
    clientSecret: decodedCredentials.slice(separatorIndex + 1),
  };
}

async function generateAccessToken({
  serverConfig,
  clientConfig,
  tokenStore,
  scope,
  subject,
}: {
  serverConfig: ServerConfig;
  clientConfig: ClientConfig;
  tokenStore: TokenStore;
  scope?: string;
  subject: string;
}) {
  if (clientConfig.accessTokenType === "opaque") {
    // Generate and save an access token.
    const accessToken = randomUUID();
    const accessTokenRecord: AccessTokenRecord = {
      clientId: clientConfig.clientId,
    };
    if (scope) {
      accessTokenRecord.scope = scope;
    }
    tokenStore.saveAccessToken(accessToken, accessTokenRecord);
    return accessToken;
  }
  // accessTokenType === "jwt"
  else {
    // JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens
    // https://datatracker.ietf.org/doc/html/rfc9068
    const payload: JWTPayload = {
      iss: serverConfig.issuer,
      aud: serverConfig.issuer,
      sub: subject,
      client_id: clientConfig.clientId,
      jti: randomUUID(),
    };
    if (scope) {
      payload.scope = scope;
    }
    const nowSeconds = getNowSeconds();
    return await new SignJWT(payload)
      .setProtectedHeader({ alg: serverConfig.jwtSigningAlg, typ: "at+jwt" })
      .setIssuedAt(nowSeconds)
      .setExpirationTime(nowSeconds + clientConfig.accessTokenLifetimeSeconds)
      .sign(serverConfig.privateKey);
  }
}

/**
 * https://openid.net/specs/openid-connect-core-1_0.html
 */
async function generateIdToken({
  serverConfig,
  clientConfig,
  scope,
  subject,
  nonce,
  userStore,
}: {
  serverConfig: ServerConfig;
  clientConfig: ClientConfig;
  scope?: string;
  subject: string;
  nonce?: string;
  userStore: UserStore;
}) {
  const idTokenPayload: JWTPayload = {
    iss: serverConfig.issuer,
    aud: clientConfig.clientId,
    sub: subject,
    jti: randomUUID(),
  };
  if (nonce) {
    idTokenPayload.nonce = nonce;
  }

  // https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
  if (hasScope(scope, "profile")) {
    const user = userStore.loadUserById(subject);
    if (user != null) {
      idTokenPayload.name = user.name;
    }
  }

  const nowSeconds = getNowSeconds();
  return await new SignJWT(idTokenPayload)
    .setProtectedHeader({ alg: serverConfig.jwtSigningAlg })
    .setIssuedAt(nowSeconds)
    .setExpirationTime(nowSeconds + clientConfig.idTokenLifetimeSeconds)
    .sign(serverConfig.privateKey);
}

function getNowSeconds() {
  return Math.floor(Date.now() / 1000);
}

function hasOpenIdScope(scope: string | undefined) {
  return hasScope(scope, "openid");
}

function hasScope(scope: string | undefined, expectedScope: string) {
  return scope?.split(/\s+/).includes(expectedScope) ?? false;
}
