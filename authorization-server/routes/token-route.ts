import { createHash, randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { type JWTPayload, SignJWT } from "jose";
import type { AuthorizationCodeStore } from "../authorization-code-store.ts";
import { clientsConfig } from "../config/clients-config.ts";
import type { ServerConfig } from "../config/server-config.ts";
import type { AccessTokenRecord, TokenStore } from "../token-store.ts";

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
) {
  const tokenEndpointPath = new URL(serverConfig.tokenEndpoint).pathname;

  fastify.post<{
    Body: {
      code?: string;
      grant_type?: string;
      redirect_uri?: string;
      code_verifier?: string;
    };
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

    // Check other body data is valid.
    if (request.body.grant_type !== "authorization_code") {
      return reply.code(400).send({
        error: "unsupported_grant_type",
      });
    }

    if (!request.body.code) {
      return reply.code(400).send({
        error: "invalid_request",
        error_description: "Missing code",
      });
    }

    // Check we have a record of the given auth code.
    const authCodeRecord = authorizationCodeStore.get(request.body.code);
    if (authCodeRecord == null) {
      return reply.code(400).send({
        error: "invalid_grant",
        error_description: "Unknown code",
      });
    }

    if (Date.now() > authCodeRecord.expiresAt) {
      authorizationCodeStore.delete(request.body.code);
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
      request.body.redirect_uri != null &&
      request.body.redirect_uri !== authCodeRecord.redirectUri
    ) {
      return reply.code(400).send({
        error: "invalid_grant",
        error_description: "Invalid redirect_uri",
      });
    }

    // PKCE check. https://datatracker.ietf.org/doc/html/rfc7636
    if (
      authCodeRecord.codeChallengeMethod === "plain" &&
      request.body.code_verifier !== authCodeRecord.codeChallenge
    ) {
      return reply.code(400).send({
        error: "invalid_grant",
        error_description: "plain code_verifier does not match",
      });
    } else if (authCodeRecord.codeChallengeMethod === "S256") {
      const codeChallengeFromBody = createHash("sha256")
        .update(request.body.code_verifier)
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
    authorizationCodeStore.delete(request.body.code);

    const response: {
      access_token: string;
      id_token?: string;
      token_type: "Bearer";
    } = {
      access_token: "",
      token_type: "Bearer",
    };

    // https://openid.net/specs/openid-connect-core-1_0.html
    if (hasOpenIdScope(authCodeRecord.scope)) {
      const idTokenPayload: JWTPayload = {
        iss: serverConfig.issuer,
        aud: authCodeRecord.clientId,
        sub: authCodeRecord.subject,
        jti: randomUUID(),
      };
      if (authCodeRecord.nonce) {
        idTokenPayload.nonce = authCodeRecord.nonce;
      }
      response.id_token = await new SignJWT(idTokenPayload)
        .setProtectedHeader({ alg: serverConfig.jwtSigningAlg })
        .setIssuedAt()
        .setExpirationTime("1h")
        .sign(serverConfig.privateKey);
    }

    if (clientConfig.accessTokenType === "opaque") {
      // Generate and save an access token.
      const accessToken = randomUUID();
      const accessTokenRecord: AccessTokenRecord = {
        clientId: clientConfig.clientId,
      };
      if (authCodeRecord.scope) {
        accessTokenRecord.scope = authCodeRecord.scope;
      }
      tokenStore.set(accessToken, accessTokenRecord);
      response.access_token = accessToken;
    }
    // accessTokenType === "jwt"
    else {
      // JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens
      // https://datatracker.ietf.org/doc/html/rfc9068
      const payload: JWTPayload = {
        iss: serverConfig.issuer,
        aud: serverConfig.issuer,
        sub: authCodeRecord.subject,
        client_id: clientConfig.clientId,
        jti: randomUUID(),
      };
      if (authCodeRecord.scope) {
        payload.scope = authCodeRecord.scope;
      }
      response.access_token = await new SignJWT(payload)
        .setProtectedHeader({ alg: serverConfig.jwtSigningAlg })
        .setIssuedAt()
        .setExpirationTime("1h")
        .sign(serverConfig.privateKey);
    }

    return (
      reply
        // https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
        // These headers are required by spec for token responses.
        .header("Cache-Control", "no-store")
        .header("Pragma", "no-cache")
        .send(response)
    );
  });
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

function hasOpenIdScope(scope: string | undefined) {
  return scope?.split(/\s+/).includes("openid") ?? false;
}
