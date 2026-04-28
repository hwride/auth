import type { FastifyReply, FastifyRequest } from "fastify";
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

const jwksByUri = new Map<string, ReturnType<typeof createRemoteJWKSet>>();
const bearerChallenge = `Bearer realm="resource-server"`;

export type AccessTokenVerificationConfig = {
  resourceId: string;
  acceptedAccessTokenAlgorithms: string[];
  issuer: string;
  jwksUri: string;
};

/**
 * Checks for proper access token authentication.
 *
 * Looks for a Bearer access token off the Authorization header.
 * Checks it signature is signed by the authorization server and issuer matches.
 *
 * In the case of success returns the associated subject.
 *
 * In the case of error returns undefined. Also handles sending the appropriate
 * HTTP response, so if undefined is returned consider the response handled.
 */
export async function authenticateAccessToken(
  request: FastifyRequest,
  reply: FastifyReply,
  verificationConfig: AccessTokenVerificationConfig,
): Promise<{ sub: string; scope?: string } | undefined> {
  const token = extractBearerToken(request.headers.authorization);

  if (!token) {
    sendBearerChallenge(reply);
    return undefined;
  }

  try {
    const payload = await verifyAccessToken(token, verificationConfig);

    if (typeof payload.sub !== "string" || payload.sub.length === 0) {
      sendInvalidTokenResponse(reply, "Token subject is missing");
      return undefined;
    }

    const scope = typeof payload.scope === "string" ? payload.scope : undefined;
    return { sub: payload.sub, scope };
  } catch (e) {
    // Note you wouldn't normally expose this level of info in the response.
    // But as this is a test server, it's convenient.
    sendInvalidTokenResponse(reply, e.code ?? "Invalid access token");
    return undefined;
  }
}

function extractBearerToken(
  authorizationHeader: string | undefined,
): string | undefined {
  if (!authorizationHeader) {
    return undefined;
  }

  const [scheme, token] = authorizationHeader.split(" ");
  if (scheme !== "Bearer" || !token) {
    return undefined;
  }

  return token;
}

function sendBearerChallenge(reply: FastifyReply) {
  // RFC 6750 says missing or unsupported authentication should not include
  // an error code or other error information.
  // https://www.rfc-editor.org/rfc/rfc6750.html#section-3.1
  reply.header("WWW-Authenticate", bearerChallenge);
  reply.status(401).send();
}

function sendInvalidTokenResponse(reply: FastifyReply, description: string) {
  // RFC 6750 defines the Bearer WWW-Authenticate error parameters.
  // https://www.rfc-editor.org/rfc/rfc6750.html#section-3
  reply.header(
    "WWW-Authenticate",
    `${bearerChallenge}, error="invalid_token", error_description="${description}"`,
  );
  reply.status(401).send({ error: "invalid_token" });
}

/**
 * Checks if an access token is valid. Checks:
 * 1. The signature is signed by the authorization server.
 * 2. The issuer matches the authorization server.
 */
async function verifyAccessToken(
  token: string,
  config: AccessTokenVerificationConfig,
): Promise<JWTPayload> {
  const jwks = getRemoteJwks(config.jwksUri);
  const { payload } = await jwtVerify(token, jwks, {
    algorithms: config.acceptedAccessTokenAlgorithms,
    issuer: config.issuer,
    // RFC 8707, Resource Indicators for OAuth 2.0
    audience: config.resourceId,
  });
  return payload;
}

function getRemoteJwks(jwksUri: string): ReturnType<typeof createRemoteJWKSet> {
  let remoteJwks = jwksByUri.get(jwksUri);
  if (!remoteJwks) {
    remoteJwks = createRemoteJWKSet(new URL(jwksUri));
    jwksByUri.set(jwksUri, remoteJwks);
  }
  return remoteJwks;
}
