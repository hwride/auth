import type { FastifyInstance } from "fastify";
import type { AuthFlowContext } from "./auth-flow-context.ts";
import { verifyJwtWithJose } from "../utils/jwt-verifier.ts";
import type { JWTPayload } from "jose";

type AccessTokenHandlingResult =
  | { ok: true; accessTokenJson: string | undefined }
  | { ok: false; errorMessage: string };

type IdTokenHandlingResult =
  | {
      ok: true;
      idTokenJson: string | undefined;
    }
  | { ok: false; errorMessage: string };

export function registerCallbackRoute(
  fastify: FastifyInstance,
  authFlowContext: AuthFlowContext,
) {
  // OAuth, Authorization Code Grant, Authorization Response - https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2
  // OIDC, Authorization Code Grant, Successful Authentication Response - https://openid.net/specs/openid-connect-core-1_0-final.html#AuthResponse
  fastify.get<{
    Querystring: {
      code?: string;
      state?: string;
    };
  }>("/callback", async function (request, reply) {
    const query = request.query;
    const clientId = process.env.CLIENT_ID;
    const authServerBaseUrl = authFlowContext.authServerBaseUrl;
    const discoveryUrlUsed = authFlowContext.discoveryUrl;
    const authorizationEndpointUsed = authFlowContext.authorizationEndpoint;
    const tokenEndpointUsed = authFlowContext.tokenEndpoint;
    const jwksUrlUsed = authFlowContext.jwksUri;
    fastify.log.info({ query }, "/callback - Authorization Response");

    if (!query.code) {
      return reply.code(400).view("callback.ejs", {
        callbackTitle: "Callback failed",
        errorMessage: "Missing code",
        clientId,
        authServerBaseUrl,
        discoveryUrlUsed,
        authorizationEndpointUsed,
        tokenEndpointUsed,
        jwksUrlUsed,
        tokenResponseJson: undefined,
        accessTokenJson: undefined,
        idTokenJson: undefined,
      });
    }

    if (
      authFlowContext.state &&
      (!query.state || query.state !== authFlowContext.state)
    ) {
      return reply.code(400).view("callback.ejs", {
        callbackTitle: "Callback failed",
        errorMessage: "Invalid state",
        clientId,
        authServerBaseUrl,
        discoveryUrlUsed,
        authorizationEndpointUsed,
        tokenEndpointUsed,
        jwksUrlUsed,
        tokenResponseJson: undefined,
        accessTokenJson: undefined,
        idTokenJson: undefined,
      });
    }

    // OAuth, Access Token Request - https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
    const clientSecret = process.env.CLIENT_SECRET;
    const tokenUrl = new URL(authFlowContext.tokenEndpoint);
    const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString(
      "base64",
    );
    const tokenRequestBody = new URLSearchParams({
      grant_type: "authorization_code",
      code: query.code,
      redirect_uri: authFlowContext.redirectUri,
    });
    if (authFlowContext.codeVerifier) {
      tokenRequestBody.set("code_verifier", authFlowContext.codeVerifier);
    }

    fastify.log.info(
      { url: tokenUrl, body: tokenRequestBody.toString() },
      "/callback - Access Token Request",
    );
    const tokenResponse = await fetch(tokenUrl.toString(), {
      method: "POST",
      headers: {
        authorization: `Basic ${basicAuth}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: tokenRequestBody.toString(),
    });

    if (!tokenResponse.ok) {
      const tokenResponseBody = await tokenResponse.text();
      let formattedErrorResponseBody = tokenResponseBody;
      try {
        formattedErrorResponseBody = JSON.stringify(
          JSON.parse(tokenResponseBody),
          null,
          2,
        );
      } catch {
        // Keep raw body when response is not JSON.
      }
      fastify.log.error(
        { status: tokenResponse.status, body: tokenResponseBody },
        "/callback - Access Token Request failed",
      );
      return reply.code(502).view("callback.ejs", {
        callbackTitle: "Callback failed",
        errorMessage: "Token request failed",
        clientId,
        authServerBaseUrl,
        discoveryUrlUsed,
        authorizationEndpointUsed,
        tokenEndpointUsed,
        jwksUrlUsed,
        tokenResponseJson: formattedErrorResponseBody,
        accessTokenJson: undefined,
        idTokenJson: undefined,
      });
    }

    // OAuth, Access Token Response - https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.4
    // OIDC, Token Response Validation - https://openid.net/specs/openid-connect-core-1_0-final.html#TokenResponseValidation
    const tokenResponseBody = (await tokenResponse.json()) as Record<
      string,
      unknown
    >;

    const accessTokenResult = await handleAccessToken(
      tokenResponseBody,
      authFlowContext.jwksUri,
      fastify.log,
    );
    if (accessTokenResult.ok === false) {
      return reply.code(400).view("callback.ejs", {
        callbackTitle: "Callback failed",
        errorMessage: accessTokenResult.errorMessage,
        clientId,
        authServerBaseUrl,
        discoveryUrlUsed,
        authorizationEndpointUsed,
        tokenEndpointUsed,
        jwksUrlUsed,
        tokenResponseJson: undefined,
        accessTokenJson: undefined,
        idTokenJson: undefined,
      });
    }
    const accessTokenJson = accessTokenResult.accessTokenJson;

    const idTokenResult = await handleIdToken(
      tokenResponseBody,
      authFlowContext.jwksUri,
      authFlowContext.nonce,
      fastify.log,
    );
    if (idTokenResult.ok === false) {
      return reply.code(400).view("callback.ejs", {
        callbackTitle: "Callback failed",
        errorMessage: idTokenResult.errorMessage,
        clientId,
        authServerBaseUrl,
        discoveryUrlUsed,
        authorizationEndpointUsed,
        tokenEndpointUsed,
        jwksUrlUsed,
        tokenResponseJson: undefined,
        accessTokenJson,
        idTokenJson: undefined,
      });
    }
    const idTokenJson = idTokenResult.idTokenJson;

    fastify.log.info(
      { status: tokenResponse.status, body: tokenResponseBody },
      "/callback - Access Token Response",
    );

    return reply.view("callback.ejs", {
      callbackTitle: "Callback success",
      errorMessage: undefined,
      clientId,
      authServerBaseUrl,
      discoveryUrlUsed,
      authorizationEndpointUsed,
      tokenEndpointUsed,
      jwksUrlUsed,
      tokenResponseJson: JSON.stringify(tokenResponseBody, null, 2),
      accessTokenJson,
      idTokenJson,
    });
  });
}

async function handleAccessToken(
  tokenResponseBody: Record<string, unknown>,
  jwksUri: string,
  log: FastifyInstance["log"],
): Promise<AccessTokenHandlingResult> {
  if (typeof tokenResponseBody.access_token !== "string") {
    return { ok: true, accessTokenJson: undefined };
  }

  const accessToken = tokenResponseBody.access_token;
  const isJwt = accessToken.split(".").length === 3;
  if (!isJwt) {
    log.info("Access token is opaque (not a JWT); skipping JWT verification");
    return {
      ok: true,
      accessTokenJson: JSON.stringify(
        {
          format: "opaque",
          note: "Access token is not a JWT",
        },
        null,
        2,
      ),
    };
  }

  try {
    const { payload, protectedHeader } = await verifyJwtWithJose(
      accessToken,
      jwksUri,
    );
    log.info("Access token JWT verification succeeded");
    return {
      ok: true,
      accessTokenJson: JSON.stringify(
        { header: protectedHeader, payload, jwtSignatureVerified: true },
        null,
        2,
      ),
    };
  } catch (error) {
    log.error({ error }, "Access token failed verification.");
    return {
      ok: false,
      errorMessage: "Access token did not match authorization server signature",
    };
  }
}

async function handleIdToken(
  tokenResponseBody: Record<string, unknown>,
  jwksUri: string,
  expectedNonce: string | undefined,
  log: FastifyInstance["log"],
): Promise<IdTokenHandlingResult> {
  if (typeof tokenResponseBody.id_token !== "string") {
    if (expectedNonce) {
      return { ok: false, errorMessage: "Invalid nonce" };
    }
    return { ok: true, idTokenJson: undefined };
  }

  let payload: JWTPayload;
  let protectedHeader: Awaited<
    ReturnType<typeof verifyJwtWithJose>
  >["protectedHeader"];
  try {
    log.info("Verifying ID token signature...");
    ({ payload, protectedHeader } = await verifyJwtWithJose(
      tokenResponseBody.id_token,
      jwksUri,
    ));
    log.info({ header: protectedHeader, payload }, "ID token");
  } catch (error) {
    log.error({ error }, "ID token failed verification.");
    return {
      ok: false,
      errorMessage: "ID token did not match authorization server signature",
    };
  }

  if (expectedNonce && expectedNonce !== payload.nonce) {
    return { ok: false, errorMessage: "Invalid nonce" };
  }

  return {
    ok: true,
    idTokenJson: JSON.stringify(
      { header: protectedHeader, payload, jwtSignatureVerified: true },
      null,
      2,
    ),
  };
}
