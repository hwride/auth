import type { FastifyInstance, FastifyReply } from "fastify";
import type { AuthFlowContext } from "./auth-flow-context.ts";
import { verifyJwtWithJose } from "../utils/jwt-verifier.ts";
import type { JWTPayload } from "jose";

type CallbackQuery = {
  code?: string;
  state?: string;
};

type CallbackViewProps = {
  callbackTitle: "Callback failed" | "Callback success";
  errorMessage: string | undefined;
  clientId: string | undefined;
  authServerBaseUrl: string;
  discoveryUrlUsed: string;
  authorizationEndpointUsed: string;
  tokenEndpointUsed: string;
  jwksUrlUsed: string;
  tokenResponseJson: string | undefined;
  accessTokenJson: string | undefined;
  idTokenJson: string | undefined;
  accessToken: string | undefined;
  idToken: string | undefined;
  refreshToken: string | undefined;
  hasRefreshToken: boolean;
};

const AUTH_TIME_CLOCK_TOLERANCE_SECONDS = 30;
const MAX_ID_TOKEN_AGE_SECONDS = 30 * 24 * 60 * 60;

export function registerCallbackRoute(
  fastify: FastifyInstance,
  authFlowContext: AuthFlowContext,
) {
  // OAuth, Authorization Code Grant, Authorization Response - https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2
  // OIDC, Authorization Code Grant, Successful Authentication Response - https://openid.net/specs/openid-connect-core-1_0-final.html#AuthResponse
  fastify.get<{
    Querystring: CallbackQuery;
  }>("/callback", async function (request, reply) {
    const query = request.query;
    const callbackViewProps = getDefaultCallbackViewProps(authFlowContext);

    fastify.log.info({ query }, "/callback - Authorization Response");

    const validationResult = validateCallbackAuthorizationResponse(
      query,
      authFlowContext,
    );
    if (validationResult.ok === false) {
      return renderCallbackFailure(reply, 400, {
        ...callbackViewProps,
        errorMessage: validationResult.errorMessage,
      });
    }

    const tokenResponse = await makeTokenRequest({
      code: validationResult.code,
      authFlowContext,
      clientId: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      log: fastify.log,
    });

    const tokenResponseResult = await handleTokenResponse({
      tokenResponse,
      callbackViewProps,
      authFlowContext,
      log: fastify.log,
    });
    if (tokenResponseResult.ok === false) {
      return renderCallbackFailure(
        reply,
        tokenResponseResult.statusCode,
        tokenResponseResult.callbackViewProps,
      );
    }

    return renderCallbackSuccess(reply, tokenResponseResult.callbackViewProps);
  });
}

function getDefaultCallbackViewProps(
  authFlowContext: AuthFlowContext,
): CallbackViewProps {
  return {
    callbackTitle: "Callback failed",
    errorMessage: undefined,
    clientId: process.env.CLIENT_ID,
    authServerBaseUrl: authFlowContext.authServerBaseUrl,
    discoveryUrlUsed: authFlowContext.discoveryUrl,
    authorizationEndpointUsed: authFlowContext.authorizationEndpoint,
    tokenEndpointUsed: authFlowContext.tokenEndpoint,
    jwksUrlUsed: authFlowContext.jwksUri,
    tokenResponseJson: undefined,
    accessTokenJson: undefined,
    idTokenJson: undefined,
    accessToken: authFlowContext.accessToken,
    idToken: authFlowContext.idToken,
    refreshToken: authFlowContext.refreshToken,
    hasRefreshToken: Boolean(authFlowContext.refreshToken),
  };
}

function validateCallbackAuthorizationResponse(
  query: CallbackQuery,
  authFlowContext: AuthFlowContext,
): { ok: true; code: string } | { ok: false; errorMessage: string } {
  if (!query.code) {
    return { ok: false, errorMessage: "Missing code" };
  }

  const expectedState = authFlowContext.state;
  if (expectedState && (!query.state || query.state !== expectedState)) {
    return { ok: false, errorMessage: "Invalid state" };
  }

  return { ok: true, code: query.code };
}

async function makeTokenRequest(args: {
  code: string;
  authFlowContext: AuthFlowContext;
  clientId: string | undefined;
  clientSecret: string | undefined;
  log: FastifyInstance["log"];
}): Promise<Response> {
  // OAuth, Access Token Request - https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
  const tokenUrl = new URL(args.authFlowContext.tokenEndpoint);
  const basicAuth = Buffer.from(
    `${args.clientId}:${args.clientSecret}`,
  ).toString("base64");

  const tokenRequestBody = new URLSearchParams({
    grant_type: "authorization_code",
    code: args.code,
    redirect_uri: args.authFlowContext.redirectUri,
  });
  if (args.authFlowContext.codeVerifier) {
    tokenRequestBody.set("code_verifier", args.authFlowContext.codeVerifier);
  }

  args.log.info(
    { url: tokenUrl, body: tokenRequestBody.toString() },
    "/callback - Access Token Request",
  );

  return fetch(tokenUrl.toString(), {
    method: "POST",
    headers: {
      authorization: `Basic ${basicAuth}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: tokenRequestBody.toString(),
  });
}

async function handleTokenResponse(args: {
  tokenResponse: Response;
  callbackViewProps: CallbackViewProps;
  authFlowContext: AuthFlowContext;
  log: FastifyInstance["log"];
}): Promise<
  | { ok: true; callbackViewProps: CallbackViewProps }
  | { ok: false; statusCode: number; callbackViewProps: CallbackViewProps }
> {
  if (!args.tokenResponse.ok) {
    const tokenResponseBody = await args.tokenResponse.text();
    let formattedErrorResponseBody: string;
    try {
      formattedErrorResponseBody = JSON.stringify(
        JSON.parse(tokenResponseBody),
        null,
        2,
      );
    } catch {
      // Keep raw body when response is not JSON.
      formattedErrorResponseBody = tokenResponseBody;
    }

    args.log.error(
      { status: args.tokenResponse.status, body: tokenResponseBody },
      "/callback - Access Token Request failed",
    );

    return {
      ok: false,
      statusCode: 502,
      callbackViewProps: {
        ...args.callbackViewProps,
        errorMessage: "Token request failed",
        tokenResponseJson: formattedErrorResponseBody,
      },
    };
  }

  // OAuth, Access Token Response - https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.4
  // OIDC, Token Response Validation - https://openid.net/specs/openid-connect-core-1_0-final.html#TokenResponseValidation
  const tokenResponseBody = (await args.tokenResponse.json()) as Record<
    string,
    unknown
  >;

  const accessTokenResult = await verifyAccessToken(
    tokenResponseBody,
    args.authFlowContext.jwksUri,
    args.log,
  );
  if (accessTokenResult.ok === false) {
    return {
      ok: false,
      statusCode: 400,
      callbackViewProps: {
        ...args.callbackViewProps,
        errorMessage: accessTokenResult.errorMessage,
      },
    };
  }
  const accessTokenJson = accessTokenResult.accessTokenJson;

  const idTokenResult = await verifyIdToken(
    tokenResponseBody,
    args.authFlowContext,
    args.log,
  );
  if (idTokenResult.ok === false) {
    return {
      ok: false,
      statusCode: 400,
      callbackViewProps: {
        ...args.callbackViewProps,
        errorMessage: idTokenResult.errorMessage,
        accessTokenJson,
      },
    };
  }

  args.authFlowContext.refreshToken =
    typeof tokenResponseBody.refresh_token === "string"
      ? tokenResponseBody.refresh_token
      : undefined;
  args.authFlowContext.accessToken =
    typeof tokenResponseBody.access_token === "string"
      ? tokenResponseBody.access_token
      : undefined;
  args.authFlowContext.idToken =
    typeof tokenResponseBody.id_token === "string"
      ? tokenResponseBody.id_token
      : undefined;

  args.log.info(
    { status: args.tokenResponse.status, body: tokenResponseBody },
    "/callback - Access Token Response",
  );

  return {
    ok: true,
    callbackViewProps: {
      ...args.callbackViewProps,
      errorMessage: undefined,
      tokenResponseJson: JSON.stringify(tokenResponseBody, null, 2),
      accessTokenJson,
      idTokenJson: idTokenResult.idTokenJson,
      accessToken: args.authFlowContext.accessToken,
      idToken: args.authFlowContext.idToken,
      refreshToken: args.authFlowContext.refreshToken,
      hasRefreshToken: Boolean(args.authFlowContext.refreshToken),
    },
  };
}

async function verifyAccessToken(
  tokenResponseBody: Record<string, unknown>,
  jwksUri: string,
  log: FastifyInstance["log"],
): Promise<
  | { ok: true; accessTokenJson: string | undefined }
  | {
      ok: false;
      errorMessage: string;
    }
> {
  if (typeof tokenResponseBody.access_token !== "string") {
    return {
      ok: true,
      accessTokenJson: JSON.stringify(
        {
          format: "opaque",
          note: "Access token is not a JWT or a string",
        },
        null,
        2,
      ),
    };
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

/**
 * Validate an ID token received from an Authorization Server.
 *
 * https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
 */
async function verifyIdToken(
  tokenResponseBody: Record<string, unknown>,
  authFlowContext: AuthFlowContext,
  log: FastifyInstance["log"],
): Promise<
  | { ok: true; idTokenJson: string | undefined }
  | {
      ok: false;
      errorMessage: string;
    }
> {
  if (!authFlowContext.isOidcFlow) {
    if (typeof tokenResponseBody.id_token === "string") {
      log.info("ID token returned for OAuth flow; skipping ID token validation");
      return {
        ok: true,
        idTokenJson: JSON.stringify(
          {
            note: "ID token returned, but this flow did not request openid",
          },
          null,
          2,
        ),
      };
    }

    return { ok: true, idTokenJson: undefined };
  }

  if (typeof tokenResponseBody.id_token !== "string") {
    return { ok: false, errorMessage: "ID token is not a string" };
  }

  // 3.1.3.7. ID Token Validation - 6 - Verify JWS signature
  let payload: JWTPayload;
  let protectedHeader: Awaited<
    ReturnType<typeof verifyJwtWithJose>
  >["protectedHeader"];
  try {
    log.info("Verifying ID token signature...");
    ({ payload, protectedHeader } = await verifyJwtWithJose(
      tokenResponseBody.id_token,
      authFlowContext.jwksUri,
    ));
    log.info({ header: protectedHeader, payload }, "ID token");
  } catch (error) {
    log.error({ error }, "ID token failed verification.");
    return {
      ok: false,
      errorMessage: "ID token did not match authorization server signature",
    };
  }

  // 3.1.3.7. ID Token Validation - 1 - Check encryption.

  // 3.1.3.7. ID Token Validation - 2 - Check iss - issuer should be the authorization server.
  if (authFlowContext.issuer !== payload.iss) {
    return {
      ok: false,
      errorMessage: `ID token iss "${payload.iss}" did not match discovered issuer "${authFlowContext.issuer}"`,
    };
  }

  // 3.1.3.7. ID Token Validation - 3 - Check aud - audience should be the client ID.
  if (process.env.CLIENT_ID !== payload.aud) {
    return {
      ok: false,
      errorMessage: `ID token aud "${payload.aud}" did not match client ID "${process.env.CLIENT_ID}"`,
    };
  }

  // 3.1.3.7. ID Token Validation - 4 - Check azp (authorized parties) according to extensions
  // 3.1.3.7. ID Token Validation - 5 - Check azp - if azp is present, check it includes client ID
  // 3.1.3.7. ID Token Validation - 6 - Verify JWS signature (above)

  // 3.1.3.7. ID Token Validation - 7 - Check alg - should default to RS256 or match client request
  if (protectedHeader.alg !== "RS256") {
    return {
      ok: false,
      errorMessage: "ID token does use default RS256 for alg",
    };
  }
  // 3.1.3.7. ID Token Validation - 8 - Verify alg if it is a MAC based algorithm (e.g. HS256, HS384, HS512)

  // 3.1.3.7. ID Token Validation - 9 - Check exp - current time must be before exp
  const nowSeconds = Math.floor(Date.now() / 1000);
  const tokenExpirySeconds = Number(payload.exp);
  if (nowSeconds >= tokenExpirySeconds) {
    return { ok: false, errorMessage: "ID token has expired" };
  }

  // 3.1.3.7. ID Token Validation - 10 - Check iat - clients may choose to reject tokens issued too long ago.
  const issuedAtSeconds = Number(payload.iat);
  const secondsSinceIssued = nowSeconds - issuedAtSeconds;
  if (secondsSinceIssued > MAX_ID_TOKEN_AGE_SECONDS) {
    return {
      ok: false,
      errorMessage: `ID token is too old. age=${secondsSinceIssued}s max_allowed=${MAX_ID_TOKEN_AGE_SECONDS}s`,
    };
  }

  // 3.1.3.7. ID Token Validation - 11 - Check nonce
  // Checks ID token matches the nonce we generated at the start of the authentication flow.
  if (authFlowContext.nonce && authFlowContext.nonce !== payload.nonce) {
    const tokenNonce =
      payload.nonce === undefined ? "undefined" : String(payload.nonce);
    log.warn(
      {
        newNonce: payload.nonce,
        savedNonce: authFlowContext.nonce,
      },
      "ID token nonce mismatch",
    );
    return {
      ok: false,
      errorMessage: `ID token has invalid nonce. token_nonce="${tokenNonce}" saved_nonce="${authFlowContext.nonce}"`,
    };
  }

  // 3.1.3.7. ID Token Validation - 12 - Check acr
  // If client requested acr (Authentication Context Class Reference), it should check its value is appropriate.

  // 3.1.3.7. ID Token Validation - 13 - Check auth_time
  // If the client requested auth_time either via max_age or another request, it should request re-authentication if
  // too much time has elapsed since the last user authentication.
  if (authFlowContext.maxAge !== undefined) {
    if (payload.auth_time === undefined) {
      log.warn(
        "ID token missing auth_time for requested max_age. Note this is expected from Google.",
      );
    } else {
      const authTimeSeconds = Number(payload.auth_time);
      const elapsedSeconds = nowSeconds - authTimeSeconds;
      const allowedElapsedSeconds =
        authFlowContext.maxAge + AUTH_TIME_CLOCK_TOLERANCE_SECONDS;
      if (elapsedSeconds > allowedElapsedSeconds) {
        return {
          ok: false,
          errorMessage: `Too much time has elapsed since last authentication. elapsed=${elapsedSeconds}s max_age=${authFlowContext.maxAge}s tolerance=${AUTH_TIME_CLOCK_TOLERANCE_SECONDS}s auth_time=${authTimeSeconds}`,
        };
      }
    }
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

function renderCallbackFailure(
  reply: FastifyReply,
  statusCode: number,
  callbackViewProps: CallbackViewProps,
) {
  return reply.code(statusCode).view("callback.ejs", {
    ...callbackViewProps,
    callbackTitle: "Callback failed",
  });
}

function renderCallbackSuccess(
  reply: FastifyReply,
  callbackViewProps: CallbackViewProps,
) {
  return reply.view("callback.ejs", {
    ...callbackViewProps,
    callbackTitle: "Callback success",
    errorMessage: undefined,
  });
}
