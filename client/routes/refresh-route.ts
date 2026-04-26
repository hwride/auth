import type { FastifyInstance, FastifyReply } from "fastify";
import type { AuthFlowContext } from "./auth-flow-context.ts";
import { verifyJwtWithJose } from "../utils/jwt-verifier.ts";
import type { JWTPayload } from "jose";

type RefreshViewProps = {
  callbackTitle: "Refresh failed" | "Refresh success";
  errorMessage: string | undefined;
  tokenResponseJson: string | undefined;
  accessTokenJson: string | undefined;
  idTokenJson: string | undefined;
};

const AUTH_TIME_CLOCK_TOLERANCE_SECONDS = 30;
const MAX_ID_TOKEN_AGE_SECONDS = 30 * 24 * 60 * 60;

export function registerRefreshRoute(
  fastify: FastifyInstance,
  authFlowContext: AuthFlowContext,
) {
  fastify.post("/refresh", async function (_, reply) {
    const refreshViewProps = getDefaultRefreshViewProps();

    if (!authFlowContext.refreshToken) {
      return renderRefreshFailure(reply, 400, {
        ...refreshViewProps,
        errorMessage:
          "No refresh token is stored. Authorize with offline_access first.",
      });
    }

    const tokenResponse = await makeRefreshTokenRequest({
      refreshToken: authFlowContext.refreshToken,
      authFlowContext,
      clientId: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      log: fastify.log,
    });

    const refreshResponseResult = await handleRefreshTokenResponse({
      tokenResponse,
      refreshViewProps,
      authFlowContext,
      log: fastify.log,
    });
    if (refreshResponseResult.ok === false) {
      return renderRefreshFailure(
        reply,
        refreshResponseResult.statusCode,
        refreshResponseResult.refreshViewProps,
      );
    }

    return renderRefreshSuccess(reply, refreshResponseResult.refreshViewProps);
  });
}

function getDefaultRefreshViewProps(): RefreshViewProps {
  return {
    callbackTitle: "Refresh failed",
    errorMessage: undefined,
    tokenResponseJson: undefined,
    accessTokenJson: undefined,
    idTokenJson: undefined,
  };
}

async function makeRefreshTokenRequest(args: {
  refreshToken: string;
  authFlowContext: AuthFlowContext;
  clientId: string | undefined;
  clientSecret: string | undefined;
  log: FastifyInstance["log"];
}): Promise<Response> {
  const tokenUrl = new URL(args.authFlowContext.tokenEndpoint);
  const basicAuth = Buffer.from(
    `${args.clientId}:${args.clientSecret}`,
  ).toString("base64");

  const tokenRequestBody = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: args.refreshToken,
  });

  args.log.info(
    { url: tokenUrl, body: tokenRequestBody.toString() },
    "/refresh - Refresh Token Request",
  );

  return fetch(tokenUrl.toString(), {
    method: "POST",
    headers: {
      Authorization: `Basic ${basicAuth}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: tokenRequestBody.toString(),
  });
}

/**
 * https://openid.net/specs/openid-connect-core-1_0-31.html#RefreshTokenResponse
 */
async function handleRefreshTokenResponse(args: {
  tokenResponse: Response;
  refreshViewProps: RefreshViewProps;
  authFlowContext: AuthFlowContext;
  log: FastifyInstance["log"];
}): Promise<
  | { ok: true; refreshViewProps: RefreshViewProps }
  | { ok: false; statusCode: number; refreshViewProps: RefreshViewProps }
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
      formattedErrorResponseBody = tokenResponseBody;
    }

    args.log.error(
      { status: args.tokenResponse.status, body: tokenResponseBody },
      "/refresh - Refresh Token Request failed",
    );

    return {
      ok: false,
      statusCode: 502,
      refreshViewProps: {
        ...args.refreshViewProps,
        errorMessage: "Token request failed",
        tokenResponseJson: formattedErrorResponseBody,
      },
    };
  }

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
      refreshViewProps: {
        ...args.refreshViewProps,
        errorMessage: accessTokenResult.errorMessage,
      },
    };
  }
  const accessTokenJson = accessTokenResult.accessTokenJson;

  const idTokenResult = await verifyOptionalIdToken(
    tokenResponseBody,
    args.authFlowContext,
    args.log,
  );
  if (idTokenResult.ok === false) {
    return {
      ok: false,
      statusCode: 400,
      refreshViewProps: {
        ...args.refreshViewProps,
        errorMessage: idTokenResult.errorMessage,
        accessTokenJson,
      },
    };
  }

  if (typeof tokenResponseBody.refresh_token === "string") {
    args.authFlowContext.refreshToken = tokenResponseBody.refresh_token;
  }
  if (typeof tokenResponseBody.access_token === "string") {
    args.authFlowContext.accessToken = tokenResponseBody.access_token;
  }
  if (typeof tokenResponseBody.id_token === "string") {
    args.authFlowContext.idToken = tokenResponseBody.id_token;
  }

  args.log.info(
    { status: args.tokenResponse.status, body: tokenResponseBody },
    "/refresh - Refresh Token Response",
  );

  return {
    ok: true,
    refreshViewProps: {
      ...args.refreshViewProps,
      callbackTitle: "Refresh success",
      errorMessage: undefined,
      tokenResponseJson: JSON.stringify(tokenResponseBody, null, 2),
      accessTokenJson,
      idTokenJson: idTokenResult.idTokenJson,
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

async function verifyOptionalIdToken(
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
  if (typeof tokenResponseBody.id_token !== "string") {
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

  if (authFlowContext.issuer !== payload.iss) {
    return {
      ok: false,
      errorMessage: `ID token iss "${payload.iss}" did not match discovered issuer "${authFlowContext.issuer}"`,
    };
  }

  if (process.env.CLIENT_ID !== payload.aud) {
    return {
      ok: false,
      errorMessage: `ID token aud "${payload.aud}" did not match client ID "${process.env.CLIENT_ID}"`,
    };
  }

  if (protectedHeader.alg !== "RS256") {
    return {
      ok: false,
      errorMessage: "ID token does use default RS256 for alg",
    };
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  const tokenExpirySeconds = Number(payload.exp);
  if (nowSeconds >= tokenExpirySeconds) {
    return { ok: false, errorMessage: "ID token has expired" };
  }

  const issuedAtSeconds = Number(payload.iat);
  const secondsSinceIssued = nowSeconds - issuedAtSeconds;
  if (secondsSinceIssued > MAX_ID_TOKEN_AGE_SECONDS) {
    return {
      ok: false,
      errorMessage: `ID token is too old. age=${secondsSinceIssued}s max_allowed=${MAX_ID_TOKEN_AGE_SECONDS}s`,
    };
  }

  // For refresh responses, nonce is typically omitted.
  // If the OP includes it, it must match the original nonce.
  if (
    payload.nonce !== undefined &&
    authFlowContext.nonce &&
    authFlowContext.nonce !== payload.nonce
  ) {
    const tokenNonce = String(payload.nonce);
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

function renderRefreshFailure(
  reply: FastifyReply,
  statusCode: number,
  refreshViewProps: RefreshViewProps,
) {
  return reply.code(statusCode).view("callback.ejs", {
    ...refreshViewProps,
    callbackTitle: "Refresh failed",
  });
}

function renderRefreshSuccess(
  reply: FastifyReply,
  refreshViewProps: RefreshViewProps,
) {
  return reply.view("callback.ejs", {
    ...refreshViewProps,
    callbackTitle: "Refresh success",
    errorMessage: undefined,
  });
}
