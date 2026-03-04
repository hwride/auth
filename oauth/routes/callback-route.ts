import type { FastifyInstance, FastifyReply } from "fastify";
import type { AuthFlowContext } from "./auth-flow-context.ts";
import { verifyJwtWithJose } from "../utils/jwt-verifier.ts";
import type { JWTPayload } from "jose";

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
};

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
    const callbackViewProps = getDefaultCallbackViewProps(authFlowContext);
    const clientId = callbackViewProps.clientId;
    fastify.log.info({ query }, "/callback - Authorization Response");

    if (!query.code) {
      return renderCallbackFailure(reply, 400, {
        ...callbackViewProps,
        errorMessage: "Missing code",
      });
    }

    if (
      authFlowContext.state &&
      (!query.state || query.state !== authFlowContext.state)
    ) {
      return renderCallbackFailure(reply, 400, {
        ...callbackViewProps,
        errorMessage: "Invalid state",
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
      return renderCallbackFailure(reply, 502, {
        ...callbackViewProps,
        errorMessage: "Token request failed",
        tokenResponseJson: formattedErrorResponseBody,
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
      return renderCallbackFailure(reply, 400, {
        ...callbackViewProps,
        errorMessage: accessTokenResult.errorMessage,
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
      return renderCallbackFailure(reply, 400, {
        ...callbackViewProps,
        errorMessage: idTokenResult.errorMessage,
        accessTokenJson,
      });
    }
    const idTokenJson = idTokenResult.idTokenJson;

    fastify.log.info(
      { status: tokenResponse.status, body: tokenResponseBody },
      "/callback - Access Token Response",
    );

    return renderCallbackSuccess(reply, {
      ...callbackViewProps,
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
): Promise<
  { ok: true; accessTokenJson: string | undefined } | {
    ok: false;
    errorMessage: string;
  }
> {
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
): Promise<
  { ok: true; idTokenJson: string | undefined } | {
    ok: false;
    errorMessage: string;
  }
> {
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
