import type { FastifyInstance } from "fastify";
import { decodeJwtPayload } from "../utils/jwt-utils.ts";
import type { AuthFlowContext } from "./auth-flow-context.ts";

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
    fastify.log.info({ query }, "/callback - Authorization Response");

    if (!query.code) {
      return reply.code(400).view("callback.ejs", {
        callbackTitle: "Callback failed",
        errorMessage: "Missing code",
        tokenResponseJson: undefined,
        idTokenClaimsJson: undefined,
      });
    }

    if (
      authFlowContext.state &&
      (!query.state || query.state !== authFlowContext.state)
    ) {
      return reply.code(400).view("callback.ejs", {
        callbackTitle: "Callback failed",
        errorMessage: "Invalid state",
        tokenResponseJson: undefined,
        idTokenClaimsJson: undefined,
      });
    }

    // OAuth, Access Token Request - https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
    const authServerBase = process.env.AUTH_SERVER_BASE;
    const clientId = process.env.CLIENT_ID;
    const clientSecret = process.env.CLIENT_SECRET;
    const tokenUrl = new URL("/oauth/token", authServerBase);
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
        tokenResponseJson: formattedErrorResponseBody,
        idTokenClaimsJson: undefined,
      });
    }

    // OAuth, Access Token Response - https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.4
    // OIDC, Token Response Validation - https://openid.net/specs/openid-connect-core-1_0-final.html#TokenResponseValidation
    const tokenResponseBody = (await tokenResponse.json()) as Record<
      string,
      unknown
    >;

    const idTokenClaims: any =
      typeof tokenResponseBody.id_token === "string"
        ? decodeJwtPayload(tokenResponseBody.id_token)
        : undefined;

    if (authFlowContext.nonce) {
      if (authFlowContext.nonce !== idTokenClaims?.nonce) {
        return reply.code(400).view("callback.ejs", {
          callbackTitle: "Callback failed",
          errorMessage: "Invalid nonce",
          tokenResponseJson: undefined,
          idTokenClaimsJson: idTokenClaims
            ? JSON.stringify(idTokenClaims, null, 2)
            : undefined,
        });
      }
    }

    const tokenResponseForDisplay = {
      ...tokenResponseBody,
      ...(tokenResponseBody.access_token
        ? { access_token: "<present-but-redacted>" }
        : {}),
    };

    fastify.log.info(
      { status: tokenResponse.status, body: tokenResponseBody },
      "/callback - Access Token Response",
    );

    return reply.view("callback.ejs", {
      callbackTitle: "Callback success",
      errorMessage: undefined,
      tokenResponseJson: JSON.stringify(tokenResponseForDisplay, null, 2),
      idTokenClaimsJson: idTokenClaims
        ? JSON.stringify(idTokenClaims, null, 2)
        : undefined,
    });
  });
}
