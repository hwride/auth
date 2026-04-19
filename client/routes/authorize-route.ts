import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type { AuthFlowContext } from "./auth-flow-context.ts";

export function registerAuthorizeRoute(
  fastify: FastifyInstance,
  authFlowContext: AuthFlowContext,
) {
  // OAuth, Authorization Code Grant, Authorization Request - https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
  // OIDC, Authorization Code Flow, Authentication Request - https://openid.net/specs/openid-connect-core-1_0-final.html#AuthRequest
  fastify.get<{
    Querystring: {
      scope?: string;
      audience?: string;
      max_age?: string;
      prompt?: "none" | "login" | "consent" | "select_account";
      display?: "page" | "popup" | "touch" | "wap";
      ui_locales?: "en-GB" | "nl-BE" | "fr-BE";
      login_hint?: string;
      use_pkce?: "true" | "false";
      use_state?: "true" | "false";
      use_nonce?: "true" | "false";
    };
  }>("/authorize", async function (request, reply) {
    const clientId = process.env.CLIENT_ID;
    const {
      scope,
      audience,
      max_age,
      prompt,
      display,
      ui_locales,
      login_hint,
      use_pkce,
      use_state,
      use_nonce,
    } = request.query;

    const authorizeUrl = new URL(authFlowContext.authorizationEndpoint);
    const authorizeQueryParams: Record<string, string> = {
      response_type: "code",
      client_id: clientId,
      redirect_uri: authFlowContext.redirectUri,
    };

    if (use_state === "true") {
      authFlowContext.state = randomUUID();
      authorizeQueryParams.state = authFlowContext.state;
    } else {
      authFlowContext.state = undefined;
    }

    if (use_nonce === "true") {
      // OIDC, ID token - https:openid.net/specs/openid-connect-core-1_0-final.html#IDToken
      authFlowContext.nonce = randomUUID();
      authorizeQueryParams.nonce = authFlowContext.nonce;
    } else {
      authFlowContext.nonce = undefined;
    }

    if (use_pkce === "true") {
      // PKCE, Client Creates a Code Verifier - https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
      authFlowContext.codeVerifier = randomBytes(32).toString("base64url");
      // PKCE, Client Creates a Code Challenge - https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
      authorizeQueryParams.code_challenge_method = "S256";
      authorizeQueryParams.code_challenge = createHash("sha256")
        .update(authFlowContext.codeVerifier)
        .digest("base64url");
    } else {
      authFlowContext.codeVerifier = undefined;
    }

    if (scope) {
      const trimmedScope = scope.trim();
      authorizeQueryParams.scope = trimmedScope;
      authFlowContext.isOidcFlow = trimmedScope
        .split(/\s+/)
        .includes("openid");
    } else {
      authFlowContext.isOidcFlow = false;
    }
    if (audience) {
      authorizeQueryParams.audience = audience.trim();
    }
    if (max_age) {
      const parsedMaxAge = parseMaxAge(max_age);
      authFlowContext.maxAge = parsedMaxAge;
      authorizeQueryParams.max_age = max_age.trim();
    } else {
      authFlowContext.maxAge = undefined;
    }
    if (prompt) {
      authorizeQueryParams.prompt = prompt;
    }
    if (display) {
      authorizeQueryParams.display = display;
    }
    if (ui_locales) {
      authorizeQueryParams.ui_locales = ui_locales;
    }
    if (login_hint?.trim()) {
      authorizeQueryParams.login_hint = login_hint.trim();
    }

    authorizeUrl.search = new URLSearchParams(authorizeQueryParams).toString();

    fastify.log.info(
      {
        authorizeUrl,
        ...Object.fromEntries(authorizeUrl.searchParams.entries()),
      },
      "/authorize - Authorization Request - redirecting to Authorization URL...",
    );
    return reply.redirect(authorizeUrl.toString());
  });
}

function parseMaxAge(maxAgeValue: string): number | undefined {
  const trimmedValue = maxAgeValue.trim();
  if (trimmedValue.length === 0) {
    return undefined;
  }

  const parsed = Number(trimmedValue);
  if (!Number.isInteger(parsed) || parsed < 0) {
    return undefined;
  }

  return parsed;
}
