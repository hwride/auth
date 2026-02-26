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
      use_pkce?: "true" | "false";
      use_state?: "true" | "false";
      use_nonce?: "true" | "false";
    };
  }>("/authorize", async function (request, reply) {
    const authServerBase = process.env.AUTH_SERVER_BASE;
    const clientId = process.env.CLIENT_ID;
    const { scope, use_pkce, use_state, use_nonce } = request.query;

    const authorizeUrl = new URL("/authorize", authServerBase);
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
      // https:openid.net/specs/openid-connect-core-1_0-final.html#IDToken
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
      authorizeQueryParams.scope = scope.trim();
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
