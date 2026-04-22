import type { FastifyInstance } from "fastify";
import type { AuthFlowContext } from "./auth-flow-context.ts";

export function registerHomeRoute(
  fastify: FastifyInstance,
  authFlowContext: AuthFlowContext,
) {
  fastify.get("/", async function (_, reply) {
    const defaultAudience = process.env.DEFAULT_AUDIENCE?.trim() ?? "";

    return reply.view("index.ejs", {
      authServerBaseUrl: authFlowContext.authServerBaseUrl,
      discoveryUrlUsed: authFlowContext.discoveryUrl,
      authorizationEndpointUsed: authFlowContext.authorizationEndpoint,
      tokenEndpointUsed: authFlowContext.tokenEndpoint,
      jwksUrlUsed: authFlowContext.jwksUri,
      clientId: process.env.CLIENT_ID,
      defaultAudience,
      useDefaultAudience: !!defaultAudience,
      accessToken: authFlowContext.accessToken,
      idToken: authFlowContext.idToken,
      refreshToken: authFlowContext.refreshToken,
      hasRefreshToken: Boolean(authFlowContext.refreshToken),
    });
  });
}
