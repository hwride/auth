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

  fastify.post<{
    Body: {
      resource_url?: string;
      use_invalid_access_token?: string;
    };
  }>("/resource-request", async function (request, reply) {
    const resourceRequestUrl = request.body?.resource_url?.trim() ?? "";

    // Get access token to use.
    const useInvalidAccessToken =
      request.body?.use_invalid_access_token === "true";
    const accessToken = useInvalidAccessToken
      ? "invalid-access-token"
      : authFlowContext.accessToken;
    const headers: Record<string, string> = {};
    if (accessToken) {
      headers.authorization = `Bearer ${accessToken}`;
    }

    try {
      const response = await fetch(resourceRequestUrl, {
        headers,
        method: "GET",
      });
      const responseBody = await response.text();
      let formattedResponseBody = responseBody;
      if (responseBody) {
        try {
          formattedResponseBody = JSON.stringify(
            JSON.parse(responseBody),
            null,
            2,
          );
        } catch {
          formattedResponseBody = responseBody;
        }
      }

      return {
        ok: response.ok,
        requestUrl: resourceRequestUrl,
        statusCode: response.status,
        statusText: response.statusText,
        wwwAuthenticate: response.headers.get("www-authenticate") ?? undefined,
        responseBody: formattedResponseBody,
      };
    } catch (error) {
      let errorMessage: string | undefined;
      if (error instanceof Error) {
        errorMessage = error.message;
      }

      return {
        ok: false,
        requestUrl: resourceRequestUrl,
        errorMessage,
      };
    }
  });
}
