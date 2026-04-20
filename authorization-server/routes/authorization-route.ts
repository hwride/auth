import { randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type { AuthorizationCodeStore } from "../authorization-code-store.ts";
import { clientsConfig } from "../config/clients-config.ts";
import type { ServerConfig } from "../config/server-config.ts";

export function registerAuthorizationRoute(
  fastify: FastifyInstance,
  serverConfig: ServerConfig,
  authorizationCodeStore: AuthorizationCodeStore,
) {
  const authorizationEndpointPath = new URL(serverConfig.authorizationEndpoint)
    .pathname;

  fastify.get<{
    Querystring: {
      client_id?: string;
      response_type?: string;
      redirect_uri?: string;
    };
  }>(authorizationEndpointPath, async function (request, reply) {
    // Check for valid input.
    // OAuth 2.0, Authorization Response, Error Response
    // https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
    if (!request.query.redirect_uri) {
      return reply.code(400).send({
        error: "invalid_request",
        error_description: "Missing redirect_uri",
      });
    }

    // Check if this is a valid client.
    const clientConfig = clientsConfig.find(function (client) {
      return client.clientId === request.query.client_id;
    });
    if (!clientConfig) {
      return reply.code(400).send({
        error: "invalid_request",
        error_description: "Invalid client_id",
      });
    }

    // Check if this is a valid redirect URI for the client.
    if (!clientConfig.redirectUris.includes(request.query.redirect_uri)) {
      return reply.code(400).send({
        error: "invalid_request",
        error_description: "Invalid redirect_uri",
      });
    }

    if (request.query.response_type !== "code") {
      return reply.code(400).send({
        error: "unsupported_response_type",
      });
    }

    // Passed validation. Create a new authorization code and store it.
    const code = randomUUID();
    authorizationCodeStore.set(code, {
      clientId: clientConfig.clientId,
      redirectUri: request.query.redirect_uri,
      expiresAt:
        Date.now() + serverConfig.authorizationCodeLifetimeSeconds * 1000,
    });

    // Redirect to redirect_uri with code.
    const redirectUri = new URL(request.query.redirect_uri);
    redirectUri.searchParams.set("code", code);
    return reply.redirect(redirectUri.toString());
  });
}
