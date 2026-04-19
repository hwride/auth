import type { FastifyInstance } from "fastify";
import type { ServerConfig } from "../config/server-config.ts";

export function registerAuthorizationRoute(
  fastify: FastifyInstance,
  serverConfig: ServerConfig,
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
    // OAuth 2.0, Error Response, https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
    if (!request.query.redirect_uri) {
      return reply.code(400).send({
        error: "invalid_request",
        error_description: "Missing redirect_uri",
      });
    }

    if (request.query.client_id !== "test-client-id") {
      return reply.code(400).send({
        error: "invalid_request",
        error_description: "Invalid client_id",
      });
    }

    if (request.query.response_type !== "code") {
      return reply.code(400).send({
        error: "unsupported_response_type",
      });
    }

    return reply.code(501).send({
      error: "not_implemented",
    });
  });
}
