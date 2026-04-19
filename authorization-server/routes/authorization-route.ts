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
      response_type?: string;
    };
  }>(authorizationEndpointPath, async function (request, reply) {
    if (request.query.response_type !== "code") {
      // OAuth 2.0, Error Response, https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
      return reply.code(400).send({
        error: "unsupported_response_type",
      });
    }

    return reply.code(501).send({
      error: "not_implemented",
    });
  });
}
