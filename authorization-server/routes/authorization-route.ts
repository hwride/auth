import type { FastifyInstance } from "fastify";
import type { ServerConfig } from "../config/server-config.ts";

export function registerAuthorizationRoute(
  fastify: FastifyInstance,
  serverConfig: ServerConfig,
) {
  const authorizationEndpointPath = new URL(
    serverConfig.authorizationEndpoint,
  ).pathname;

  fastify.get(authorizationEndpointPath, async function (_, reply) {
    return reply.code(501).send({
      error: "not_implemented",
    });
  });
}
