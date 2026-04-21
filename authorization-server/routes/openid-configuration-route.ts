import type { FastifyInstance } from "fastify";
import type { ServerConfig } from "../config/server-config.ts";

export function registerOpenIdConfigurationRoute(
  fastify: FastifyInstance,
  serverConfig: ServerConfig,
) {
  // OAuth 2.0 Authorization Server Metadata
  // https://datatracker.ietf.org/doc/html/rfc8414
  // OpenID Connect Discovery 1.0, Section 4.1 (OpenID Provider Configuration Request):
  // https://openid.net/specs/openid-connect-discovery-1_0.html
  fastify.get("/.well-known/openid-configuration", async function (_, reply) {
    return reply.send({
      issuer: serverConfig.issuer,
      authorization_endpoint: serverConfig.authorizationEndpoint,
      token_endpoint: serverConfig.tokenEndpoint,
      jwks_uri: serverConfig.jwksUri,
      code_challenge_methods_supported: ["S256", "plain"],
    });
  });
}
