import { exportJWK } from "jose";
import type { FastifyInstance } from "fastify";
import type { ServerConfig } from "../config/server-config.ts";

export function registerJwksRoute(
  fastify: FastifyInstance,
  serverConfig: ServerConfig,
) {
  // JSON Web Key (JWK) Set, RFC 7517, Section 5:
  // https://www.rfc-editor.org/rfc/rfc7517.html#section-5
  fastify.get("/.well-known/jwks.json", async function (_, reply) {
    const publicJwk = await exportJWK(serverConfig.publicKey);

    return reply.send({
      keys: [
        {
          ...publicJwk,
          alg: serverConfig.jwtSigningAlg,
          use: "sig",
        },
      ],
    });
  });
}
