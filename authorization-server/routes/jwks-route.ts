import type { FastifyInstance } from "fastify";

export function registerJwksRoute(fastify: FastifyInstance) {
  // JSON Web Key (JWK) Set, RFC 7517, Section 5:
  // https://www.rfc-editor.org/rfc/rfc7517.html#section-5
  fastify.get("/.well-known/jwks.json", async function (_, reply) {
    return reply.send({
      keys: [],
    });
  });
}
