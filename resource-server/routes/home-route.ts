import type { FastifyInstance } from "fastify";

export function registerHomeRoute(fastify: FastifyInstance) {
  fastify.get("/", async (_, reply) => {
    reply.type("text/html");
    return "<h1>OAuth Resource Server</h1>";
  });
}
