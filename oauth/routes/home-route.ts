import type { FastifyInstance } from "fastify";

export function registerHomeRoute(fastify: FastifyInstance) {
  fastify.get("/", async function (request, reply) {
    return reply.view("index.ejs");
  });
}
