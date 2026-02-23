// Import the framework and instantiate it
import Fastify from "fastify";

main();

async function main() {
  const fastify = await initServer();
  fastify.log.info("Client is booted");
}

async function initServer() {
  const fastify = Fastify({
    logger: true,
  });
  fastify.get("/", async function handler(request, reply) {
    return { hello: "world" };
  });
  try {
    await fastify.listen({ port: 3000 });
    return fastify;
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}
