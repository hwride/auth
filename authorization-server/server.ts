import Fastify from "fastify";

main();

async function main() {
  const fastify = await initServer();
  fastify.log.info("Authorization server is booted");
}

async function initServer() {
  const fastify = Fastify({
    logger: {
      transport: {
        target: "pino-pretty",
        options: {
          translateTime: "HH:MM:ss Z",
          ignore: "pid,hostname",
        },
      },
    },
    disableRequestLogging: true,
  });

  fastify.get("/", async () => {
    return "hello world";
  });

  try {
    await fastify.listen({ port: 4000 });
    return fastify;
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}
