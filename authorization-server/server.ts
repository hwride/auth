import Fastify from "fastify";
import { getServerConfig } from "./config/server-config.ts";
import { registerOpenIdConfigurationRoute } from "./routes/openid-configuration-route.ts";

if (import.meta.main) {
  main();
}

async function main() {
  const fastify = createServer();

  try {
    await fastify.listen({ port: 4000 });
    fastify.log.info("Authorization server is booted");
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}

export function createServer() {
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

  const serverConfig = getServerConfig();

  registerOpenIdConfigurationRoute(fastify, serverConfig);

  return fastify;
}
