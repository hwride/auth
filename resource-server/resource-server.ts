import Fastify from "fastify";
import {
  getResourceServerConfig,
  type ResourceServerConfig,
} from "./config.ts";
import { registerHomeRoute } from "./routes/home-route.ts";
import { registerOrdersRoute } from "./routes/orders-route.ts";
import { registerProductsRoute } from "./routes/products-route.ts";
import { createDefaultOrderStore } from "./stores/order-store.ts";
import { createDefaultProductStore } from "./stores/product-store.ts";

export const defaultResourceServerPort = 5000;

if (import.meta.main) {
  main();
}

export async function main() {
  const serverConfig = await getResourceServerConfig();
  const fastify = createServer(serverConfig);

  try {
    await fastify.listen({
      port: Number(
        process.env.RESOURCE_SERVER_PORT ?? defaultResourceServerPort,
      ),
    });
    fastify.log.info("Resource server is booted");
    return fastify;
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}

export function createServer(serverConfig: ResourceServerConfig) {
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

  const orderStore = createDefaultOrderStore();
  const productStore = createDefaultProductStore();

  registerHomeRoute(fastify);
  registerOrdersRoute(fastify, serverConfig, orderStore);
  registerProductsRoute(fastify, serverConfig, productStore);

  return fastify;
}
