import Fastify from "fastify";
import path from "node:path";
import { fileURLToPath } from "node:url";
import view from "@fastify/view";
import ejs from "ejs";
import type { AuthFlowContext } from "./routes/auth-flow-context.ts";
import { registerHomeRoute } from "./routes/home-route.ts";
import { registerAuthorizeRoute } from "./routes/authorize-route.ts";
import { registerCallbackRoute } from "./routes/callback-route.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

main();

async function main() {
  const fastify = await initServer();
  fastify.log.info("Client is booted");
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

  await fastify.register(view, {
    engine: {
      ejs,
    },
    root: path.join(__dirname, "templates"),
  });

  registerHomeRoute(fastify);

  const authFlowContext: AuthFlowContext = {
    redirectUri: "http://localhost:3000/callback",
  };
  registerAuthorizeRoute(fastify, authFlowContext);
  registerCallbackRoute(fastify, authFlowContext);

  try {
    await fastify.listen({ port: 3000 });
    return fastify;
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}
