import Fastify, { type FastifyInstance } from "fastify";
import path from "node:path";
import { fileURLToPath } from "node:url";
import formbody from "@fastify/formbody";
import view from "@fastify/view";
import ejs from "ejs";
import type { AuthFlowContext } from "./routes/auth-flow-context.ts";
import { registerHomeRoute } from "./routes/home-route.ts";
import { registerAuthorizeRoute } from "./routes/authorize-route.ts";
import { registerCallbackRoute } from "./routes/callback-route.ts";
import { registerRefreshRoute } from "./routes/refresh-route.ts";
import { authServerDiscovery } from "./utils/oidc-discovery.ts";

export const defaultClientPort = 3000;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

if (import.meta.main) {
  main();
}

export async function main() {
  const fastify = await createServer();

  try {
    await fastify.listen({
      port: getClientPort(),
    });
    fastify.log.info("Client is booted");
    return fastify;
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}

export async function createServer() {
  const clientPort = getClientPort();
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

  await fastify.register(formbody);

  await fastify.register(view, {
    engine: {
      ejs,
    },
    root: path.join(__dirname, "templates"),
  });

  const authFlowContext = await initAuthFlowContext({
    fastify,
    redirectUri: `http://localhost:${clientPort}/callback`,
  });
  registerHomeRoute(fastify, authFlowContext);
  registerAuthorizeRoute(fastify, authFlowContext);
  registerCallbackRoute(fastify, authFlowContext);
  registerRefreshRoute(fastify, authFlowContext);

  return fastify;
}

function getClientPort() {
  return Number(process.env.CLIENT_PORT ?? defaultClientPort);
}

async function initAuthFlowContext({
  fastify,
  redirectUri,
}: {
  fastify: FastifyInstance;
  redirectUri: string;
}): Promise<AuthFlowContext> {
  const authServerBase = process.env.AUTH_SERVER_BASE;
  if (!authServerBase) {
    throw new Error("Missing AUTH_SERVER_BASE");
  }

  const discovery = await authServerDiscovery(authServerBase, fastify.log);

  return {
    authServerBaseUrl: authServerBase,
    issuer: discovery.issuer ?? authServerBase,
    redirectUri,
    discoveryUrl: discovery.discoveryUrl,
    authorizationEndpoint: discovery.authorizationEndpoint,
    tokenEndpoint: discovery.tokenEndpoint,
    jwksUri: discovery.jwksUri,
  };
}
