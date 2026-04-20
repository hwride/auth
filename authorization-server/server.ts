import formbody from "@fastify/formbody";
import Fastify from "fastify";
import {
  createAuthorizationCodeStore,
  type AuthorizationCodeStore,
} from "./authorization-code-store.ts";
import { getServerConfig, type ServerConfig } from "./config/server-config.ts";
import { registerAuthorizationRoute } from "./routes/authorization-route.ts";
import { registerJwksRoute } from "./routes/jwks-route.ts";
import { registerOpenIdConfigurationRoute } from "./routes/openid-configuration-route.ts";
import { registerTokenRoute } from "./routes/token-route.ts";
import { createTokenStore, type TokenStore } from "./token-store.ts";

if (import.meta.main) {
  main();
}

async function main() {
  const fastify = await createServer();

  try {
    await fastify.listen({ port: 4000 });
    fastify.log.info("Authorization server is booted");
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}

export async function createServer(
  serverConfig?: ServerConfig,
  authorizationCodeStore: AuthorizationCodeStore = createAuthorizationCodeStore(),
  tokenStore: TokenStore = createTokenStore(),
) {
  const resolvedServerConfig = serverConfig ?? (await getServerConfig());
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

  fastify.register(formbody);

  registerOpenIdConfigurationRoute(fastify, resolvedServerConfig);
  registerAuthorizationRoute(
    fastify,
    resolvedServerConfig,
    authorizationCodeStore,
  );
  registerTokenRoute(
    fastify,
    resolvedServerConfig,
    authorizationCodeStore,
    tokenStore,
  );
  registerJwksRoute(fastify, resolvedServerConfig);

  return fastify;
}
