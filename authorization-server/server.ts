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
  const fastify = createServer();

  try {
    await fastify.listen({ port: 4000 });
    fastify.log.info("Authorization server is booted");
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}

export function createServer(
  serverConfig: ServerConfig = getServerConfig(),
  authorizationCodeStore: AuthorizationCodeStore = createAuthorizationCodeStore(),
  tokenStore: TokenStore = createTokenStore(),
) {
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

  registerOpenIdConfigurationRoute(fastify, serverConfig);
  registerAuthorizationRoute(fastify, serverConfig, authorizationCodeStore);
  registerTokenRoute(fastify, serverConfig, authorizationCodeStore, tokenStore);
  registerJwksRoute(fastify);

  return fastify;
}
