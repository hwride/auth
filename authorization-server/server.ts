import formbody from "@fastify/formbody";
import Fastify from "fastify";
import { getServerConfig, type ServerConfig } from "./config/server-config.ts";
import { registerAuthorizationRoute } from "./routes/authorization-route.ts";
import { registerJwksRoute } from "./routes/jwks-route.ts";
import { registerOpenIdConfigurationRoute } from "./routes/openid-configuration-route.ts";
import { registerSignupRoute } from "./routes/signup-route.ts";
import { registerTokenRoute } from "./routes/token-route.ts";
import {
  createAuthorizationCodeStore,
  type AuthorizationCodeStore,
} from "./stores/authorization-code-store.ts";
import {
  createRefreshTokenStore,
  type RefreshTokenStore,
} from "./stores/refresh-token-store.ts";
import { createTokenStore, type TokenStore } from "./stores/token-store.ts";
import { createUserStore, type UserStore } from "./stores/user-store.ts";

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
  userStore: UserStore = createUserStore(),
  refreshTokenStore?: RefreshTokenStore,
) {
  const resolvedServerConfig = serverConfig ?? (await getServerConfig());
  const resolvedRefreshTokenStore =
    refreshTokenStore ?? createRefreshTokenStore();
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
    userStore,
  );
  registerSignupRoute(fastify, resolvedServerConfig, userStore);
  registerTokenRoute(
    fastify,
    resolvedServerConfig,
    authorizationCodeStore,
    tokenStore,
    resolvedRefreshTokenStore,
  );
  registerJwksRoute(fastify, resolvedServerConfig);

  return fastify;
}
