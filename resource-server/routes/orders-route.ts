import type { FastifyInstance } from "fastify";
import { authenticateAccessToken } from "../utils/access-token-auth.ts";
import type { ResourceServerConfig } from "../config.ts";

export function registerOrdersRoute(
  fastify: FastifyInstance,
  serverConfig: ResourceServerConfig,
) {
  fastify.get("/orders", async (request, reply) => {
    const authenticatedUser = await authenticateAccessToken(
      request,
      reply,
      serverConfig,
    );

    // If user is undefined, the error response will have been handled by the util.
    if (!authenticatedUser) {
      return;
    }
    // https://www.rfc-editor.org/rfc/rfc6750.html#section-3.1
    if (!hasScope(authenticatedUser.scope, "orders:read")) {
      reply
        .header(
          "WWW-Authenticate",
          'Bearer realm="resource-server", error="insufficient_scope", scope="orders:read"',
        )
        .status(403)
        .send({ error: "insufficient_scope" });
      return;
    }

    return {
      orders: [
        { orderId: "order-001", userId: authenticatedUser.sub },
        { orderId: "order-002", userId: authenticatedUser.sub },
      ],
    };
  });
}

function hasScope(scope: string | undefined, expectedScope: string) {
  return scope?.split(/\s+/).includes(expectedScope) ?? false;
}
