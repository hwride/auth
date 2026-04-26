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

    return {
      orders: [
        { orderId: "order-001", userId: authenticatedUser.sub },
        { orderId: "order-002", userId: authenticatedUser.sub },
      ],
    };
  });
}
