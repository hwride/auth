import type { FastifyInstance, FastifyReply } from "fastify";
import { authenticateAccessToken } from "../utils/access-token-auth.ts";
import { hasScope } from "../utils/has-scope.ts";
import type { ResourceServerConfig } from "../config.ts";
import type { OrderStore } from "../stores/order-store.ts";

export function registerOrdersRoute(
  fastify: FastifyInstance,
  serverConfig: ResourceServerConfig,
  orderStore: OrderStore,
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
      sendInsufficientScope(reply);
      return;
    }

    return {
      orders: orderStore.getOrdersByUserId(authenticatedUser.sub),
    };
  });

  fastify.get("/orders/:id", async (request, reply) => {
    const authenticatedUser = await authenticateAccessToken(
      request,
      reply,
      serverConfig,
    );

    if (!authenticatedUser) {
      return;
    }

    if (!hasScope(authenticatedUser.scope, "orders:read")) {
      sendInsufficientScope(reply);
      return;
    }

    const requestedOrderId = (request.params as { id: string }).id;
    const order = orderStore.getOrderById(requestedOrderId);

    if (!order) {
      reply.status(404).send({ error: "not_found" });
      return;
    }

    if (order.userId !== authenticatedUser.sub) {
      reply.status(403).send({ error: "forbidden" });
      return;
    }

    return { order };
  });
}

function sendInsufficientScope(reply: FastifyReply) {
  reply
    .header(
      "WWW-Authenticate",
      'Bearer realm="resource-server", error="insufficient_scope", scope="orders:read"',
    )
    .status(403)
    .send({ error: "insufficient_scope" });
}
