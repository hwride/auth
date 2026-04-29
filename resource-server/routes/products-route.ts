import type { FastifyInstance, FastifyReply } from "fastify";
import {
  authenticateAccessToken,
  type AccessTokenVerificationConfig,
} from "../utils/access-token-auth.ts";
import { hasScope } from "../utils/has-scope.ts";
import type { ResourceServerConfig } from "../config.ts";
import type { ProductStore } from "../stores/product-store.ts";

export function registerProductsRoute(
  fastify: FastifyInstance,
  serverConfig: ResourceServerConfig,
  productStore: ProductStore,
) {
  const verificationConfig: AccessTokenVerificationConfig = {
    resourceId: serverConfig.resourceIds.productsApi,
    acceptedAccessTokenAlgorithms: serverConfig.acceptedAccessTokenAlgorithms,
    issuer: serverConfig.issuer,
    jwksUri: serverConfig.jwksUri,
  };

  fastify.get("/products", async (request, reply) => {
    const authenticatedUser = await authenticateAccessToken(
      request,
      reply,
      verificationConfig,
    );

    if (!authenticatedUser) {
      return;
    }

    if (!hasScope(authenticatedUser.scope, "products:read")) {
      sendInsufficientScope(reply);
      return;
    }

    return { products: productStore.getProductsAll() };
  });

  fastify.get("/products/:id", async (request, reply) => {
    const authenticatedUser = await authenticateAccessToken(
      request,
      reply,
      verificationConfig,
    );

    if (!authenticatedUser) {
      return;
    }

    if (!hasScope(authenticatedUser.scope, "products:read")) {
      sendInsufficientScope(reply);
      return;
    }

    const requestedProductId = (request.params as { id: string }).id;
    const product = productStore.getProductById(requestedProductId);

    if (!product) {
      reply.status(404).send({ error: "not_found" });
      return;
    }

    return { product };
  });
}

function sendInsufficientScope(reply: FastifyReply) {
  reply
    .header(
      "WWW-Authenticate",
      'Bearer realm="resource-server", error="insufficient_scope", scope="products:read"',
    )
    .status(403)
    .send({ error: "insufficient_scope" });
}
