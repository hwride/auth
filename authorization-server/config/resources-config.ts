/*
  Resource Indicators for OAuth 2.0
  https://datatracker.ietf.org/doc/html/rfc8707
 */

export const ordersApiResource = "https://orders-api.example.test";
export const productsApiResource = "https://products-api.example.test";

export type ResourceConfig = {
  id: string;
  allowedScopes: readonly string[];
};

const resources: ResourceConfig[] = [
  {
    id: ordersApiResource,
    allowedScopes: ["orders:read", "orders:read:any", "orders:write"],
  },
  {
    id: productsApiResource,
    allowedScopes: ["products:read"],
  },
];

const supportedResourceIds = resources.map((resource) => {
  return resource.id;
});

export type SupportedResource = (typeof resources)[number]["id"];

export function isSupportedResource(
  resource: string,
): resource is SupportedResource {
  return supportedResourceIds.includes(resource as SupportedResource);
}

export function getResourceConfig(resource: SupportedResource): ResourceConfig {
  const resourceConfig = resources.find(function (supportedResource) {
    return supportedResource.id === resource;
  });
  if (!resourceConfig) {
    throw new Error(`Unknown resource: ${resource}`);
  }
  return resourceConfig;
}
