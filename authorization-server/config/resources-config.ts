/*
  Resource Indicators for OAuth 2.0
  https://datatracker.ietf.org/doc/html/rfc8707
 */

export const ordersApiResource = "https://orders-api.example.test";

const supportedResources = [ordersApiResource] as const;

export type SupportedResource = (typeof supportedResources)[number];

export function isSupportedResource(
  resource: string,
): resource is SupportedResource {
  return supportedResources.includes(resource as SupportedResource);
}
