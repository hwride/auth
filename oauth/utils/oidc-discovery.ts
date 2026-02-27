import type { FastifyBaseLogger } from "fastify";

export async function discoverAuthServerEndpoints(
  authServerBase: string,
  logger: FastifyBaseLogger,
) {
  const oidcDiscoveryUrl = new URL(
    "/.well-known/openid-configuration",
    authServerBase,
  );
  const oauthDiscoveryUrl = new URL(
    "/.well-known/oauth-authorization-server",
    authServerBase,
  );

  const discoveryTargets = [
    { kind: "oidc", url: oidcDiscoveryUrl },
    { kind: "oauth", url: oauthDiscoveryUrl },
  ] as const;

  for (const target of discoveryTargets) {
    logger.info(
      { discoveryUrl: target.url.toString(), type: target.kind },
      "Checking auth server discovery endpoint",
    );
    try {
      const response = await fetch(target.url.toString());
      if (!response.ok) {
        logger.warn("Discovery endpoint returned non-success status");
        continue;
      }
      const metadata = (await response.json()) as {
        authorization_endpoint?: string;
        token_endpoint?: string;
      };
      if (metadata.authorization_endpoint && metadata.token_endpoint) {
        const result = {
          kind: target.kind,
          authorizationEndpoint: metadata.authorization_endpoint,
          tokenEndpoint: metadata.token_endpoint,
          discoveryUrl: target.url.toString(),
        };
        logger.info(result, `Using endpoints from ${target.kind} discovery`);
        return result;
      } else {
        logger.warn(
          { discoveryUrl: target.url.toString(), type: target.kind },
          `Discovery metadata missing required endpoints from ${target.kind} discovery`,
        );
      }
    } catch {
      logger.warn("Discovery request failed; trying next endpoint");
    }
  }

  const fallback = {
    authorizationEndpoint: new URL("/authorize", authServerBase).toString(),
    tokenEndpoint: new URL("/oauth/token", authServerBase).toString(),
    discoveryUrl: undefined,
  };
  logger.warn(
    {
      authorizationEndpoint: fallback.authorizationEndpoint,
      tokenEndpoint: fallback.tokenEndpoint,
    },
    "No discovery metadata found; using fallback endpoints",
  );
  return fallback;
}
