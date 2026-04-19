import type { FastifyBaseLogger } from "fastify";

type DiscoveryResult = {
  kind?: "oidc" | "oauth" | "fallback";
  issuer?: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string | undefined;
  discoveryUrl: string | undefined;
};

export async function authServerDiscovery(
  authServerBase: string,
  logger: FastifyBaseLogger,
): Promise<DiscoveryResult> {
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
        issuer?: string;
        authorization_endpoint?: string;
        token_endpoint?: string;
        jwks_uri?: string;
      };
      if (
        metadata.authorization_endpoint &&
        metadata.token_endpoint &&
        metadata.jwks_uri
      ) {
        const result = {
          kind: target.kind,
          issuer: metadata.issuer,
          authorizationEndpoint: metadata.authorization_endpoint,
          tokenEndpoint: metadata.token_endpoint,
          jwksUri: metadata.jwks_uri,
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
    kind: "fallback" as const,
    issuer: undefined,
    authorizationEndpoint: new URL("/authorize", authServerBase).toString(),
    tokenEndpoint: new URL("/oauth/token", authServerBase).toString(),
    jwksUri: undefined,
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
