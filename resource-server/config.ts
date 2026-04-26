export type ResourceServerConfig = {
  authServerBase: string;
  issuer: string;
  jwksUri: string;
};

export async function getResourceServerConfig(): Promise<ResourceServerConfig> {
  const authServerBase = process.env.AUTH_SERVER_BASE;
  if (!authServerBase) {
    throw new Error("Missing AUTH_SERVER_BASE");
  }

  const discoveryUrl = new URL(
    "/.well-known/openid-configuration",
    authServerBase,
  );
  const response = await fetch(discoveryUrl);

  if (!response.ok) {
    throw new Error(
      `Failed to fetch auth server discovery metadata from ${discoveryUrl.toString()}`,
    );
  }

  const metadata = (await response.json()) as {
    issuer?: string;
    jwks_uri?: string;
  };

  if (!metadata.issuer) {
    throw new Error("Discovery metadata missing issuer");
  }

  if (!metadata.jwks_uri) {
    throw new Error("Discovery metadata missing jwks_uri");
  }

  return {
    authServerBase,
    issuer: metadata.issuer,
    jwksUri: metadata.jwks_uri,
  };
}
