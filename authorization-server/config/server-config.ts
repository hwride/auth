export type ServerConfig = {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
};

export function getServerConfig(): ServerConfig {
  const issuerEnvVar = process.env.ISSUER;
  if (!issuerEnvVar) {
    throw new Error("Missing ISSUER");
  }

  const issuer = validateIssuer(issuerEnvVar);

  return {
    issuer,
    authorizationEndpoint:
      process.env.AUTHORIZATION_ENDPOINT ?? `${issuer}/authorize`,
    tokenEndpoint: process.env.TOKEN_ENDPOINT ?? `${issuer}/token`,
    jwksUri: process.env.JWKS_URI ?? `${issuer}/.well-known/jwks.json`,
  };
}

function validateIssuer(issuer: string) {
  const issuerUrl = new URL(issuer);
  if (issuerUrl.search || issuerUrl.hash) {
    throw new Error("ISSUER must not include a query string or fragment");
  }

  return issuer;
}
