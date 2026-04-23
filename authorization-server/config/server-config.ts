import { generateKeyPair } from "jose";
import type { GenerateKeyPairResult } from "jose/key/generate/keypair";

export type ServerConfig = {
  jwtSigningAlg: "RS256";
  publicKey: GenerateKeyPairResult["publicKey"];
  privateKey: GenerateKeyPairResult["privateKey"];
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  authorizationCodeLifetimeSeconds: number;
  accessTokenLifetimeSeconds: number;
  idTokenLifetimeSeconds: number;
  refreshTokenLifetimeSeconds: number;
};

export async function getServerConfig(): Promise<ServerConfig> {
  const issuerEnvVar = process.env.ISSUER;
  if (!issuerEnvVar) {
    throw new Error("Missing ISSUER");
  }

  const issuer = validateIssuer(issuerEnvVar);
  const jwtSigningAlg = "RS256";
  const { publicKey, privateKey } = await generateKeyPair(jwtSigningAlg);

  return {
    jwtSigningAlg,
    publicKey,
    privateKey,
    issuer,
    authorizationEndpoint:
      process.env.AUTHORIZATION_ENDPOINT ?? `${issuer}/authorize`,
    tokenEndpoint: process.env.TOKEN_ENDPOINT ?? `${issuer}/token`,
    jwksUri: process.env.JWKS_URI ?? `${issuer}/.well-known/jwks.json`,
    authorizationCodeLifetimeSeconds: 60 * 10,
    accessTokenLifetimeSeconds: 60 * 60,
    idTokenLifetimeSeconds: 60 * 60,
    refreshTokenLifetimeSeconds: 60 * 60 * 24 * 2,
  };
}

function validateIssuer(issuer: string) {
  const issuerUrl = new URL(issuer);
  if (issuerUrl.search || issuerUrl.hash) {
    throw new Error("ISSUER must not include a query string or fragment");
  }

  return issuer;
}
