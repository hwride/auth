import { generateKeyPair } from "jose";
import type { ServerConfig } from "../config/server-config.ts";

const jwtSigningAlg = "RS256";
const testSigningKeys = await generateKeyPair(jwtSigningAlg);

const defaultServerConfig: ServerConfig = {
  jwtSigningAlg,
  publicKey: testSigningKeys.publicKey,
  privateKey: testSigningKeys.privateKey,
  issuer: "https://issuer.example.test",
  authorizationEndpoint: "https://issuer.example.test/authorize",
  tokenEndpoint: "https://issuer.example.test/token",
  jwksUri: "https://issuer.example.test/.well-known/jwks.json",
  authorizationCodeLifetimeSeconds: 60 * 10,
};

export function getTestServerConfig(
  overrides: Partial<ServerConfig> = {},
): ServerConfig {
  return {
    ...defaultServerConfig,
    ...overrides,
  };
}
