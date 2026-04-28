export type ClientConfig = {
  clientId: string;
  clientSecret: string;
  redirectUris: string[];
  accessTokenType: "opaque" | "jwt";
  accessTokenLifetimeSeconds: number;
  idTokenLifetimeSeconds: number;
  refreshTokenLifetimeSeconds: number;
};

const accessTokenLifetimeSeconds = 60 * 60;
const idTokenLifetimeSeconds = 60 * 60;
const refreshTokenLifetimeSeconds = 60 * 60 * 24 * 2;
const defaultClientBase = "http://localhost:3000";

export const clientsConfig: Readonly<ClientConfig>[] = [
  Object.freeze({
    clientId: "client-id-opaque",
    clientSecret: "test-client-secret",
    redirectUris: [
      new URL(
        "/callback",
        process.env.CLIENT_OPAQUE_BASE ?? defaultClientBase,
      ).toString(),
    ],
    accessTokenType: "opaque",
    accessTokenLifetimeSeconds,
    idTokenLifetimeSeconds,
    refreshTokenLifetimeSeconds,
  }),
  Object.freeze({
    clientId: "client-id-jwt",
    clientSecret: "other-test-client-secret",
    redirectUris: [
      new URL(
        "/callback",
        process.env.CLIENT_JWT_BASE ?? defaultClientBase,
      ).toString(),
    ],
    accessTokenType: "jwt",
    accessTokenLifetimeSeconds,
    idTokenLifetimeSeconds,
    refreshTokenLifetimeSeconds,
  }),
];
