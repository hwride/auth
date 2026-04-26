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

export const clientsConfig: ClientConfig[] = [
  {
    clientId: "client-id-opaque",
    clientSecret: "test-client-secret",
    redirectUris: ["http://localhost:3000/callback"],
    accessTokenType: "opaque",
    accessTokenLifetimeSeconds,
    idTokenLifetimeSeconds,
    refreshTokenLifetimeSeconds,
  },
  {
    clientId: "client-id-jwt",
    clientSecret: "other-test-client-secret",
    redirectUris: ["http://localhost:3000/callback"],
    accessTokenType: "jwt",
    accessTokenLifetimeSeconds,
    idTokenLifetimeSeconds,
    refreshTokenLifetimeSeconds,
  },
];
