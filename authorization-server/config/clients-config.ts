export type ClientConfig = {
  clientId: string;
  clientSecret: string;
  redirectUris: string[];
  accessTokenType: "opaque" | "jwt";
};

export const clientsConfig: ClientConfig[] = [
  {
    clientId: "client-id-opaque",
    clientSecret: "test-client-secret",
    redirectUris: ["http://localhost:3000/callback"],
    accessTokenType: "opaque",
  },
  {
    clientId: "client-id-jwt",
    clientSecret: "other-test-client-secret",
    redirectUris: ["http://localhost:3000/callback"],
    accessTokenType: "jwt",
  },
];
