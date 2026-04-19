export type ClientConfig = {
  clientId: string;
  clientSecret: string;
  redirectUris: string[];
};

export const clientsConfig: ClientConfig[] = [
  {
    clientId: "test-client-id",
    clientSecret: "test-client-secret",
    redirectUris: ["http://localhost:3000/callback"],
  },
  {
    clientId: "other-test-client-id",
    clientSecret: "other-test-client-secret",
    redirectUris: ["http://localhost:3000/callback"],
  },
];
