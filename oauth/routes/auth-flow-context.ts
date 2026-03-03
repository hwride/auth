export type AuthFlowContext = {
  state?: string;
  nonce?: string;
  codeVerifier?: string;
  authServerBaseUrl: string;
  discoveryUrl?: string;
  redirectUri: string;
  authorizationEndpoint: string;
  jwksUri: string;
  tokenEndpoint: string;
};
