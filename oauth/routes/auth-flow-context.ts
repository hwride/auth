export type AuthFlowContext = {
  state?: string;
  nonce?: string;
  codeVerifier?: string;
  maxAge?: number;
  authServerBaseUrl: string;
  issuer: string;
  discoveryUrl?: string;
  redirectUri: string;
  authorizationEndpoint: string;
  jwksUri: string;
  tokenEndpoint: string;
};
