export type AuthFlowContext = {
  state?: string;
  nonce?: string;
  codeVerifier?: string;
  maxAge?: number;
  accessToken?: string;
  idToken?: string;
  refreshToken?: string;
  authServerBaseUrl: string;
  issuer: string;
  discoveryUrl?: string;
  redirectUri: string;
  authorizationEndpoint: string;
  jwksUri: string;
  tokenEndpoint: string;
};
