export type AuthFlowContext = {
  state?: string;
  nonce?: string;
  codeVerifier?: string;
  redirectUri: string;
};
