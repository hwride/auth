export type AuthorizationCodeRecord = {
  clientId: string;
  subject: string;
  redirectUri: string;
  expiresAt: number;
  codeChallenge?: string;
  codeChallengeMethod?: "plain" | "S256";
};

export type AuthorizationCodeStore = Map<string, AuthorizationCodeRecord>;

export function createAuthorizationCodeStore(): AuthorizationCodeStore {
  return new Map();
}
