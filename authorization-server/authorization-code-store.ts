export type AuthorizationCodeRecord = {
  clientId: string;
  redirectUri: string;
};

export type AuthorizationCodeStore = Map<string, AuthorizationCodeRecord>;

export function createAuthorizationCodeStore(): AuthorizationCodeStore {
  return new Map();
}
