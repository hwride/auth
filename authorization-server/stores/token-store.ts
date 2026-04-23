export type AccessTokenRecord = {
  clientId: string;
  scope?: string;
};

export type TokenStore = {
  saveAccessToken(token: string, record: AccessTokenRecord): void;
  loadAccessToken(
    token: string | null | undefined,
  ): AccessTokenRecord | undefined;
  isEmpty(): boolean;
};

export function createTokenStore(): TokenStore {
  const accessTokens = new Map<string, AccessTokenRecord>();

  return {
    saveAccessToken(token, record) {
      accessTokens.set(token, record);
    },
    loadAccessToken(token) {
      if (token == null) {
        return undefined;
      }
      return accessTokens.get(token);
    },
    isEmpty() {
      return accessTokens.size === 0;
    },
  };
}
