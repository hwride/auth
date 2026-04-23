export type AccessTokenRecord = {
  clientId: string;
  scope?: string;
};

export type TokenStore = Map<string, AccessTokenRecord>;

export function createTokenStore(): TokenStore {
  return new Map();
}
