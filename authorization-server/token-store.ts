export type AccessTokenRecord = {
  clientId: string;
};

export type TokenStore = Map<string, AccessTokenRecord>;

export function createTokenStore(): TokenStore {
  return new Map();
}
