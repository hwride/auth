import { randomUUID } from "node:crypto";

export type RefreshTokenRecord = {
  clientId: string;
  scope?: string;
  subject: string;
  expiresAt: number;
};

export type CreateRefreshTokenRecordInput = Omit<
  RefreshTokenRecord,
  "expiresAt"
>;

export type RefreshTokenStore = {
  generateNew(record: CreateRefreshTokenRecordInput): string;
  hasToken(token: string): boolean;
  get(token: string): RefreshTokenRecord | undefined;
  delete(token: string): boolean;
};

export function createRefreshTokenStore(
  refreshTokenLifetimeSeconds: number,
): RefreshTokenStore {
  const tokenStore = new Map<string, RefreshTokenRecord>();

  return {
    generateNew(record) {
      const refreshToken = randomUUID();
      tokenStore.set(refreshToken, {
        ...record,
        expiresAt: Date.now() + refreshTokenLifetimeSeconds * 1000,
      });
      return refreshToken;
    },
    hasToken(token) {
      return tokenStore.has(token);
    },
    get(token) {
      return tokenStore.get(token);
    },
    delete(token) {
      return tokenStore.delete(token);
    },
  };
}
