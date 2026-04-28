import { roleScopes, type Scope } from "../config/rbac-config.ts";
import type { UserRecord } from "../stores/user-store.ts";

/**
 * Get the allowed scopes for a user.
 * This is calculated using RBAC for a user.
 */
export function getAllowedScopesForUser(user: UserRecord): Scope[] {
  const scopes = new Set<Scope>();

  for (const role of user.roles ?? []) {
    for (const scope of roleScopes[role]) {
      scopes.add(scope);
    }
  }
  for (const scope of user.allowedScopes ?? []) {
    scopes.add(scope);
  }

  return [...scopes];
}
