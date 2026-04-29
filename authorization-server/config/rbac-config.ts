export type Scope = (typeof scopes)[number];
export const scopes = [
  "orders:read",
  "orders:read:any",
  "products:read",
] as const;

export type Role = keyof typeof roleScopes;
export const roleScopes = {
  admin: ["orders:read", "orders:read:any", "products:read"],
  customer: ["orders:read"],
} satisfies Record<string, readonly Scope[]>;
