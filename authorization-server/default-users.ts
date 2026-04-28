import type { UserRecord } from "./stores/user-store.ts";

export const adminUserId = "00000000-0000-0000-0000-000000000000";
export const testUserId = "00000000-0000-0000-0000-000000000001";
export const janeUserId = "00000000-0000-0000-0000-000000000002";

export function defaultUsers(): UserRecord[] {
  return [
    {
      userId: adminUserId,
      username: "admin",
      password: "password",
      name: "John Wick",
      roles: ["admin"],
    },
    {
      userId: testUserId,
      username: "user",
      password: "password",
      name: "John Smith",
      roles: ["customer"],
    },
    {
      userId: janeUserId,
      username: "jane",
      password: "password",
      name: "Jane Smith",
    },
  ];
}
