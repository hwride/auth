import type { UserRecord } from "./stores/user-store.ts";

export const testUserId = "00000000-0000-0000-0000-000000000000";
export const janeUserId = "00000000-0000-0000-0000-000000000001";

export function defaultUsers(): UserRecord[] {
  return [
    {
      userId: testUserId,
      username: "user",
      password: "password",
      name: "John Smith",
    },
    {
      userId: janeUserId,
      username: "jane",
      password: "password",
      name: "Jane Smith",
    },
  ];
}
