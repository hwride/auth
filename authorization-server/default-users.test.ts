import assert from "node:assert/strict";
import test from "node:test";
import {
  testUserId,
  defaultUsers,
  janeUserId,
  adminUserId,
} from "./default-users.ts";
import { createUserStore } from "./stores/user-store.ts";

test("defaultUsers returns the seeded test users", function () {
  assert.deepEqual(defaultUsers(), [
    {
      userId: adminUserId,
      username: "admin",
      password: "password",
      name: "John Wick",
      allowedScopes: ["orders:read", "orders:read:any"],
    },
    {
      userId: testUserId,
      username: "user",
      password: "password",
      name: "John Smith",
      allowedScopes: ["orders:read"],
    },
    {
      userId: janeUserId,
      username: "jane",
      password: "password",
      name: "Jane Smith",
    },
  ]);
});

test("defaultUsers can seed a user store", function () {
  const userStore = createUserStore(defaultUsers());

  const user = userStore.loadUserByUsername("user");
  const jane = userStore.loadUserByUsername("jane");

  assert.notEqual(user, undefined);
  assert.notEqual(jane, undefined);
  assert.deepEqual(user.allowedScopes, ["orders:read"]);
  assert.equal(jane.allowedScopes, undefined);
  assert.equal(userStore.loadUserById(testUserId), user);
  assert.equal(userStore.loadUserById(janeUserId), jane);
});
