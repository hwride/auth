import assert from "node:assert/strict";
import test from "node:test";
import {
  adminUserId,
  defaultUsers,
  janeUserId,
  testUserId,
} from "./default-users.ts";
import { createUserStore } from "./stores/user-store.ts";

test("defaultUsers returns the seeded test users", function () {
  assert.deepEqual(defaultUsers(), [
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
  ]);
});

test("defaultUsers can seed a user store", function () {
  const userStore = createUserStore(defaultUsers());

  const admin = userStore.loadUserByUsername("admin");
  const user = userStore.loadUserByUsername("user");
  const jane = userStore.loadUserByUsername("jane");

  assert.notEqual(admin, undefined);
  assert.notEqual(user, undefined);
  assert.notEqual(jane, undefined);
  assert.deepEqual(admin.roles, ["admin"]);
  assert.deepEqual(user.roles, ["customer"]);
  assert.equal(jane.allowedScopes, undefined);
  assert.equal(jane.roles, undefined);
  assert.equal(userStore.loadUserById(adminUserId), admin);
  assert.equal(userStore.loadUserById(testUserId), user);
  assert.equal(userStore.loadUserById(janeUserId), jane);
});
