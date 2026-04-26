import assert from "node:assert/strict";
import test from "node:test";
import { testUserId, defaultUsers, janeUserId } from "./default-users.ts";
import { createUserStore } from "./stores/user-store.ts";

test("defaultUsers returns the seeded test users", function () {
  assert.deepEqual(defaultUsers(), [
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
  ]);
});

test("defaultUsers can seed a user store", function () {
  const userStore = createUserStore(defaultUsers());

  const user = userStore.loadUserByUsername("user");
  const jane = userStore.loadUserByUsername("jane");

  assert.notEqual(user, undefined);
  assert.notEqual(jane, undefined);
  assert.equal(userStore.loadUserById(testUserId), user);
  assert.equal(userStore.loadUserById(janeUserId), jane);
});
