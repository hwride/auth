import assert from "node:assert/strict";
import test from "node:test";
import { createUserStore } from "./user-store.ts";

test("createUserStore seeds the default user", function () {
  const userStore = createUserStore();

  assert.deepEqual(userStore.loadUser("user"), {
    username: "user",
    password: "password",
    name: "John Smith",
  });
  assert.deepEqual(userStore.loadUser("jane"), {
    username: "jane",
    password: "password",
    name: "Jane Smith",
  });
});

test("createUserStore uses provided initial users", function () {
  const userStore = createUserStore([
    {
      username: "existing-user",
      password: "existing-password",
      name: "Jane Smith",
    },
  ]);

  assert.deepEqual(userStore.loadUser("existing-user"), {
    username: "existing-user",
    password: "existing-password",
    name: "Jane Smith",
  });
  assert.equal(userStore.loadUser("user"), undefined);
});

test("saveUser stores and overwrites users by username", function () {
  const userStore = createUserStore([]);

  userStore.saveUser({
    username: "new-user",
    password: "first-password",
    name: "John Smith",
  });
  userStore.saveUser({
    username: "new-user",
    password: "updated-password",
    name: "Jane Smith",
  });

  assert.deepEqual(userStore.loadUser("new-user"), {
    username: "new-user",
    password: "updated-password",
    name: "Jane Smith",
  });
});
