import assert from "node:assert/strict";
import test from "node:test";
import { isUuidV4 } from "../utils/uuid.ts";
import { createUserStore } from "./user-store.ts";

test("createUserStore starts empty by default", function () {
  const userStore = createUserStore();

  assert.equal(userStore.loadUserByUsername("user"), undefined);
  assert.equal(userStore.loadUserById("missing-user-id"), undefined);
});

test("createUserStore uses allows loading of users by id and username", function () {
  const userStore = createUserStore([
    {
      userId: "existing-user-id",
      username: "existing-user",
      password: "existing-password",
      name: "Jane Smith",
    },
  ]);
  const existingUser = userStore.loadUserByUsername("existing-user");
  assert.notEqual(existingUser, undefined);

  assert.deepEqual(existingUser, {
    userId: "existing-user-id",
    username: "existing-user",
    password: "existing-password",
    name: "Jane Smith",
  });
  assert.equal(userStore.loadUserById("existing-user-id"), existingUser);
  assert.equal(userStore.loadUserByUsername("user"), undefined);
});

test("createUserStore rejects duplicate initial usernames", function () {
  assert.throws(
    function () {
      createUserStore([
        {
          userId: "first-user-id",
          username: "same-user",
          password: "first-password",
          name: "First User",
        },
        {
          userId: "second-user-id",
          username: "same-user",
          password: "second-password",
          name: "Second User",
        },
      ]);
    },
    {
      message: "Initial user username already exists: same-user",
    },
  );
});

test("createUserStore rejects duplicate initial user IDs", function () {
  assert.throws(
    function () {
      createUserStore([
        {
          userId: "same-user-id",
          username: "first-user",
          password: "first-password",
          name: "First User",
        },
        {
          userId: "same-user-id",
          username: "second-user",
          password: "second-password",
          name: "Second User",
        },
      ]);
    },
    {
      message: "Initial user ID already exists: same-user-id",
    },
  );
});

test("createUser creates users with generated user IDs", function () {
  const userStore = createUserStore([]);

  const user = userStore.createUser({
    username: "new-user",
    password: "new-password",
    name: "John Smith",
  });
  assert.equal(isUuidV4(user.userId), true);

  assert.deepEqual(userStore.loadUserByUsername("new-user"), {
    userId: user.userId,
    username: "new-user",
    password: "new-password",
    name: "John Smith",
  });
  assert.equal(userStore.loadUserById(user.userId), user);
});

test("createUser rejects duplicate usernames", function () {
  const userStore = createUserStore([]);

  const user = userStore.createUser({
    username: "new-user",
    password: "new-password",
    name: "New User",
  });

  assert.throws(
    function () {
      userStore.createUser({
        username: "new-user",
        password: "other-password",
        name: "Other User",
      });
    },
    {
      message: "Username already exists: new-user",
    },
  );
  assert.equal(userStore.loadUserByUsername("new-user"), user);
});

test("createUser ignores a userId property if one is present at runtime", function () {
  const userStore = createUserStore([]);

  const userWithIgnoredId = {
    userId: "provided-user-id",
    username: "new-user",
    password: "new-password",
    name: "New User",
  };
  const savedUser = userStore.createUser(userWithIgnoredId);

  assert.equal(isUuidV4(savedUser.userId), true);
  assert.notEqual(savedUser.userId, userWithIgnoredId.userId);
  assert.equal(userStore.loadUserById("provided-user-id"), undefined);
});
