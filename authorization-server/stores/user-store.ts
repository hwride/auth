import { randomUUID } from "node:crypto";

export type UserRecord = {
  userId: string;
  username: string;
  password: string;
  name: string;
  allowedScopes?: string[];
};

export type CreateUserInput = Omit<UserRecord, "userId">;

export type UserStore = {
  loadUserByUsername: (username: string) => UserRecord | undefined;
  loadUserById: (userId: string) => UserRecord | undefined;
  createUser: (user: CreateUserInput) => UserRecord;
};

export function createUserStore(initialUsers: UserRecord[] = []) {
  assertUniqueInitialUsers(initialUsers);

  const usersByUsername = new Map(
    initialUsers.map(function (user) {
      return [user.username, user];
    }),
  );
  const usersById = new Map(
    initialUsers.map(function (user) {
      return [user.userId, user];
    }),
  );
  const userStore: UserStore = {
    loadUserByUsername(username) {
      return usersByUsername.get(username);
    },

    loadUserById(userId) {
      return usersById.get(userId);
    },

    createUser(user) {
      if (usersByUsername.has(user.username)) {
        throw new Error(`Username already exists: ${user.username}`);
      }

      const savedUser = {
        ...user,
        userId: generateUniqueUserId(usersById),
      };

      usersByUsername.set(savedUser.username, savedUser);
      usersById.set(savedUser.userId, savedUser);
      return savedUser;
    },
  };

  return userStore;
}

function assertUniqueInitialUsers(initialUsers: UserRecord[]) {
  const usernames = new Set<string>();
  const userIds = new Set<string>();

  for (const user of initialUsers) {
    if (usernames.has(user.username)) {
      throw new Error(`Initial user username already exists: ${user.username}`);
    }
    if (userIds.has(user.userId)) {
      throw new Error(`Initial user ID already exists: ${user.userId}`);
    }

    usernames.add(user.username);
    userIds.add(user.userId);
  }
}

function generateUniqueUserId(usersById: Map<string, UserRecord>) {
  let userId = randomUUID();
  while (usersById.has(userId)) {
    userId = randomUUID();
  }
  return userId;
}
