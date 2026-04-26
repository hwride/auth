export type UserRecord = {
  username: string;
  password: string;
};

export type UserStore = {
  loadUser: (username: string) => UserRecord | undefined;
  saveUser: (user: UserRecord) => void;
};

export function createUserStore(initialUsers: UserRecord[] = defaultUsers()) {
  const users = new Map(
    initialUsers.map(function (user) {
      return [user.username, user];
    }),
  );

  return {
    loadUser(username) {
      return users.get(username);
    },
    saveUser(user) {
      users.set(user.username, user);
    },
  } satisfies UserStore;
}

function defaultUsers() {
  return [{ username: "user", password: "password" }];
}
