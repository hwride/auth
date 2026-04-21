import type { FastifyInstance } from "fastify";
import type { ServerConfig } from "../config/server-config.ts";
import type { UserStore } from "../user-store.ts";

type SignupState = {
  client_id?: string;
  response_type?: string;
  redirect_uri?: string;
  username?: string;
};

export function registerSignupRoute(
  fastify: FastifyInstance,
  serverConfig: ServerConfig,
  userStore: UserStore,
) {
  const authorizationEndpointPath = new URL(serverConfig.authorizationEndpoint)
    .pathname;

  fastify.get<{
    Querystring: {
      client_id?: string;
      response_type?: string;
      redirect_uri?: string;
    };
  }>("/signup", async function (request, reply) {
    return reply
      .type("text/html; charset=utf-8")
      .send(
        renderSignupPage(
          {
            authorizationEndpointPath,
            signupState: request.query,
          },
        ),
      );
  });

  fastify.post<{
    Body: {
      client_id?: string;
      response_type?: string;
      redirect_uri?: string;
      username?: string;
      password?: string;
    };
  }>("/signup", async function (request, reply) {
    const username = request.body.username?.trim();
    const password = request.body.password;

    if (!username || !password) {
      return reply
        .code(400)
        .type("text/html; charset=utf-8")
        .send(
          renderSignupPage(
            {
              authorizationEndpointPath,
              signupState: request.body,
              errorMessage: "Username and password are required",
            },
          ),
        );
    }

    if (userStore.loadUser(username)) {
      return reply
        .code(409)
        .type("text/html; charset=utf-8")
        .send(
          renderSignupPage(
            {
              authorizationEndpointPath,
              signupState: request.body,
              errorMessage: "That username already exists",
            },
          ),
        );
    }

    userStore.saveUser({ username, password });

    const loginUrl = new URL(authorizationEndpointPath, "http://localhost");
    if (request.body.client_id) {
      loginUrl.searchParams.set("client_id", request.body.client_id);
    }
    if (request.body.response_type) {
      loginUrl.searchParams.set("response_type", request.body.response_type);
    }
    if (request.body.redirect_uri) {
      loginUrl.searchParams.set("redirect_uri", request.body.redirect_uri);
    }

    return reply.redirect(loginUrl.pathname + loginUrl.search);
  });
}

function renderSignupPage(
  {
    authorizationEndpointPath,
    signupState,
    errorMessage,
  }: {
    authorizationEndpointPath: string;
    signupState: SignupState;
    errorMessage?: string;
  },
) {
  const escapedErrorMessage = errorMessage
    ? `<p>${escapeHtml(errorMessage)}</p>`
    : "";

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Sign up</title>
  </head>
  <body>
    <h1>Sign up</h1>
    ${escapedErrorMessage}
    <form method="post" action="/signup">
      <input type="hidden" name="client_id" value="${escapeHtml(signupState.client_id ?? "")}">
      <input type="hidden" name="response_type" value="${escapeHtml(signupState.response_type ?? "")}">
      <input type="hidden" name="redirect_uri" value="${escapeHtml(signupState.redirect_uri ?? "")}">
      <label>
        Username
        <input type="text" name="username" autocomplete="username" value="${escapeHtml(signupState.username ?? "")}" required>
      </label>
      <label>
        Password
        <input type="password" name="password" autocomplete="new-password" required>
      </label>
      <button type="submit">Create account</button>
    </form>
    <p><a href="${escapeHtml(createLinkWithParams(authorizationEndpointPath, signupState))}">Log in</a></p>
  </body>
</html>`;
}

function createLinkWithParams(
  path: string,
  params: SignupState,
) {
  const url = new URL(path, "http://localhost");
  if (params.client_id) {
    url.searchParams.set("client_id", params.client_id);
  }
  if (params.response_type) {
    url.searchParams.set("response_type", params.response_type);
  }
  if (params.redirect_uri) {
    url.searchParams.set("redirect_uri", params.redirect_uri);
  }
  return url.pathname + url.search;
}

function escapeHtml(value: string) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
