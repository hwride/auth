import type { FastifyInstance } from "fastify";
import type { ServerConfig } from "../config/server-config.ts";
import type { UserStore } from "../stores/user-store.ts";

type SignupPageQueryParams = {
  client_id?: string;
  response_type?: string;
  redirect_uri?: string;
  scope?: string;
  nonce?: string;
  state?: string;
  code_challenge?: string;
  code_challenge_method?: string;
  name?: string;
};

export function registerSignupRoute(
  fastify: FastifyInstance,
  serverConfig: ServerConfig,
  userStore: UserStore,
) {
  const authorizationEndpointPath = new URL(serverConfig.authorizationEndpoint)
    .pathname;

  fastify.get<{
    Querystring: SignupPageQueryParams;
  }>("/signup", async function (request, reply) {
    return reply.type("text/html; charset=utf-8").send(
      renderSignupPage({
        authorizationEndpointPath,
        signupQueryParams: request.query,
      }),
    );
  });

  fastify.post<{
    Body: {
      client_id?: string;
      response_type?: string;
      redirect_uri?: string;
      scope?: string;
      nonce?: string;
      state?: string;
      code_challenge?: string;
      code_challenge_method?: string;
      username?: string;
      name?: string;
      password?: string;
    };
  }>("/signup", async function (request, reply) {
    const username = request.body.username?.trim();
    const name = request.body.name?.trim();
    const password = request.body.password;

    if (!username || !name || !password) {
      return reply
        .code(400)
        .type("text/html; charset=utf-8")
        .send(
          renderSignupPage({
            authorizationEndpointPath,
            signupQueryParams: request.body,
            errorMessage: "Username, name and password are required",
          }),
        );
    }

    if (userStore.loadUser(username)) {
      return reply
        .code(409)
        .type("text/html; charset=utf-8")
        .send(
          renderSignupPage({
            authorizationEndpointPath,
            signupQueryParams: request.body,
            errorMessage: "That username already exists",
          }),
        );
    }

    userStore.saveUser({ username, password, name });

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
    if (request.body.state) {
      loginUrl.searchParams.set("state", request.body.state);
    }
    if (request.body.scope) {
      loginUrl.searchParams.set("scope", request.body.scope);
    }
    if (request.body.nonce) {
      loginUrl.searchParams.set("nonce", request.body.nonce);
    }
    if (request.body.code_challenge) {
      loginUrl.searchParams.set("code_challenge", request.body.code_challenge);
    }
    if (request.body.code_challenge_method) {
      loginUrl.searchParams.set(
        "code_challenge_method",
        request.body.code_challenge_method,
      );
    }

    return reply.redirect(loginUrl.pathname + loginUrl.search);
  });
}

function renderSignupPage({
  authorizationEndpointPath,
  signupQueryParams,
  errorMessage,
}: {
  authorizationEndpointPath: string;
  signupQueryParams: SignupPageQueryParams;
  errorMessage?: string;
}) {
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
      <input type="hidden" name="client_id" value="${escapeHtml(signupQueryParams.client_id ?? "")}">
      <input type="hidden" name="response_type" value="${escapeHtml(signupQueryParams.response_type ?? "")}">
      <input type="hidden" name="redirect_uri" value="${escapeHtml(signupQueryParams.redirect_uri ?? "")}">
      <input type="hidden" name="scope" value="${escapeHtml(signupQueryParams.scope ?? "")}">
      <input type="hidden" name="nonce" value="${escapeHtml(signupQueryParams.nonce ?? "")}">
      <input type="hidden" name="state" value="${escapeHtml(signupQueryParams.state ?? "")}">
      <input type="hidden" name="code_challenge" value="${escapeHtml(signupQueryParams.code_challenge ?? "")}">
      <input type="hidden" name="code_challenge_method" value="${escapeHtml(signupQueryParams.code_challenge_method ?? "")}">
      <label>
        Username
        <input type="text" name="username" autocomplete="username" required>
      </label>
      <label>
        Name
        <input type="text" name="name" autocomplete="name" value="${escapeHtml(signupQueryParams.name ?? "")}" required>
      </label>
      <label>
        Password
        <input type="password" name="password" autocomplete="new-password" required>
      </label>
      <button type="submit">Create account</button>
    </form>
    <p><a href="${escapeHtml(createLinkWithParams(authorizationEndpointPath, signupQueryParams))}">Log in</a></p>
  </body>
</html>`;
}

function createLinkWithParams(path: string, params: SignupPageQueryParams) {
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
  if (params.state) {
    url.searchParams.set("state", params.state);
  }
  if (params.scope) {
    url.searchParams.set("scope", params.scope);
  }
  if (params.nonce) {
    url.searchParams.set("nonce", params.nonce);
  }
  if (params.code_challenge) {
    url.searchParams.set("code_challenge", params.code_challenge);
  }
  if (params.code_challenge_method) {
    url.searchParams.set("code_challenge_method", params.code_challenge_method);
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
