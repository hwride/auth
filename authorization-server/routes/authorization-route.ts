import { randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type { AuthorizationCodeStore } from "../authorization-code-store.ts";
import { clientsConfig, type ClientConfig } from "../config/clients-config.ts";
import type { ServerConfig } from "../config/server-config.ts";
import type { UserStore } from "../user-store.ts";

export function registerAuthorizationRoute(
  fastify: FastifyInstance,
  serverConfig: ServerConfig,
  authorizationCodeStore: AuthorizationCodeStore,
  userStore: UserStore,
) {
  const authorizationEndpointPath = new URL(serverConfig.authorizationEndpoint)
    .pathname;

  // Main authorization endpoint.
  fastify.get<{
    Querystring: {
      client_id?: string;
      response_type?: string;
      redirect_uri?: string;
    };
  }>(authorizationEndpointPath, async function (request, reply) {
    const authorizationRequest = validateAuthorizationRequest(request.query);
    if ("error" in authorizationRequest) {
      return reply
        .code(authorizationRequest.statusCode)
        .send(authorizationRequest.error);
    }

    return reply
      .type("text/html; charset=utf-8")
      .send(renderLoginPage(authorizationEndpointPath, authorizationRequest));
  });

  // Endpoint to submit login form to if login is required.
  fastify.post<{
    Body: {
      client_id?: string;
      response_type?: string;
      redirect_uri?: string;
      username?: string;
      password?: string;
    };
  }>(authorizationEndpointPath, async function (request, reply) {
    const authorizationRequest = validateAuthorizationRequest(request.body);
    if ("error" in authorizationRequest) {
      return reply
        .code(authorizationRequest.statusCode)
        .send(authorizationRequest.error);
    }

    if (
      !isValidLogin(userStore, request.body.username, request.body.password)
    ) {
      return reply
        .code(401)
        .type("text/html; charset=utf-8")
        .send(
          renderLoginPage(
            authorizationEndpointPath,
            authorizationRequest,
            "Invalid username or password",
          ),
        );
    }

    return reply.redirect(
      createAuthorizationRedirectUrl(
        serverConfig,
        authorizationCodeStore,
        authorizationRequest.clientConfig,
        authorizationRequest.redirectUri,
        request.body.username as string,
      ),
    );
  });
}

function validateAuthorizationRequest(input: {
  client_id?: string;
  response_type?: string;
  redirect_uri?: string;
}) {
  // Check for valid input.
  // OAuth 2.0, Authorization Response, Error Response
  // https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
  if (!input.redirect_uri) {
    return {
      statusCode: 400,
      error: {
        error: "invalid_request",
        error_description: "Missing redirect_uri",
      },
    };
  }

  const clientConfig = clientsConfig.find(function (client) {
    return client.clientId === input.client_id;
  });
  if (!clientConfig) {
    return {
      statusCode: 400,
      error: {
        error: "invalid_request",
        error_description: "Invalid client_id",
      },
    };
  }

  if (!clientConfig.redirectUris.includes(input.redirect_uri)) {
    return {
      statusCode: 400,
      error: {
        error: "invalid_request",
        error_description: "Invalid redirect_uri",
      },
    };
  }

  if (input.response_type !== "code") {
    return {
      statusCode: 400,
      error: {
        error: "unsupported_response_type",
      },
    };
  }

  return {
    clientConfig,
    redirectUri: input.redirect_uri,
    responseType: input.response_type,
  };
}

function renderLoginPage(
  authorizationEndpointPath: string,
  authorizationRequest: {
    clientConfig: ClientConfig;
    redirectUri: string;
    responseType: string;
  },
  errorMessage?: string,
) {
  const escapedErrorMessage = errorMessage
    ? `<p>${escapeHtml(errorMessage)}</p>`
    : "";
  const signupPath = `/signup?client_id=${encodeURIComponent(authorizationRequest.clientConfig.clientId)}&response_type=${encodeURIComponent(authorizationRequest.responseType)}&redirect_uri=${encodeURIComponent(authorizationRequest.redirectUri)}`;

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Login</title>
  </head>
  <body>
    <h1>Login</h1>
    <p>Sign in to continue for client ${escapeHtml(authorizationRequest.clientConfig.clientId)}.</p>
    ${escapedErrorMessage}
    <form method="post" action="${escapeHtml(authorizationEndpointPath)}">
      <input type="hidden" name="client_id" value="${escapeHtml(authorizationRequest.clientConfig.clientId)}">
      <input type="hidden" name="response_type" value="${escapeHtml(authorizationRequest.responseType)}">
      <input type="hidden" name="redirect_uri" value="${escapeHtml(authorizationRequest.redirectUri)}">
      <label>
        Username
        <input type="text" name="username" autocomplete="username" required>
      </label>
      <label>
        Password
        <input type="password" name="password" autocomplete="current-password" required>
      </label>
      <button type="submit">Login</button>
    </form>
    <p><a href="${escapeHtml(signupPath)}">Sign up</a></p>
  </body>
</html>`;
}

function isValidLogin(
  userStore: UserStore,
  username?: string,
  password?: string,
) {
  if (!username || !password) {
    return false;
  }

  const user = userStore.loadUser(username);
  return user?.password === password;
}

function createAuthorizationRedirectUrl(
  serverConfig: ServerConfig,
  authorizationCodeStore: AuthorizationCodeStore,
  clientConfig: ClientConfig,
  redirectUri: string,
  subject: string,
) {
  const code = randomUUID();
  authorizationCodeStore.set(code, {
    clientId: clientConfig.clientId,
    subject,
    redirectUri,
    expiresAt:
      Date.now() + serverConfig.authorizationCodeLifetimeSeconds * 1000,
  });

  const redirectUrl = new URL(redirectUri);
  redirectUrl.searchParams.set("code", code);
  return redirectUrl.toString();
}

function escapeHtml(value: string) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
