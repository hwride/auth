import { randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { clientsConfig, type ClientConfig } from "../config/clients-config.ts";
import type { ServerConfig } from "../config/server-config.ts";
import type { AuthorizationCodeStore } from "../stores/authorization-code-store.ts";
import type { UserStore } from "../stores/user-store.ts";

type AuthorizeQueryParams = {
  client_id?: string;
  response_type?: string;
  redirect_uri?: string;
  scope?: string;
  nonce?: string;
  state?: string;
  code_challenge?: string;
  code_challenge_method?: string;
};

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
    Querystring: AuthorizeQueryParams;
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
    Body: AuthorizeQueryParams & {
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
        authorizationRequest,
        request.body.username as string,
      ),
    );
  });
}

type AuthorizationRequest = {
  clientConfig: ClientConfig;
  redirectUri: string;
  responseType: string;
  scope?: string;
  nonce?: string;
  state?: string;
  codeChallenge?: string;
  codeChallengeMethod?: "plain" | "S256";
};
type AuthorizationRequestError = {
  statusCode: number;
  error: { error: string; error_description?: string };
};

function validateAuthorizationRequest(
  input: AuthorizeQueryParams,
): AuthorizationRequest | AuthorizationRequestError {
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

  // Check for a matching client.
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

  // Check for matching redirect URI.
  if (!clientConfig.redirectUris.includes(input.redirect_uri)) {
    return {
      statusCode: 400,
      error: {
        error: "invalid_request",
        error_description: "Invalid redirect_uri",
      },
    };
  }

  // Check for supported grant type.
  if (input.response_type !== "code") {
    return {
      statusCode: 400,
      error: {
        error: "unsupported_response_type",
      },
    };
  }

  const successResponse: AuthorizationRequest = {
    clientConfig,
    redirectUri: input.redirect_uri,
    responseType: input.response_type,
    scope: input.scope,
    nonce: input.nonce,
    state: input.state,
  };

  // Expose PKCE data. https://datatracker.ietf.org/doc/html/rfc7636
  if (input.code_challenge) {
    if (
      input.code_challenge_method != null &&
      !["plain", "S256"].includes(input.code_challenge_method)
    ) {
      return {
        statusCode: 400,
        error: {
          error: "invalid_request",
          error_description: "Unsupported code_challenge_method",
        },
      };
    }

    successResponse.codeChallenge = input.code_challenge;
    successResponse.codeChallengeMethod =
      input.code_challenge_method === "S256" ? "S256" : "plain";
  }

  return successResponse;
}

function renderLoginPage(
  authorizationEndpointPath: string,
  authorizationRequest: AuthorizationRequest,
  errorMessage?: string,
) {
  const escapedErrorMessage = errorMessage
    ? `<p>${escapeHtml(errorMessage)}</p>`
    : "";
  const signupPathSearchParams = new URLSearchParams({
    client_id: authorizationRequest.clientConfig.clientId,
    response_type: authorizationRequest.responseType,
    redirect_uri: authorizationRequest.redirectUri,
  });
  const setIfExists = (
    sourceKey: Exclude<keyof AuthorizationRequest, "clientConfig">,
    targetKey: string,
  ) => {
    if (authorizationRequest[sourceKey]) {
      signupPathSearchParams.set(targetKey, authorizationRequest[sourceKey]);
    }
  };
  setIfExists("state", "state");
  setIfExists("scope", "scope");
  setIfExists("nonce", "nonce");
  setIfExists("codeChallenge", "code_challenge");
  setIfExists("codeChallengeMethod", "code_challenge_method");
  const signupPath = `/signup?${signupPathSearchParams.toString()}`;

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
      <input type="hidden" name="scope" value="${escapeHtml(authorizationRequest.scope ?? "")}">
      <input type="hidden" name="nonce" value="${escapeHtml(authorizationRequest.nonce ?? "")}">
      <input type="hidden" name="state" value="${escapeHtml(authorizationRequest.state ?? "")}">
      <input type="hidden" name="code_challenge" value="${escapeHtml(authorizationRequest.codeChallenge ?? "")}">
      <input type="hidden" name="code_challenge_method" value="${escapeHtml(authorizationRequest.codeChallengeMethod ?? "")}">
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
  authorizationRequest: AuthorizationRequest,
  subject: string,
) {
  const code = randomUUID();
  authorizationCodeStore.saveAuthorizationCode(code, {
    clientId: authorizationRequest.clientConfig.clientId,
    subject,
    redirectUri: authorizationRequest.redirectUri,
    scope: authorizationRequest.scope,
    nonce: authorizationRequest.nonce,
    expiresAt:
      Date.now() + serverConfig.authorizationCodeLifetimeSeconds * 1000,
    codeChallenge: authorizationRequest.codeChallenge,
    codeChallengeMethod: authorizationRequest.codeChallengeMethod,
  });

  const redirectUrl = new URL(authorizationRequest.redirectUri);
  redirectUrl.searchParams.set("code", code);
  if (authorizationRequest.state) {
    redirectUrl.searchParams.set("state", authorizationRequest.state);
  }
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
