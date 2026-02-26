import Fastify from "fastify";
import path from "node:path";
import { fileURLToPath } from "node:url";
import view from "@fastify/view";
import ejs from "ejs";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { decodeJwtPayload } from "./utils/jwt-utils.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

main();

async function main() {
  const fastify = await initServer();
  fastify.log.info("Client is booted");
}

async function initServer() {
  const fastify = Fastify({
    logger: {
      transport: {
        target: "pino-pretty",
        options: {
          translateTime: "HH:MM:ss Z",
          ignore: "pid,hostname",
        },
      },
    },
    disableRequestLogging: true,
  });

  await fastify.register(view, {
    engine: {
      ejs,
    },
    root: path.join(__dirname, "templates"),
  });

  fastify.get("/", async function (request, reply) {
    return reply.view("index.ejs");
  });

  let state: string | undefined;
  let codeVerifier: string | undefined;
  const redirectUri = "http://localhost:3000/callback";

  // OAuth, Authorization Code Grant, Authorization Request - https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
  // OIDC, Authorization Code Flow, Authentication Request - https://openid.net/specs/openid-connect-core-1_0-final.html#AuthRequest
  fastify.get<{
    Querystring: {
      scope?: string;
      use_pkce?: "true" | "false";
      use_state?: "true" | "false";
    };
  }>("/authorize", async function (request, reply) {
    const authServerBase = process.env.AUTH_SERVER_BASE;
    const clientId = process.env.CLIENT_ID;
    const { scope, use_pkce, use_state } = request.query;

    const authorizeUrl = new URL("/authorize", authServerBase);
    const authorizeQueryParams: Record<string, string> = {
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirectUri,
    };

    if (use_state === "true") {
      state = randomUUID();
      authorizeQueryParams.state = state;
    } else {
      state = undefined;
    }

    if (use_pkce === "true") {
      // PKCE, Client Creates a Code Verifier - https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
      codeVerifier = randomBytes(32).toString("base64url");
      // PKCE, Client Creates a Code Challenge - https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
      authorizeQueryParams.code_challenge_method = "S256";
      authorizeQueryParams.code_challenge = createHash("sha256")
        .update(codeVerifier)
        .digest("base64url");
    } else {
      codeVerifier = undefined;
    }

    if (scope) {
      authorizeQueryParams.scope = scope.trim();
    }

    authorizeUrl.search = new URLSearchParams(authorizeQueryParams).toString();

    fastify.log.info(
      {
        authorizeUrl,
        ...Object.fromEntries(authorizeUrl.searchParams.entries()),
      },
      "/authorize - Authorization Request - redirecting to Authorization URL...",
    );
    return reply.redirect(authorizeUrl.toString());
  });

  // OAuth, Authorization Code Grant, Authorization Response - https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2
  // OIDC, Authorization Code Grant, Successful Authentication Response - https://openid.net/specs/openid-connect-core-1_0-final.html#AuthResponse
  fastify.get<{
    Querystring: {
      code?: string;
      state?: string;
    };
  }>("/callback", async function (request, reply) {
    const query = request.query;
    fastify.log.info({ query }, "/callback - Authorization Response");

    // Access Token Request - https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
    const authServerBase = process.env.AUTH_SERVER_BASE;
    const clientId = process.env.CLIENT_ID;
    const clientSecret = process.env.CLIENT_SECRET;

    if (!query.code) {
      return reply.code(400).view("callback.ejs", {
        callbackTitle: "Callback failed",
        errorMessage: "Missing code",
        tokenResponseJson: undefined,
        idTokenClaimsJson: undefined,
      });
    }

    if (state && (!query.state || query.state !== state)) {
      return reply.code(400).view("callback.ejs", {
        callbackTitle: "Callback failed",
        errorMessage: "Invalid state",
        tokenResponseJson: undefined,
        idTokenClaimsJson: undefined,
      });
    }

    const tokenUrl = new URL("/oauth/token", authServerBase);
    const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString(
      "base64",
    );
    const tokenRequestBody = new URLSearchParams({
      grant_type: "authorization_code",
      code: query.code,
      redirect_uri: redirectUri,
    });
    if (codeVerifier) {
      tokenRequestBody.set("code_verifier", codeVerifier);
    }

    fastify.log.info(
      { url: tokenUrl, body: tokenRequestBody.toString() },
      "/callback - Access Token Request",
    );
    const tokenResponse = await fetch(tokenUrl.toString(), {
      method: "POST",
      headers: {
        authorization: `Basic ${basicAuth}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: tokenRequestBody.toString(),
    });

    if (!tokenResponse.ok) {
      const tokenResponseBody = await tokenResponse.text();
      let formattedErrorResponseBody = tokenResponseBody;
      try {
        formattedErrorResponseBody = JSON.stringify(
          JSON.parse(tokenResponseBody),
          null,
          2,
        );
      } catch {
        // Keep raw body when response is not JSON.
      }
      fastify.log.error(
        { status: tokenResponse.status, body: tokenResponseBody },
        "/callback - Access Token Request failed",
      );
      return reply.code(502).view("callback.ejs", {
        callbackTitle: "Callback failed",
        errorMessage: "Token request failed",
        tokenResponseJson: formattedErrorResponseBody,
        idTokenClaimsJson: undefined,
      });
    }

    const tokenResponseBody = (await tokenResponse.json()) as Record<
      string,
      unknown
    >;
    const idTokenClaims =
      typeof tokenResponseBody.id_token === "string"
        ? decodeJwtPayload(tokenResponseBody.id_token)
        : undefined;
    const tokenResponseForDisplay = {
      ...tokenResponseBody,
      ...(tokenResponseBody.access_token
        ? { access_token: "<present-but-redacted>" }
        : {}),
    };

    fastify.log.info(
      { status: tokenResponse.status, body: tokenResponseBody },
      "/callback - Access Token Response",
    );

    return reply.view("callback.ejs", {
      callbackTitle: "Callback success",
      errorMessage: undefined,
      tokenResponseJson: JSON.stringify(tokenResponseForDisplay, null, 2),
      idTokenClaimsJson: idTokenClaims
        ? JSON.stringify(idTokenClaims, null, 2)
        : undefined,
    });
  });

  try {
    await fastify.listen({ port: 3000 });
    return fastify;
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}
