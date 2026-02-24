import Fastify from "fastify";
import path from "node:path";
import { fileURLToPath } from "node:url";
import view from "@fastify/view";
import ejs from "ejs";
import { randomUUID } from "node:crypto";

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
  const redirectUri = "http://localhost:3000/callback";

  // Authorization Code Grant, Authorization Request - https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
  fastify.get("/authorize", async function (request, reply) {
    const authServerBase = process.env.AUTH_SERVER_BASE;
    const clientId = process.env.CLIENT_ID;

    const authorizeUrl = new URL("/authorize", authServerBase);
    state = randomUUID();
    authorizeUrl.search = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirectUri,
      state,
    }).toString();

    fastify.log.info(
      {
        authorizeUrl,
        ...Object.fromEntries(authorizeUrl.searchParams.entries()),
      },
      "/authorize - Authorization Request - redirecting to Authorization URL...",
    );
    return reply.redirect(authorizeUrl.toString());
  });

  // Authorization Code Grant, Authorization Response - https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2
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
      return reply.code(400).send("Missing code");
    }

    if (!query.state || query.state !== state) {
      return reply.code(400).send("Invalid state");
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
    const tokenResponseBody = await tokenResponse.text();

    if (!tokenResponse.ok) {
      fastify.log.error(
        { status: tokenResponse.status, body: tokenResponseBody },
        "/callback - Access Token Request failed",
      );
      return reply.code(502).send("Token request failed");
    }

    fastify.log.info(
      { status: tokenResponse.status, body: tokenResponseBody },
      "/callback - Access Token Response",
    );

    return reply.code(200).send("Callback received");
  });

  try {
    await fastify.listen({ port: 3000 });
    return fastify;
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}
