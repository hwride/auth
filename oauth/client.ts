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

  // Authorization Code Grant, Authorization Request - https://datatracker.ietf.org/doc/html/rfc6749#autoid-36
  fastify.get("/authorize", async function (request, reply) {
    const authServerBase = process.env.AUTH_SERVER_BASE;
    const clientId = process.env.CLIENT_ID;

    const authorizeUrl = new URL("/authorize", authServerBase);
    state = randomUUID();
    authorizeUrl.search = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: "http://localhost:3000/callback",
      state,
    }).toString();

    fastify.log.info(`Redirecting to Authorization URL ${authorizeUrl}...`);
    return reply.redirect(authorizeUrl.toString());
  });

  // Authorization Code Grant, Authorization Response - https://datatracker.ietf.org/doc/html/rfc6749#autoid-37
  fastify.get<{
    Querystring: {
      code?: string;
      state?: string;
    };
  }>("/callback", async function (request, reply) {
    const query = request.query;
    fastify.log.info({ query }, "Received callback query params");
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
