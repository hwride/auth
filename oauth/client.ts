import Fastify from "fastify";
import path from "node:path";
import { fileURLToPath } from "node:url";
import view from "@fastify/view";
import ejs from "ejs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

main();

async function main() {
  const fastify = await initServer();
  fastify.log.info("Client is booted");
}

async function initServer() {
  const fastify = Fastify({
    logger: true,
  });

  await fastify.register(view, {
    engine: {
      ejs,
    },
    root: path.join(__dirname, "templates"),
  });

  fastify.get("/", async function handler(request, reply) {
    return reply.view("index.ejs", { message: "Hello world" });
  });

  try {
    await fastify.listen({ port: 3000 });
    return fastify;
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}
