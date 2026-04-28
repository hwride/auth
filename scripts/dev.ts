import { setTimeout as sleep } from "node:timers/promises";
import {
  defaultAuthorizationServerPort,
  main as startAuthorizationServer,
} from "../authorization-server/server.ts";
import { defaultClientPort, main as startClient } from "../client/client.ts";
import {
  defaultResourceServerPort,
  main as startResourceServer,
} from "../resource-server/resource-server.ts";

async function main() {
  // Auth server
  const authorizationServerPort = Number(
    process.env.AUTH_SERVER_PORT ?? defaultAuthorizationServerPort,
  );
  const authServerBase = `http://localhost:${authorizationServerPort}`;
  process.env.CLIENT_JWT_BASE ??= "http://localhost:3000";
  process.env.CLIENT_OPAQUE_BASE ??= "http://localhost:3001";
  process.env.AUTH_SERVER_PORT = String(authorizationServerPort);
  process.env.ISSUER = authServerBase;

  // Resource server and client
  process.env.AUTH_SERVER_BASE = authServerBase;

  // Resource server
  const resourceServerPort = Number(
    process.env.RESOURCE_SERVER_PORT ?? defaultResourceServerPort,
  );
  process.env.RESOURCE_SERVER_PORT = String(resourceServerPort);
  process.env.DEFAULT_RESOURCE =
    process.env.DEFAULT_RESOURCE ?? "https://orders-api.example.test";

  // Client
  const clientPort = Number(process.env.CLIENT_PORT ?? defaultClientPort);
  process.env.CLIENT_PORT = String(clientPort);
  process.env.CLIENT_ID ??= "client-id-jwt";
  process.env.CLIENT_SECRET ??= "other-test-client-secret";
  process.env.DEFAULT_SCOPES ??= "openid orders:read";

  await startAuthorizationServer();

  await waitForAuthServerDiscovery();

  await startClient();
  await startResourceServer();
}

async function waitForAuthServerDiscovery() {
  const authServerDiscoveryUrl = new URL(
    "/.well-known/openid-configuration",
    process.env.AUTH_SERVER_BASE,
  );
  while (true) {
    try {
      const response = await fetch(authServerDiscoveryUrl);
      if (response.status === 200) {
        return;
      }
    } catch {}

    await sleep(100);
  }
}

await main();
