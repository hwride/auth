import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { jwtVerify } from "jose";
import type { ServerConfig } from "../config/server-config.ts";
import type { UserStore } from "../stores/user-store.ts";

const bearerChallenge = `Bearer realm="userinfo"`;

/**
 * https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
 */
export function registerUserinfoRoute(
  fastify: FastifyInstance,
  serverConfig: ServerConfig,
  userStore: UserStore,
) {
  fastify.get("/userinfo", async function (request, reply) {
    return await handleUserinfoRequest(request, reply, serverConfig, userStore);
  });

  fastify.post("/userinfo", async function (request, reply) {
    return await handleUserinfoRequest(request, reply, serverConfig, userStore);
  });
}

async function handleUserinfoRequest(
  request: FastifyRequest,
  reply: FastifyReply,
  serverConfig: ServerConfig,
  userStore: UserStore,
) {
  const token = extractBearerToken(request.headers.authorization);
  if (!token) {
    return sendBearerChallenge(reply);
  }

  try {
    const { payload } = await jwtVerify(token, serverConfig.publicKey, {
      algorithms: [serverConfig.jwtSigningAlg],
      audience: serverConfig.issuer,
      issuer: serverConfig.issuer,
      requiredClaims: ["sub", "exp"],
      typ: "at+jwt",
    });

    if (typeof payload.sub !== "string" || payload.sub.length === 0) {
      return sendInvalidTokenResponse(reply);
    }

    const user = userStore.loadUser(payload.sub);
    if (user == null) {
      return sendInvalidTokenResponse(reply);
    }

    const response: { sub: string; name?: string } = {
      sub: user.username,
    };

    // https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
    if (hasScope(payload.scope, "profile")) {
      response.name = user.name;
    }

    return reply.code(200).send(response);
  } catch {
    return sendInvalidTokenResponse(reply);
  }
}

function extractBearerToken(
  authorizationHeader: string | undefined,
): string | undefined {
  if (!authorizationHeader) {
    return undefined;
  }

  const [scheme, token, extra] = authorizationHeader.trim().split(/\s+/);
  if (scheme !== "Bearer" || !token || extra != null) {
    return undefined;
  }

  return token;
}

function sendBearerChallenge(reply: FastifyReply) {
  return reply.header("WWW-Authenticate", bearerChallenge).code(401).send();
}

function sendInvalidTokenResponse(reply: FastifyReply) {
  return reply
    .header("WWW-Authenticate", `${bearerChallenge}, error="invalid_token"`)
    .code(401)
    .send({
      error: "invalid_token",
    });
}

function hasScope(scope: unknown, expectedScope: string) {
  return (
    typeof scope === "string" && scope.split(/\s+/).includes(expectedScope)
  );
}
