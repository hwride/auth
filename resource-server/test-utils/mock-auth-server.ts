import Fastify from "fastify";
import { exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";

export async function createMockAuthServer(
  options: MockAuthServerOptions = {},
): Promise<MockAuthServer> {
  const kid = "test-key-id";
  const signingAlg = options.signingAlg ?? "RS256";
  const keyPair = await generateKeyPair(signingAlg);
  const publicJwk = (await exportJWK(keyPair.publicKey)) as JWK;
  publicJwk.kid = kid;
  publicJwk.use = "sig";
  publicJwk.alg = signingAlg;

  let issuer = "";
  const mockAuthServer = Fastify();
  mockAuthServer.get("/.well-known/openid-configuration", async () => ({
    issuer,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
  }));
  mockAuthServer.get("/.well-known/jwks.json", async () => ({
    keys: [publicJwk],
  }));

  issuer = await mockAuthServer.listen({ host: "127.0.0.1", port: 0 });

  return {
    authServerBase: issuer,
    createAccessToken: async (payload) => {
      const now = Math.floor(Date.now() / 1000);

      return await new SignJWT({
        sub: payload.sub,
        scope: payload.scope,
      })
        .setProtectedHeader({ alg: signingAlg, kid })
        .setIssuer(payload.iss ?? issuer)
        .setIssuedAt(now)
        .setNotBefore(payload.nbf ?? now - 5)
        .setExpirationTime(payload.exp ?? now + 60)
        .sign(keyPair.privateKey);
    },
    issuer,
    jwksUri: `${issuer}/.well-known/jwks.json`,
    close: async () => {
      await mockAuthServer.close();
    },
  };
}

export type MockAuthServer = {
  authServerBase: string;
  createAccessToken: (payload: AccessTokenPayload) => Promise<string>;
  issuer: string;
  jwksUri: string;
  close: () => Promise<void>;
};

type MockAuthServerOptions = {
  signingAlg?: string;
};

type AccessTokenPayload = {
  iss?: string;
  sub?: string;
  scope?: string;
  exp?: number;
  nbf?: number;
};
