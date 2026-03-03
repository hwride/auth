import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

const jwksByUri = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

export async function verifyJwtWithJose(
  token: string,
  jwksUri: string,
): Promise<JWTPayload> {
  const jwks = getRemoteJwks(jwksUri);
  const { payload } = await jwtVerify(token, jwks);
  return payload;
}

function getRemoteJwks(jwksUri: string): ReturnType<typeof createRemoteJWKSet> {
  let remoteJwks = jwksByUri.get(jwksUri);
  if (!remoteJwks) {
    remoteJwks = createRemoteJWKSet(new URL(jwksUri));
    jwksByUri.set(jwksUri, remoteJwks);
  }
  return remoteJwks;
}
