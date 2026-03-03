import {
  createRemoteJWKSet,
  jwtVerify,
  type JWTPayload,
  type JWTHeaderParameters,
} from "jose";

const jwksByUri = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

export type VerifyJwtWithJoseResult = {
  payload: JWTPayload;
  protectedHeader: JWTHeaderParameters;
};

export async function verifyJwtWithJose(
  token: string,
  jwksUri: string,
): Promise<VerifyJwtWithJoseResult> {
  const jwks = getRemoteJwks(jwksUri);
  const { payload, protectedHeader } = await jwtVerify(token, jwks);
  return { payload, protectedHeader };
}

function getRemoteJwks(jwksUri: string): ReturnType<typeof createRemoteJWKSet> {
  let remoteJwks = jwksByUri.get(jwksUri);
  if (!remoteJwks) {
    remoteJwks = createRemoteJWKSet(new URL(jwksUri));
    jwksByUri.set(jwksUri, remoteJwks);
  }
  return remoteJwks;
}
