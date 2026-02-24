export function decodeJwtPayload(token: string): unknown | undefined {
  const tokenParts = token.split(".");
  if (tokenParts.length < 2) {
    return undefined;
  }

  try {
    const payloadJson = Buffer.from(tokenParts[1], "base64url").toString(
      "utf8",
    );
    return JSON.parse(payloadJson);
  } catch {
    return undefined;
  }
}
