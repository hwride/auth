export function hasScope(
  scope: string | undefined,
  expectedScope: string,
): boolean {
  return scope?.split(/\s+/).includes(expectedScope) ?? false;
}
