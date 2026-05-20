export class HttpError extends Error {
  constructor(
    readonly statusCode: number,
    readonly code: string,
    message = code,
  ) {
    super(message);
    this.name = "HttpError";
  }
}

export function requireBearer(
  authorization: string | undefined,
  expectedToken: string | undefined,
): void {
  if (!expectedToken) return;
  const expected = `Bearer ${expectedToken}`;
  if (authorization !== expected) {
    throw new HttpError(401, "unauthorized");
  }
}
