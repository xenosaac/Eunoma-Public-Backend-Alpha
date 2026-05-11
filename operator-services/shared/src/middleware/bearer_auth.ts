// Bearer-token auth + in-memory rate limit middleware (Phase 4 W1).
//
// Both hooks are framework-agnostic — they accept FastifyRequest/Reply but only
// use the `headers`, `ip`, `url` shape, so they could be ported to other HTTP
// libraries trivially.

import type { FastifyReply, FastifyRequest } from "fastify";

const BEARER_RE = /^Bearer\s+(.+)$/i;

export interface BearerAuthOptions {
  /** Token the server expects in `Authorization: Bearer <token>`. */
  expectedToken: string;
  /** Paths to skip auth on (e.g. `/v1/health`). Matched as exact-equals. */
  exemptPaths?: string[];
}

export function bearerAuthHook(opts: BearerAuthOptions) {
  if (!opts.expectedToken) {
    throw new Error("bearerAuthHook: expectedToken must be non-empty");
  }
  const exempt = new Set(opts.exemptPaths ?? []);
  return async function bearerAuth(req: FastifyRequest, reply: FastifyReply) {
    // Strip query string for exact-path matching (req.url includes querystring).
    const path = req.url.split("?", 1)[0];
    if (exempt.has(path)) return;
    const header = req.headers.authorization;
    if (!header) {
      reply.code(401).send({ error: "missing_authorization" });
      return reply;
    }
    const m = BEARER_RE.exec(header);
    if (!m) {
      reply.code(401).send({ error: "invalid_authorization_format" });
      return reply;
    }
    if (!timingSafeEqualString(m[1], opts.expectedToken)) {
      reply.code(401).send({ error: "invalid_token" });
      return reply;
    }
  };
}

/** Constant-time string compare to avoid leaking token length / prefix via timing. */
function timingSafeEqualString(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export interface RateLimitOptions {
  /** Maximum requests per IP within the window. */
  maxPerWindow: number;
  /** Window length in milliseconds. */
  windowMs: number;
  /** Paths this limit applies to (exact-equals). Other paths pass through. */
  paths: string[];
}

interface RateBucket {
  count: number;
  windowStart: number;
}

export function rateLimitHook(opts: RateLimitOptions) {
  if (opts.maxPerWindow < 1) throw new Error("rateLimitHook: maxPerWindow must be ≥ 1");
  if (opts.windowMs < 1) throw new Error("rateLimitHook: windowMs must be ≥ 1");
  const target = new Set(opts.paths);
  const hits = new Map<string, RateBucket>();
  return async function rateLimit(req: FastifyRequest, reply: FastifyReply) {
    const path = req.url.split("?", 1)[0];
    if (!target.has(path)) return;
    const ip = req.ip;
    const now = Date.now();
    const bucket = hits.get(ip);
    if (!bucket || now - bucket.windowStart > opts.windowMs) {
      hits.set(ip, { count: 1, windowStart: now });
      return;
    }
    bucket.count++;
    if (bucket.count > opts.maxPerWindow) {
      reply.code(429).send({
        error: "rate_limit_exceeded",
        retry_after_ms: opts.windowMs - (now - bucket.windowStart),
      });
      return reply;
    }
  };
}
