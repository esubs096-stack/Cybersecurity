import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { Request, RequestHandler, Response } from "express";
import { config } from "./config";
import { sha256 } from "./ids";
import { prisma } from "./prisma";
import { requestId, sendError } from "./http";
import { sessionCookieName } from "./session";

const anonymousCookieName = config.production
  ? "__Host-vaultshare-csrf"
  : "vaultshare_anon_csrf";
const maxAge = 2 * 60 * 60 * 1000;

export const sessionCsrfToken = (rawSessionId: string) =>
  createHmac("sha256", config.csrfKey).update(rawSessionId).digest("base64url");

function equalToken(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

function setAnonymousCookie(res: Response): string {
  const value = randomBytes(32).toString("base64url");
  res.cookie(anonymousCookieName, value, {
    httpOnly: false,
    secure: config.production,
    sameSite: "lax",
    path: "/",
    maxAge,
  });
  return value;
}

export async function csrfForRequest(req: Request, res: Response): Promise<string> {
  const rawSessionId = req.cookies?.[sessionCookieName];
  if (typeof rawSessionId === "string" && rawSessionId.length >= 40 && rawSessionId.length <= 64) {
    const session = await prisma.session.findUnique({
      where: { tokenHash: sha256(rawSessionId) },
      include: { user: true },
    });
    const now = new Date();
    if (
      session &&
      !session.revokedAt &&
      session.idleExpires > now &&
      session.expiresAt > now &&
      !session.user.deletedAt &&
      session.user.active
    ) {
      return sessionCsrfToken(rawSessionId);
    }
  }
  const existing = req.cookies?.[anonymousCookieName];
  if (typeof existing === "string" && existing.length >= 40 && existing.length <= 64) {
    return existing;
  }
  return setAnonymousCookie(res);
}

function requestHasValidOrigin(req: Request): boolean {
  const origin = req.get("origin");
  const host = req.get("host");
  if (!origin || !host) return false;
  try {
    const parsedOrigin = new URL(origin);
    const expected = `${req.protocol}://${host}`;
    return parsedOrigin.origin === expected;
  } catch {
    return false;
  }
}

export const requireCsrf: RequestHandler = (req, res, next) => {
  void (async () => {
    if (!requestHasValidOrigin(req)) {
      sendError(req, res, 403, "You do not have permission to access this resource.");
      return;
    }
    const supplied = req.get("x-csrf-token");
    const rawSessionId = req.cookies?.[sessionCookieName];
    let expected: string | undefined;
    if (typeof rawSessionId === "string" && rawSessionId.length >= 40 && rawSessionId.length <= 64) {
      const session = await prisma.session.findUnique({
        where: { tokenHash: sha256(rawSessionId) },
        include: { user: true },
      });
      const now = new Date();
      if (
        session &&
        !session.revokedAt &&
        session.idleExpires > now &&
        session.expiresAt > now &&
        !session.user.deletedAt &&
        session.user.active
      ) {
        expected = sessionCsrfToken(rawSessionId);
      }
    }
    if (!expected) {
      const cookieValue = req.cookies?.[anonymousCookieName];
      if (typeof cookieValue === "string") expected = cookieValue;
    }
    if (!supplied || !expected || !equalToken(supplied, expected)) {
      sendError(req, res, 403, "You do not have permission to access this resource.");
      return;
    }
    next();
  })().catch((error: unknown) => {
    req.log?.error({ errorName: error instanceof Error ? error.name : "unknown" }, "CSRF verification failed");
    sendError(req, res, 503, "Unable to verify this request.");
  });
};

export function sendCsrfResponse(req: Request, res: Response, csrfToken: string): void {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Request-Id", requestId(req));
  res.json({ csrfToken });
}
