import { randomBytes } from "node:crypto";
import type { Request, RequestHandler, Response } from "express";
import { config } from "./config";
import { sha256 } from "./ids";
import { prisma } from "./prisma";
import { genericMessages, sendError } from "./http";
import type { VaultUser } from "./types";

const idleMilliseconds = 30 * 60 * 1000;
const absoluteMilliseconds = 12 * 60 * 60 * 1000;

export const sessionCookieName = config.production
  ? "__Host-vaultshare"
  : "vaultshare_session";

function asVaultUser(user: {
  id: string;
  publicId: string;
  name: string;
  email: string;
  role: string;
  emailVerified: boolean;
  twoFactorEnabled: boolean;
}): VaultUser | null {
  if (user.role !== "admin" && user.role !== "user") return null;
  return {
    id: user.id,
    publicId: user.publicId,
    name: user.name,
    email: user.email,
    role: user.role,
    emailVerified: user.emailVerified,
    twoFactorEnabled: user.twoFactorEnabled,
  };
}

export function setSessionCookie(res: Response, rawToken: string): void {
  res.cookie(sessionCookieName, rawToken, {
    httpOnly: true,
    secure: config.production,
    sameSite: "lax",
    path: "/",
    maxAge: absoluteMilliseconds,
  });
}

export function clearSessionCookie(res: Response): void {
  res.clearCookie(sessionCookieName, {
    httpOnly: true,
    secure: config.production,
    sameSite: "lax",
    path: "/",
  });
}

export async function createSession(userId: string, res: Response): Promise<string> {
  const rawToken = randomBytes(32).toString("base64url");
  const now = new Date();
  const expiresAt = new Date(now.getTime() + absoluteMilliseconds);
  await prisma.session.create({
    data: {
      tokenHash: sha256(rawToken),
      userId,
      lastSeenAt: now,
      idleExpires: new Date(Math.min(now.getTime() + idleMilliseconds, expiresAt.getTime())),
      expiresAt,
    },
  });
  setSessionCookie(res, rawToken);
  return rawToken;
}

export async function loadSession(
  req: Request,
  touch = true,
): Promise<{ user: VaultUser; rawToken: string; sessionDbId: string } | null> {
  const rawToken = req.cookies?.[sessionCookieName];
  if (typeof rawToken !== "string" || rawToken.length < 40 || rawToken.length > 64) {
    return null;
  }
  const now = new Date();
  const session = await prisma.session.findUnique({
    where: { tokenHash: sha256(rawToken) },
    include: { user: true },
  });
  if (!session) return null;
  if (
    session.revokedAt ||
    session.idleExpires <= now ||
    session.expiresAt <= now ||
    session.user.deletedAt ||
    !session.user.active
  ) {
    if (!session.revokedAt) {
      await prisma.session.updateMany({
        where: { id: session.id, revokedAt: null },
        data: { revokedAt: now },
      });
    }
    return null;
  }
  const user = asVaultUser(session.user);
  if (!user) return null;
  if (touch) {
    await prisma.session.updateMany({
      where: {
        id: session.id,
        revokedAt: null,
        expiresAt: { gt: now },
        idleExpires: { gt: now },
      },
      data: {
        lastSeenAt: now,
        idleExpires: new Date(Math.min(now.getTime() + idleMilliseconds, session.expiresAt.getTime())),
      },
    });
  }
  return { user, rawToken, sessionDbId: session.id };
}

export async function requireUser(req: Request, res: Response, next: (error?: unknown) => void): Promise<void> {
  try {
    const session = await loadSession(req);
    if (!session) {
      clearSessionCookie(res);
      sendError(req, res, 401, "You do not have permission to access this resource.");
      return;
    }
    req.vaultUser = session.user;
    req.vaultSessionRaw = session.rawToken;
    req.vaultSessionDbId = session.sessionDbId;
    next();
  } catch (error) {
    req.log?.error({ errorName: error instanceof Error ? error.name : "unknown" }, "Session verification failed");
    sendError(req, res, 503, "Unable to verify your session.");
  }
}

export const requireAdmin: RequestHandler = (req, res, next) => {
  if (!req.vaultUser) {
    sendError(req, res, 401, "You do not have permission to access this resource.");
    return;
  }
  if (req.vaultUser.role !== "admin") {
    sendError(req, res, 403, genericMessages.forbidden);
    return;
  }
  next();
};

export async function revokeCurrentSession(req: Request): Promise<void> {
  if (req.vaultSessionDbId) {
    await prisma.session.updateMany({
      where: { id: req.vaultSessionDbId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
  }
}
