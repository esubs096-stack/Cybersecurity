import { hash, verify } from "@node-rs/argon2";
import type { AuthState } from "@workspace/api-zod";
import { Prisma } from "@prisma/client";
import { zxcvbn, zxcvbnOptions } from "@zxcvbn-ts/core";
import languageCommon from "@zxcvbn-ts/language-common";
import { Router, type IRouter } from "express";
import { setTimeout as sleep } from "node:timers/promises";
import { z } from "zod";
import { appendAudit } from "../lib/vaultshare/audit";
import { csrfForRequest, requireCsrf, sendCsrfResponse, sessionCsrfToken } from "../lib/vaultshare/csrf";
import { genericMessages, asyncRoute, sendError } from "../lib/vaultshare/http";
import { prisma } from "../lib/vaultshare/prisma";
import { getClientIp, consumeRateLimit, isRateLimited, clearRateLimit } from "../lib/vaultshare/rate-limit";
import {
  clearSessionCookie,
  createSession,
  loadSession,
  requireUser,
  revokeCurrentSession,
} from "../lib/vaultshare/session";
import { publicId, sha256, randomToken } from "../lib/vaultshare/ids";

const router: IRouter = Router();

const argonOptions = {
  memoryCost: 19_456,
  timeCost: 2,
  parallelism: 1,
};
const dummyHashPromise = hash(randomToken(), argonOptions);
const commonPasswordSet = new Set(languageCommon.dictionary.passwords.map((entry) => String(entry).toLowerCase()));
zxcvbnOptions.setOptions({
  dictionary: languageCommon.dictionary,
  graphs: languageCommon.adjacencyGraphs,
});

const registrationInput = z.object({
  name: z.string().trim().min(1).max(80).refine((value) => !/[\u0000-\u001f\u007f]/.test(value)),
  email: z.string().trim().email().max(254).transform((value) => value.toLowerCase()),
  password: z.string().min(12).max(128),
}).strict();
const loginInput = z.object({
  email: z.string().trim().email().max(254).transform((value) => value.toLowerCase()),
  password: z.string().min(1).max(128),
}).strict();

type PublicAuthUser = Exclude<AuthState["user"], null>;

function authUser(user: {
  publicId: string;
  name: string;
  email: string;
  role: string;
  emailVerified: boolean;
  twoFactorEnabled: boolean;
}): PublicAuthUser {
  if (user.role !== "admin" && user.role !== "user") {
    throw new Error("Stored user role is invalid.");
  }
  return {
    id: user.publicId,
    name: user.name,
    email: user.email,
    role: user.role,
    emailVerified: user.emailVerified,
    twoFactorEnabled: user.twoFactorEnabled,
  };
}

function validPasswordStrength(password: string, name: string, email: string): boolean {
  if (commonPasswordSet.has(password.toLowerCase())) return false;
  const result = zxcvbn(password, [name, email, email.split("@")[0] ?? ""]);
  return result.score >= 3;
}

function authState(user: PublicAuthUser | null, csrfToken: string): AuthState {
  return { user, csrfToken };
}

router.get(
  "/auth/csrf",
  asyncRoute(async (req, res) => {
    sendCsrfResponse(req, res, await csrfForRequest(req, res));
  }),
);

router.get(
  "/auth/me",
  asyncRoute(async (req, res) => {
    const session = await loadSession(req);
    if (!session) clearSessionCookie(res);
    const csrfToken = await csrfForRequest(req, res);
    res.setHeader("Cache-Control", "no-store");
    res.json(authState(session ? authUser(session.user) : null, csrfToken));
  }),
);

router.post(
  "/auth/register",
  requireCsrf,
  asyncRoute(async (req, res) => {
    const parsed = registrationInput.safeParse(req.body);
    if (!parsed.success) {
      sendError(req, res, 400, "Invalid request.");
      return;
    }
    const { name, email, password } = parsed.data;
    if (!validPasswordStrength(password, name, email)) {
      sendError(req, res, 400, "Choose a stronger password that is not commonly used.");
      return;
    }

    const clientIp = getClientIp(req);
    const registrationLimit = await consumeRateLimit({
      scope: "register-ip",
      key: clientIp,
      limit: 10,
      windowMs: 60 * 60 * 1000,
      lockMs: 60 * 60 * 1000,
    });
    if (!registrationLimit.allowed) {
      sendError(req, res, 429, genericMessages.tooManyAttempts);
      return;
    }

    const startedAt = Date.now();
    const passwordHash = await hash(password, argonOptions);
    let createdPublicId: string | null = null;
    try {
      const user = await prisma.user.create({
        data: { publicId: publicId(), name, email, passwordHash, role: "user" },
      });
      createdPublicId = user.publicId;
    } catch (error) {
      if (!(error instanceof Prisma.PrismaClientKnownRequestError) || error.code !== "P2002") {
        throw error;
      }
    }

    await appendAudit({
      actorPublicId: createdPublicId,
      action: "REGISTER",
      ip: clientIp,
      userAgent: req.get("user-agent"),
      result: "SUCCESS",
      reason: "Registration request processed.",
    });

    // Give both new and already-used addresses the same response and a similar
    // minimum processing time. Registration never creates an authenticated session.
    const minimumMs = 250;
    const remainingMs = minimumMs - (Date.now() - startedAt);
    if (remainingMs > 0) await sleep(remainingMs);
    res.setHeader("Cache-Control", "no-store");
    res.status(201).json(authState(null, await csrfForRequest(req, res)));
  }),
);

router.post(
  "/auth/login",
  requireCsrf,
  asyncRoute(async (req, res) => {
    const parsed = loginInput.safeParse(req.body);
    if (!parsed.success) {
      sendError(req, res, 401, genericMessages.invalidCredentials);
      return;
    }
    const { email, password } = parsed.data;
    const clientIp = getClientIp(req);
    const rateKey = email;
    const emailLimited = await isRateLimited({ scope: "login-email", key: rateKey });
    const ipLimited = await isRateLimited({ scope: "login-ip", key: clientIp });
    if (emailLimited || ipLimited) {
      sendError(req, res, 429, genericMessages.tooManyAttempts);
      return;
    }

    const candidate = await prisma.user.findUnique({ where: { email } });
    const eligible =
      !!candidate &&
      candidate.active &&
      !candidate.deletedAt &&
      (candidate.role === "admin" || candidate.role === "user");
    let passwordMatches = false;
    try {
      passwordMatches = await verify(
        eligible ? candidate.passwordHash : await dummyHashPromise,
        password,
      );
    } catch {
      passwordMatches = false;
    }

    if (eligible && candidate && passwordMatches) {
      const rawSession = await createSession(candidate.id, res);
      try {
        await appendAudit({
          actorPublicId: candidate.publicId,
          action: "LOGIN",
          ip: clientIp,
          userAgent: req.get("user-agent"),
          result: "SUCCESS",
          reason: "Password authentication succeeded.",
        });
      } catch (error) {
        await prisma.session.updateMany({
          where: { tokenHash: sha256(rawSession), revokedAt: null },
          data: { revokedAt: new Date() },
        });
        clearSessionCookie(res);
        throw error;
      }
      await prisma.user.update({
        where: { id: candidate.id },
        data: { failedLoginCount: 0, lockedUntil: null },
      });
      await clearRateLimit({ scope: "login-email", key: rateKey });
      res.setHeader("Cache-Control", "no-store");
      res.json(authState(authUser(candidate), sessionCsrfToken(rawSession)));
      return;
    }

    const [emailResult, ipResult] = await Promise.all([
      consumeRateLimit({
        scope: "login-email",
        key: rateKey,
        limit: 5,
        windowMs: 15 * 60 * 1000,
        lockMs: 15 * 60 * 1000,
      }),
      consumeRateLimit({
        scope: "login-ip",
        key: clientIp,
        limit: 30,
        windowMs: 15 * 60 * 1000,
        lockMs: 15 * 60 * 1000,
      }),
    ]);

    if (eligible && candidate) {
      const updated = await prisma.user.update({
        where: { id: candidate.id },
        data: {
          failedLoginCount: { increment: 1 },
          ...(emailResult.blockedUntil ? { lockedUntil: emailResult.blockedUntil } : {}),
        },
      });
      if (updated.failedLoginCount >= 5 && !emailResult.blockedUntil) {
        await prisma.user.update({
          where: { id: candidate.id },
          data: { lockedUntil: new Date(Date.now() + 15 * 60 * 1000) },
        });
      }
    }

    await appendAudit({
      actorPublicId: candidate?.publicId ?? null,
      action: emailResult.blockedUntil || ipResult.blockedUntil ? "ACCOUNT_LOCKED" : "LOGIN_FAILED",
      ip: clientIp,
      userAgent: req.get("user-agent"),
      result: "FAILED",
      reason: "Invalid credentials or authentication rate limit.",
    });

    if (!emailResult.allowed || !ipResult.allowed) {
      sendError(req, res, 429, genericMessages.tooManyAttempts);
      return;
    }
    const delayMs = Math.min(4_000, 200 * 2 ** Math.max(0, emailResult.count - 1));
    await sleep(delayMs);
    sendError(req, res, 401, genericMessages.invalidCredentials);
  }),
);

router.post(
  "/auth/logout",
  requireCsrf,
  requireUser,
  asyncRoute(async (req, res) => {
    await revokeCurrentSession(req);
    clearSessionCookie(res);
    await appendAudit({
      actorPublicId: req.vaultUser?.publicId,
      action: "LOGOUT",
      ip: getClientIp(req),
      userAgent: req.get("user-agent"),
      result: "SUCCESS",
      reason: "Current session revoked.",
    });
    res.setHeader("Cache-Control", "no-store");
    res.json({ message: "Signed out." });
  }),
);

export default router;
