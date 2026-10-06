import { createHmac, randomBytes } from "node:crypto";
import type { Request } from "express";
import { Prisma } from "@prisma/client";
import { config } from "./config";
import { prisma } from "./prisma";

export function getClientIp(req: Request): string {
  if (config.trustedProxyCount > 0 && req.ip) return req.ip;
  return req.socket.remoteAddress ?? "unknown";
}

function hashLimitKey(value: string): string {
  return createHmac("sha256", config.csrfKey).update(value).digest("hex");
}

export async function isRateLimited(input: {
  scope: string;
  key: string;
}): Promise<boolean> {
  const keyHash = hashLimitKey(`${input.scope}\0${input.key}`);
  const bucket = await prisma.rateLimitBucket.findUnique({
    where: { keyHash },
    select: { blockedUntil: true },
  });
  return !!bucket?.blockedUntil && bucket.blockedUntil > new Date();
}

export async function clearRateLimit(input: {
  scope: string;
  key: string;
}): Promise<void> {
  const keyHash = hashLimitKey(`${input.scope}\0${input.key}`);
  await prisma.rateLimitBucket.deleteMany({ where: { keyHash } });
}

export async function consumeRateLimit(input: {
  scope: string;
  key: string;
  limit: number;
  windowMs: number;
  lockMs: number;
}): Promise<{ allowed: boolean; count: number; blockedUntil: Date | null }> {
  const now = new Date();
  const cutoff = new Date(now.getTime() - input.windowMs);
  const lockedUntil = new Date(now.getTime() + input.lockMs);
  const keyHash = hashLimitKey(`${input.scope}\0${input.key}`);
  const rows = await prisma.$queryRaw<Array<{ count: number; blockedUntil: Date | null }>>(
    Prisma.sql`INSERT INTO "RateLimitBucket" ("id", "keyHash", "count", "windowStarted", "updatedAt")
      VALUES (${randomBytes(16).toString("hex")}, ${keyHash}, 1, ${now}, ${now})
      ON CONFLICT ("keyHash") DO UPDATE SET
        "count" = CASE
          WHEN "windowStarted" <= ${cutoff} OR ("blockedUntil" IS NOT NULL AND "blockedUntil" <= ${now}) THEN 1
          ELSE "count" + 1
        END,
        "windowStarted" = CASE
          WHEN "windowStarted" <= ${cutoff} OR ("blockedUntil" IS NOT NULL AND "blockedUntil" <= ${now}) THEN ${now}
          ELSE "windowStarted"
        END,
        "blockedUntil" = CASE
          WHEN "windowStarted" <= ${cutoff} OR ("blockedUntil" IS NOT NULL AND "blockedUntil" <= ${now}) THEN NULL
          WHEN "blockedUntil" IS NOT NULL THEN "blockedUntil"
          WHEN "count" + 1 >= ${input.limit} THEN ${lockedUntil}
          ELSE NULL
        END,
        "updatedAt" = ${now}
      RETURNING "count", "blockedUntil"`,
  );
  const row = rows[0];
  if (!row) return { allowed: false, count: input.limit, blockedUntil: lockedUntil };
  const blockedUntil = row.blockedUntil ? new Date(row.blockedUntil) : null;
  return {
    allowed: !blockedUntil || blockedUntil <= now,
    count: Number(row.count),
    blockedUntil,
  };
}
