import { createHmac, timingSafeEqual } from "node:crypto";
import { open, readFile, rename, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { Prisma } from "@prisma/client";
import { config } from "./config";
import { prisma } from "./prisma";

export type AuditAction =
  | "REGISTER"
  | "LOGIN"
  | "LOGOUT"
  | "LOGIN_FAILED"
  | "ACCOUNT_LOCKED"
  | "PASSWORD_CHANGED"
  | "TWO_FA_ENABLED"
  | "TWO_FA_DISABLED"
  | "SESSION_REVOKED"
  | "UPLOAD"
  | "DOCUMENT_ENCRYPTED"
  | "DOCUMENT_VIEW"
  | "DOCUMENT_DOWNLOAD"
  | "DOCUMENT_DELETE"
  | "SHARE_CREATED"
  | "SHARE_ACCESS"
  | "SHARE_EXPIRED"
  | "PERMISSION_CHANGED"
  | "ACCESS_REVOKED"
  | "REVOKE_ALL"
  | "SHARE_PASSWORD_FAILED"
  | "SHARE_PASSWORD_OK"
  | "ACCESS_DENIED"
  | "ACCESS_AFTER_REVOCATION"
  | "ACCESS_AFTER_EXPIRY"
  | "COMMENT_ADDED"
  | "SUSPICIOUS_ACTIVITY"
  | "ALERT_STATUS_CHANGED"
  | "ACCOUNT_DISABLED"
  | "ACCOUNT_ENABLED"
  | "POLICY_CHANGED"
  | "INTEGRITY_VERIFIED"
  | "SECURITY_SELF_TEST_RUN"
  | "DEMO_TAMPER_SIMULATED"
  | "DEMO_RESET";

export type AuditInput = {
  actorPublicId?: string | null;
  documentPublicId?: string | null;
  sharePublicId?: string | null;
  action: AuditAction;
  ip?: string | null;
  userAgent?: string | null;
  result: "SUCCESS" | "FAILED";
  reason?: string | null;
};

type CanonicalEvent = {
  seq: number;
  timestamp: string;
  actor_public_id: string | null;
  document_public_id: string | null;
  share_public_id: string | null;
  action: string;
  ip: string | null;
  user_agent: string | null;
  result: string;
  reason: string | null;
};

const genesisHash = "0".repeat(64);
let appendQueue: Promise<void> = Promise.resolve();

function canonicalJson(event: CanonicalEvent): string {
  return JSON.stringify({
    seq: event.seq,
    timestamp: event.timestamp,
    actor_public_id: event.actor_public_id,
    document_public_id: event.document_public_id,
    share_public_id: event.share_public_id,
    action: event.action,
    ip: event.ip,
    user_agent: event.user_agent,
    result: event.result,
    reason: event.reason,
  });
}

function hashEvent(event: CanonicalEvent, previousHash: string): string {
  return createHmac("sha256", config.auditHmacKey)
    .update(`${canonicalJson(event)}|${previousHash}`)
    .digest("hex");
}

function checkpointSignature(seq: number, head: string): string {
  return createHmac("sha256", config.auditHmacKey)
    .update(`${seq}|${head}`)
    .digest("hex");
}

function safeText(value: string | null | undefined, maximum: number): string | null {
  if (value == null) return null;
  return value
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/\b[A-Za-z0-9_-]{32,}\b/g, "[REDACTED]")
    .slice(0, maximum);
}

function toCanonical(row: {
  seq: number;
  timestamp: Date;
  actorPublicId: string | null;
  documentPublicId: string | null;
  sharePublicId: string | null;
  action: string;
  ip: string | null;
  userAgent: string | null;
  result: string;
  reason: string | null;
}): CanonicalEvent {
  return {
    seq: row.seq,
    timestamp: row.timestamp.toISOString(),
    actor_public_id: row.actorPublicId,
    document_public_id: row.documentPublicId,
    share_public_id: row.sharePublicId,
    action: row.action,
    ip: row.ip,
    user_agent: row.userAgent,
    result: row.result,
    reason: row.reason,
  };
}

async function writeCheckpoint(seq: number, head: string): Promise<void> {
  const payload = JSON.stringify({ seq, head, signature: checkpointSignature(seq, head) });
  const temporaryPath = `${config.checkpointPath}.${process.pid}.tmp`;
  const handle = await open(temporaryPath, "w", 0o600);
  try {
    await handle.writeFile(payload, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  await rename(temporaryPath, config.checkpointPath);
}

async function serializedCheckpointWrite(seq: number, head: string): Promise<void> {
  const before = appendQueue;
  let release!: () => void;
  appendQueue = new Promise<void>((resolve) => {
    release = resolve;
  });
  await before;
  try {
    const current = await readCheckpoint().catch(() => null);
    if (!current || seq >= current.seq) await writeCheckpoint(seq, head);
  } finally {
    release();
  }
}

async function readCheckpoint(): Promise<{ seq: number; head: string; signature: string }> {
  const text = await readFile(config.checkpointPath, "utf8");
  const parsed: unknown = JSON.parse(text);
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    !("seq" in parsed) ||
    !("head" in parsed) ||
    !("signature" in parsed) ||
    typeof parsed.seq !== "number" ||
    typeof parsed.head !== "string" ||
    typeof parsed.signature !== "string"
  ) {
    throw new Error("Invalid checkpoint format");
  }
  return { seq: parsed.seq, head: parsed.head, signature: parsed.signature };
}

export async function appendAudit(input: AuditInput): Promise<{ seq: number; eventHash: string }> {
  const data = {
    actorPublicId: input.actorPublicId ?? null,
    documentPublicId: input.documentPublicId ?? null,
    sharePublicId: input.sharePublicId ?? null,
    action: input.action,
    ip: safeText(input.ip, 128),
    userAgent: safeText(input.userAgent, 512),
    result: input.result,
    reason: safeText(input.reason, 200),
  };
  let inserted: { seq: number; timestamp: Date; eventHash: string } | undefined;

  for (let attempt = 0; attempt < 5; attempt += 1) {
    try {
      inserted = await prisma.$transaction(async (tx) => {
        const last = await tx.auditLog.findFirst({ orderBy: { seq: "desc" } });
        const seq = (last?.seq ?? 0) + 1;
        const timestamp = new Date();
        const event: CanonicalEvent = {
          seq,
          timestamp: timestamp.toISOString(),
          actor_public_id: data.actorPublicId,
          document_public_id: data.documentPublicId,
          share_public_id: data.sharePublicId,
          action: data.action,
          ip: data.ip,
          user_agent: data.userAgent,
          result: data.result,
          reason: data.reason,
        };
        const eventHash = hashEvent(event, last?.eventHash ?? genesisHash);
        await tx.auditLog.create({
          data: {
            seq,
            timestamp,
            ...data,
            prevHash: last?.eventHash ?? genesisHash,
            eventHash,
          },
        });
        return { seq, timestamp, eventHash };
      });
      break;
    } catch (error) {
      const code =
        error instanceof Prisma.PrismaClientKnownRequestError ? error.code : "";
      if (!["P2002", "P2034", "P1008"].includes(code) || attempt === 4) throw error;
      await sleep(15 * (attempt + 1));
    }
  }

  if (!inserted) throw new Error("Audit append could not be committed.");
  await serializedCheckpointWrite(inserted.seq, inserted.eventHash);
  return { seq: inserted.seq, eventHash: inserted.eventHash };
}

export type IntegrityReport = {
  valid: boolean;
  checkedAt: string;
  firstBrokenSeq: number | null;
  expectedHash: string | null;
  actualHash: string | null;
  head: string;
  message: string;
  limit: string;
};

function constantTimeHexEqual(expected: string, actual: string): boolean {
  if (!/^[a-f0-9]{64}$/.test(expected) || !/^[a-f0-9]{64}$/.test(actual)) return false;
  return timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(actual, "hex"));
}

export async function verifyAudit(): Promise<IntegrityReport> {
  const rows = await prisma.auditLog.findMany({ orderBy: { seq: "asc" } });
  let previousHash = genesisHash;
  let firstBrokenSeq: number | null = null;
  let expectedHash: string | null = null;
  let actualHash: string | null = null;

  for (let index = 0; index < rows.length; index += 1) {
    const row = rows[index];
    const expectedSeq = index + 1;
    const canonical = toCanonical(row);
    const computedHash = hashEvent(canonical, previousHash);
    if (
      row.seq !== expectedSeq ||
      row.prevHash !== previousHash ||
      !constantTimeHexEqual(computedHash, row.eventHash)
    ) {
      firstBrokenSeq = row.seq !== expectedSeq ? expectedSeq : row.seq;
      expectedHash = row.prevHash !== previousHash ? previousHash : computedHash;
      actualHash = row.eventHash;
      break;
    }
    previousHash = row.eventHash;
  }

  let checkpoint: { seq: number; head: string; signature: string } | null = null;
  try {
    checkpoint = await readCheckpoint();
  } catch {
    if (rows.length > 0 && firstBrokenSeq === null) {
      firstBrokenSeq = rows.length + 1;
      expectedHash = "valid external checkpoint";
      actualHash = "missing or unreadable checkpoint";
    }
  }

  if (checkpoint && firstBrokenSeq === null) {
    const signature = checkpointSignature(checkpoint.seq, checkpoint.head);
    if (!constantTimeHexEqual(signature, checkpoint.signature)) {
      firstBrokenSeq = checkpoint.seq;
      expectedHash = signature;
      actualHash = checkpoint.signature;
    } else if (checkpoint.seq !== rows.length) {
      firstBrokenSeq = Math.min(checkpoint.seq, rows.length) + 1;
      expectedHash = checkpoint.head;
      actualHash = previousHash;
    } else if (checkpoint.head !== previousHash) {
      firstBrokenSeq = rows.length || 1;
      expectedHash = checkpoint.head;
      actualHash = previousHash;
    }
  }

  const valid = firstBrokenSeq === null;
  return {
    valid,
    checkedAt: new Date().toISOString(),
    firstBrokenSeq,
    expectedHash,
    actualHash,
    head: previousHash,
    message: valid ? "✓ Audit log integrity verified" : "⚠ Audit log tampering detected",
    limit:
      "An attacker with simultaneous control of the database, checkpoint filesystem, and HMAC keys can forge the chain. External anchoring is required to mitigate that risk.",
  };
}

export async function removeCheckpointForDemoReset(): Promise<void> {
  await unlink(config.checkpointPath).catch(() => undefined);
  await writeCheckpoint(0, genesisHash);
}

export function auditCheckpointPathForDiagnostics(): string {
  return path.basename(config.checkpointPath);
}
