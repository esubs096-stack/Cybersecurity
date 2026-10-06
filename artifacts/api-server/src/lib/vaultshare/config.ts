import { createHash, hkdfSync } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, realpathSync } from "node:fs";
import path from "node:path";
import dotenv from "dotenv";
import { z } from "zod";

const envCandidates = [
  path.resolve(process.cwd(), ".env"),
  path.resolve(process.cwd(), "../../.env"),
];
const envPath = envCandidates.find(existsSync);
dotenv.config(envPath ? { path: envPath } : undefined);

const keyValue = z.string().superRefine((value, ctx) => {
  try {
    if (/^(replace|change|placeholder)/i.test(value)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "placeholder" });
      return;
    }
    const decoded = Buffer.from(value, "base64");
    if (decoded.length !== 32 || decoded.toString("base64") !== value) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "invalid key" });
    }
  } catch {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: "invalid key" });
  }
});

const rawSchema = z.object({
  MASTER_KEY: keyValue,
  AUDIT_HMAC_KEY: keyValue,
  CSRF_SECRET: keyValue,
  STORAGE_DIR: z.string().min(1),
  AUDIT_CHECKPOINT_PATH: z.string().min(1),
  VAULTSHARE_DATABASE_URL: z.string().min(1),
  DEMO_MODE: z.enum(["true", "false"]).default("false"),
  DEMO_PASSWORD: z.string().default(""),
  ADMIN_EMAIL: z.string().email().default("admin@vaultshare.local"),
  TRUSTED_PROXY_COUNT: z.coerce.number().int().min(0).max(8).default(0),
  MAX_UPLOAD_MB: z.coerce.number().int().min(1).max(100).default(25),
});

if (process.env.NODE_ENV === "production" && !process.env.VAULTSHARE_DATABASE_URL) {
  process.env.VAULTSHARE_DATABASE_URL = process.env.DATABASE_URL ?? "";
}

const parsed = rawSchema.safeParse(process.env);
if (!parsed.success) {
  const names = [...new Set(parsed.error.issues.map((issue) => issue.path.join(".")))];
  throw new Error(`VaultShare configuration is invalid (${names.join(", ")}). Run pnpm run gen:keys for local development.`);
}

const raw = parsed.data;
const encodedKeys = [raw.MASTER_KEY, raw.AUDIT_HMAC_KEY, raw.CSRF_SECRET];
if (new Set(encodedKeys).size !== encodedKeys.length) {
  throw new Error("VaultShare configuration is invalid (cryptographic keys must be distinct).");
}
if (process.env.NODE_ENV === "production" && raw.DEMO_MODE === "true") {
  throw new Error("VaultShare configuration is invalid (demo mode cannot run in production).");
}
if (raw.DEMO_MODE === "true" && raw.DEMO_PASSWORD.length < 12) {
  throw new Error("VaultShare configuration is invalid (DEMO_PASSWORD must contain at least 12 characters).");
}
if (process.env.NODE_ENV === "production" && !process.env.ADMIN_EMAIL) {
  throw new Error("VaultShare configuration is invalid (ADMIN_EMAIL is required in production).");
}

const storageDir = path.resolve(raw.STORAGE_DIR);
const workspaceRoot = path.resolve(process.cwd(), "../..");
const publicRoots = [
  path.join(workspaceRoot, "public"),
  path.join(workspaceRoot, "artifacts/vaultshare/public"),
  path.join(workspaceRoot, "artifacts/vaultshare/dist/public"),
  path.join(workspaceRoot, "artifacts/api-server/public"),
].map((value) => path.resolve(value));
const isWithin = (parent: string, candidate: string) =>
  candidate === parent || candidate.startsWith(`${parent}${path.sep}`);
if (publicRoots.some((publicRoot) => isWithin(publicRoot, storageDir))) {
  throw new Error("VaultShare configuration is invalid (STORAGE_DIR must be outside public directories).");
}

mkdirSync(storageDir, { recursive: true, mode: 0o700 });
chmodSync(storageDir, 0o700);
const realStorageDir = realpathSync(storageDir);
if (publicRoots.some((publicRoot) => isWithin(publicRoot, realStorageDir))) {
  throw new Error("VaultShare configuration is invalid (STORAGE_DIR resolves inside a public directory).");
}

const checkpointPath = path.resolve(raw.AUDIT_CHECKPOINT_PATH);
if (!isWithin(realStorageDir, checkpointPath)) {
  throw new Error("VaultShare configuration is invalid (AUDIT_CHECKPOINT_PATH must be inside STORAGE_DIR).");
}

const decodeKey = (value: string) => Buffer.from(value, "base64");
const deriveKey = (value: string, info: string) =>
  Buffer.from(hkdfSync("sha256", decodeKey(value), Buffer.from("VaultShare v1"), Buffer.from(info), 32));
const databaseUrl = raw.VAULTSHARE_DATABASE_URL;
const production = process.env.NODE_ENV === "production";
if (production && !databaseUrl.startsWith("postgres://") && !databaseUrl.startsWith("postgresql://")) {
  throw new Error("VaultShare configuration is invalid (production requires a PostgreSQL database URL).");
}
if (!production && !databaseUrl.startsWith("file:")) {
  throw new Error("VaultShare configuration is invalid (development requires a SQLite database URL).");
}

export const config = Object.freeze({
  production,
  masterKey: decodeKey(raw.MASTER_KEY),
  auditHmacKey: decodeKey(raw.AUDIT_HMAC_KEY),
  csrfKey: deriveKey(raw.CSRF_SECRET, "csrf"),
  fileKek: deriveKey(raw.MASTER_KEY, "file-kek"),
  totpKey: deriveKey(raw.MASTER_KEY, "totp"),
  storageDir: realStorageDir,
  checkpointPath,
  databaseUrl,
  demoMode: raw.DEMO_MODE === "true",
  demoPassword: raw.DEMO_PASSWORD,
  adminEmail: raw.ADMIN_EMAIL.toLowerCase(),
  trustedProxyCount: raw.TRUSTED_PROXY_COUNT,
  maxUploadBytes: raw.MAX_UPLOAD_MB * 1024 * 1024,
  keyId: createHash("sha256").update(decodeKey(raw.MASTER_KEY)).digest("hex").slice(0, 12),
});
