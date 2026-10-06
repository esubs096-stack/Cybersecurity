import { randomBytes } from "node:crypto";
import { chmod, access, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const envPath = path.join(root, ".env");
const storageDir = path.join(root, ".vaultshare-storage");

try {
  await access(envPath);
  console.error("A local .env already exists. It was not changed.");
  process.exit(1);
} catch {
  // No local secrets file exists yet.
}

await mkdir(storageDir, { recursive: true, mode: 0o700 });
await chmod(storageDir, 0o700);
const values = {
  MASTER_KEY: randomBytes(32).toString("base64"),
  AUDIT_HMAC_KEY: randomBytes(32).toString("base64"),
  CSRF_SECRET: randomBytes(32).toString("base64"),
  STORAGE_DIR: storageDir,
  AUDIT_CHECKPOINT_PATH: path.join(storageDir, "audit.checkpoint"),
  VAULTSHARE_DATABASE_URL: `file:${path.join(storageDir, "vaultshare.sqlite")}`,
  DEMO_MODE: "true",
  DEMO_PASSWORD: randomBytes(24).toString("base64url"),
  ADMIN_EMAIL: "admin@vaultshare.local",
  TRUSTED_PROXY_COUNT: "1",
  MAX_UPLOAD_MB: "25",
};

const lines = Object.entries(values).map(([key, value]) => `${key}=${JSON.stringify(value)}`);
await writeFile(envPath, `${lines.join("\n")}\n`, { mode: 0o600, flag: "wx" });
await chmod(envPath, 0o600);
console.info("VaultShare local development secrets were created in .env with owner-only file permissions.");
console.info("Do not commit or share .env. Use separate random values in Replit Secrets for production.");
