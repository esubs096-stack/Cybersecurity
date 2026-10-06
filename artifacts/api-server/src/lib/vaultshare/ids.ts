import { createHash, createHmac, randomBytes } from "node:crypto";
import { nanoid } from "nanoid";
import { config } from "./config";

export const publicId = () => nanoid(21);
export const randomToken = (bytes = 32) => randomBytes(bytes).toString("base64url");
export const sha256 = (value: string) => createHash("sha256").update(value).digest("hex");
export const keyedHash = (value: string) =>
  createHmac("sha256", config.csrfKey).update(value).digest("hex");
