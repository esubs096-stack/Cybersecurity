import type { VaultUser } from "./types";

export type SecurityAction =
  | "dashboard:read"
  | "document:list"
  | "document:read"
  | "document:decrypt"
  | "document:upload"
  | "document:delete"
  | "share:list"
  | "share:create"
  | "share:edit"
  | "share:revoke"
  | "audit:read"
  | "audit:verify"
  | "alert:list"
  | "alert:update"
  | "settings:read"
  | "settings:update"
  | "user:admin";

export type SecurityResource = {
  ownerPublicId?: string | null;
  documentOwnerPublicId?: string | null;
  isSystemMetadata?: boolean;
};

/**
 * One fail-closed authorization policy. Admins may inspect security metadata,
 * but can never decrypt document content.
 */
export function authorize(
  actor: VaultUser | null,
  action: SecurityAction,
  resource: SecurityResource = {},
): boolean {
  if (!actor || (actor.role !== "admin" && actor.role !== "user")) return false;
  if (action === "document:decrypt") return false;
  if (actor.role === "admin") {
    return [
      "dashboard:read",
      "document:list",
      "audit:read",
      "audit:verify",
      "alert:list",
      "alert:update",
      "settings:read",
      "settings:update",
      "user:admin",
    ].includes(action);
  }
  if (action === "user:admin") return false;
  if (action === "dashboard:read" || action === "document:list" || action === "share:list" ||
      action === "document:upload" || action === "audit:read" || action === "alert:list" ||
      action === "settings:read" || action === "settings:update") {
    return true;
  }
  const owner = resource.ownerPublicId ?? resource.documentOwnerPublicId;
  return !!owner && owner === actor.publicId;
}

export type AccessDecision = {
  allow: boolean;
  code: string;
  userMessage: string;
  auditAction: string;
  reason: string;
};

export function authorizeAccess(
  actor: VaultUser | null,
  action: "view" | "download" | "print" | "comment" | "reshare",
  share: {
    ownerPublicId: string;
    recipientPublicId?: string | null;
    recipientEmail?: string | null;
    tokenMatched: boolean;
    active: boolean;
    notExpired: boolean;
    passwordSatisfied: boolean;
    permissions: string[];
    verifiedRecipientEmail?: string | null;
  },
): AccessDecision {
  const deny = (code: string, reason: string): AccessDecision => ({
    allow: false,
    code,
    userMessage: "This link is invalid or unavailable.",
    auditAction: "ACCESS_DENIED",
    reason,
  });

  if (!share.tokenMatched) return deny("TOKEN_INVALID", "Token hash did not match.");
  if (!share.active) return deny("SHARE_REVOKED", "Share has been revoked.");
  if (!share.notExpired) return deny("SHARE_EXPIRED", "Share has expired.");
  if (!share.passwordSatisfied) return deny("PASSWORD_REQUIRED", "Share password was not verified.");
  if (!share.permissions.includes(action)) return deny("PERMISSION_DENIED", "Requested permission is absent.");

  if (share.recipientPublicId) {
    const sessionMatch = actor?.publicId === share.recipientPublicId;
    const emailMatch =
      !!share.verifiedRecipientEmail &&
      !!share.recipientEmail &&
      share.verifiedRecipientEmail.toLowerCase() === share.recipientEmail.toLowerCase();
    if (!sessionMatch && !emailMatch) {
      return deny("RECIPIENT_MISMATCH", "Recipient identity did not match.");
    }
  }

  return {
    allow: true,
    code: "ACCESS_ALLOWED",
    userMessage: "",
    auditAction: action === "view" ? "DOCUMENT_VIEW" : action === "download" ? "DOCUMENT_DOWNLOAD" : "SHARE_ACCESS",
    reason: "All share access rules passed.",
  };
}
