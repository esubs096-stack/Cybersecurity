export type VaultUser = {
  id: string;
  publicId: string;
  name: string;
  email: string;
  role: "admin" | "user";
  emailVerified: boolean;
  twoFactorEnabled: boolean;
};

declare global {
  namespace Express {
    interface Request {
      vaultUser?: VaultUser;
      vaultSessionRaw?: string;
      vaultSessionDbId?: string;
      vaultRequestId?: string;
    }
  }
}

export {};
