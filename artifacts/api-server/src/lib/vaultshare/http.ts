import type { Request, Response } from "express";

export const genericMessages = Object.freeze({
  invalidCredentials: "Invalid credentials.",
  forbidden: "You do not have permission to access this resource.",
  unavailableShare: "This link is invalid or unavailable.",
  tooManyAttempts: "Too many attempts. Try again later.",
});

export function requestId(req: Request): string {
  return String(req.id ?? req.vaultRequestId ?? "unknown");
}

export function sendError(
  req: Request,
  res: Response,
  status: number,
  error: string,
): void {
  res.status(status).json({ error, requestId: requestId(req) });
}

export function asyncRoute(
  handler: (req: Request, res: Response) => Promise<void>,
) {
  return (req: Request, res: Response, next: (error?: unknown) => void) => {
    void handler(req, res).catch(next);
  };
}
