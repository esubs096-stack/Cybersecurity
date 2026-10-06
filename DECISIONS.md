# VaultShare decisions

## Platform fit

- Use the existing pnpm workspace's React/Vite web artifact and Express API artifact instead of introducing a separate Next.js server. Keep the requested routes, security behavior, and API-first design; document the framework difference wherever setup or architecture is described.
- The repo's existing database package is Drizzle/PostgreSQL. The requested Prisma + SQLite development setup will be evaluated against the shared API artifact and deployment environment before choosing persistence; do not silently claim SQLite/Prisma support if the selected implementation differs.

## Security policy

- Demo data and security indicators must come from real persisted records or be visibly labelled as simulated. Never create a visual-only PASS state.
- Public IDs, not database row IDs, are the only identifiers exposed outside the server.
- Use the supplied generic authentication/access error messages. Do not include tokens, passwords, storage paths, or internal IDs in logs or API errors.
- Security-sensitive endpoints require an explicit server-side guard; unknown actions deny by default.
