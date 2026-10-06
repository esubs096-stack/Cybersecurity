import express, { type Express } from "express";
import cookieParser from "cookie-parser";
import pinoHttp from "pino-http";
import router from "./routes";
import { logger } from "./lib/logger";
import { config } from "./lib/vaultshare/config";
import { requestId, sendError } from "./lib/vaultshare/http";
import type { ErrorRequestHandler } from "express";

const app: Express = express();
app.set("trust proxy", config.trustedProxyCount);

app.use(
  pinoHttp({
    logger,
    serializers: {
      req(req) {
        return {
          id: req.id,
          method: req.method,
          url: req.url
            ?.split("?")[0]
            .replace(/(^|\/)[A-Za-z0-9_-]{32,}(?=\/|$)/g, "$1[REDACTED]"),
        };
      },
      res(res) {
        return {
          statusCode: res.statusCode,
        };
      },
    },
  }),
);
app.use((req, res, next) => {
  req.vaultRequestId = String(req.id ?? "unknown");
  res.setHeader("X-Request-Id", requestId(req));
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  if (config.production) res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  next();
});
app.use(cookieParser());
app.use(express.json({ limit: "64kb" }));
app.use(express.urlencoded({ extended: true, limit: "64kb" }));

app.use("/api", router);

const errorHandler: ErrorRequestHandler = (error: unknown, req, res, _next) => {
  const status =
    typeof error === "object" &&
    error !== null &&
    "status" in error &&
    typeof error.status === "number" &&
    error.status >= 400 &&
    error.status <= 599
      ? error.status
      : 500;
  req.log?.error(
    { errorName: error instanceof Error ? error.name : "unknown", status },
    "Request failed",
  );
  sendError(
    req,
    res,
    status,
    status === 400 ? "Invalid request." : "The request could not be completed.",
  );
};
app.use(errorHandler);

export default app;
