// App factory: builds the Elysia instance without listening. Used by the
// production entrypoint (`src/index.ts`) and by the in-process test harness.

import { cors } from "@elysiajs/cors";
import { Elysia } from "elysia";
import { env } from "./config/env";
import { ipContextPlugin } from "./auth/ipContextPlugin";
import { authRoutes } from "./routes/auth.routes";
import { billingRoutes } from "./routes/billing.routes";
import { downloadRoutes } from "./routes/download.routes";
import { meRoutes } from "./routes/me.routes";
import { passkeyRoutes } from "./routes/passkey.routes";
import { portalRoutes } from "./routes/portal.routes";
import { uploadRoutes } from "./routes/upload.routes";
import { validateRoutes } from "./routes/validate.routes";
import { vaultRoutes } from "./routes/vault.routes";

export function createApp() {
  const corsOrigins = env.CORS_ORIGINS.split(",")
    .map((o) => o.trim())
    .filter(Boolean);

  return new Elysia()
    // Every API response is dynamic and frequently sensitive (presigned R2
    // download URLs, session/auth payloads, account exports). Mark them all
    // non-cacheable so nothing — browser, proxy, or Cloudflare tiered cache
    // (Smart Shield) — ever stores a response body. Set in onRequest so it
    // also lands on error/404 responses, not just successful handlers.
    .onRequest(({ set }) => {
      set.headers["cache-control"] = "no-store";
    })
    // Every handler returns `{ error: string }` on failure, but anything that
    // throws past a handler fell through to Elysia's own error shape, breaking
    // that contract. Normalise it here, and log 5xx so unhandled exceptions
    // are visible in journalctl (ADR-0012: no error tracker).
    .onError(({ code, error, set, request, path }) => {
      if (code === "NOT_FOUND") {
        set.status = 404;
        return { error: "Not found" };
      }
      if (code === "VALIDATION") {
        set.status = 400;
        return { error: "Invalid request" };
      }
      if (code === "PARSE") {
        set.status = 400;
        return { error: "Malformed request body" };
      }

      const message = error instanceof Error ? error.message : String(error);
      const stack = error instanceof Error ? error.stack : undefined;
      console.error(
        `[error] ${code} ${request.method} ${path}: ${message}`,
        stack ?? "",
      );

      set.status = 500;
      return { error: "Internal server error" };
    })
    .use(
      cors({
        origin:
          corsOrigins.length === 1 && corsOrigins[0] === "*"
            ? true
            : corsOrigins,
        credentials: true,
        allowedHeaders: ["Content-Type", "X-Requested-With"],
        // PUT serves /me/transfers/:id/title, PATCH serves /passkey/:id.
        // Omitting them made cross-origin preflight reject both.
        methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        exposeHeaders: ["Content-Length", "Content-Type"],
      }),
    )
    .use(ipContextPlugin)
    .get("/health", () => ({ status: "ok", timestamp: new Date().toISOString() }))
    .use(authRoutes)
    .use(passkeyRoutes)
    .use(billingRoutes)
    .use(uploadRoutes)
    .use(downloadRoutes)
    .use(meRoutes)
    .use(vaultRoutes)
    .use(portalRoutes)
    .use(validateRoutes);
}
