// User-scoped endpoints. All routes require an authenticated session;
// non-owner access to owned resources returns 404 (not 403) to avoid
// an existence oracle.

import { Elysia, t } from "elysia";
import { authPlugin } from "../auth/middleware";
import { ipContextPlugin } from "../auth/ipContextPlugin";
import { logAuthEvent } from "../auth/events";
import { buildAccountExport, eraseAccount } from "../auth/users";
import { SESSION_COOKIE_NAME, SESSION_COOKIE_OPTIONS } from "../auth/sessions";
import { normaliseEmail } from "../auth/tokens";
import { getFileMetadataForOwnedTransfer, getStoredBytes, listTransfersForUser, setOwnedTransferTitle, softDeleteOwnedTransfer } from "../services/file.service";
import { sendAccountDeletedNotification } from "../services/email.service";
import {
  checkRateLimit,
  peekRateLimit,
  peekVolumeLimit,
  rateLimiters,
} from "../services/ratelimit.service";
import { resolveCaps } from "../config/tiers";
import {
  ENCRYPTED_TITLE_IV_LENGTH,
  ENCRYPTED_TITLE_MAX_LENGTH,
  validateEncryptedTitle,
} from "../utils/encryptedTitle";

const NANOID_PATTERN = /^[A-Za-z0-9_-]{21}$/;
const DEFAULT_PAGE_SIZE = 20;
const MAX_PAGE_SIZE = 50;

export const meRoutes = new Elysia({ prefix: "/api/me" })
  .use(authPlugin)
  .use(ipContextPlugin)

  // Current usage against the authenticated user's tier caps. Reads
  // the rate-limit counters without consuming a slot.
  .get("/usage", async ({ me, set }) => {
    if (!me) {
      set.status = 401;
      return { error: "Not authenticated" };
    }

    const caps = resolveCaps(me);

    const dailyConfig = {
      ...rateLimiters.dailyTransfers,
      maxRequests: caps.dailyTransferCount,
    };
    const monthlyConfig = {
      ...rateLimiters.monthlyUploadVolume,
      maxBytes: caps.monthlyVolumeBytes,
      increment: 0,
    };

    const [daily, monthly, storedBytes] = await Promise.all([
      peekRateLimit(me.id, dailyConfig),
      peekVolumeLimit(me.id, monthlyConfig),
      caps.storageBytes === null ? null : getStoredBytes(me.id),
    ]);

    const now = Date.now();
    return {
      tier: me.tier,
      // NULL on plans without a storage quota.
      storage:
        caps.storageBytes === null || storedBytes === null
          ? null
          : { usedBytes: storedBytes, quotaBytes: caps.storageBytes },
      monthlyVolume: {
        usedBytes: monthly.usedBytes,
        capBytes: caps.monthlyVolumeBytes,
        resetAt: new Date(now + monthly.resetIn * 1000).toISOString(),
      },
      dailyTransfers: {
        used: daily.used,
        cap: caps.dailyTransferCount,
        resetAt: new Date(now + daily.resetIn * 1000).toISOString(),
      },
      caps: {
        maxFileSize: caps.maxFileSize,
        maxTransferSize: caps.maxTransferSize,
        allowedExpiryHours: [...caps.allowedExpiryHours],
      },
    };
  })

  .get(
    "/transfers",
    async ({ me, query, set }) => {
      if (!me) {
        set.status = 401;
        return { error: "Not authenticated" };
      }

      const listLimit = await checkRateLimit(me.id, rateLimiters.meTransfersList);
      if (!listLimit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(listLimit.resetIn);
        return { error: "Rate limit exceeded. Try again later." };
      }

      const limit = Math.min(
        Math.max(Number(query.limit) || DEFAULT_PAGE_SIZE, 1),
        MAX_PAGE_SIZE,
      );

      let cursor: Date | null = null;
      if (typeof query.cursor === "string" && query.cursor.length > 0) {
        const parsed = new Date(query.cursor);
        if (Number.isNaN(parsed.getTime())) {
          set.status = 400;
          return { error: "Invalid cursor" };
        }
        cursor = parsed;
      }

      const rows = await listTransfersForUser(me.id, cursor, limit);
      const nextCursor = rows.length === limit ? rows[rows.length - 1].createdAt.toISOString() : null;

      return { transfers: rows, nextCursor };
    },
    {
      query: t.Object({
        cursor: t.Optional(t.String({ maxLength: 64 })),
        limit: t.Optional(t.String({ maxLength: 4 })),
      }),
    },
  )

  // Per-file metadata for an owned transfer (encrypted filename + IV +
  // size + mime). Used by the dashboard to decrypt filenames after the
  // vault key has unwrapped K_transfer client-side. Not-owned /
  // not-found both collapse to 404.
  .get(
    "/transfers/:id/files",
    async ({ me, params, set }) => {
      if (!me) {
        set.status = 401;
        return { error: "Not authenticated" };
      }
      const listLimit = await checkRateLimit(me.id, rateLimiters.meTransfersList);
      if (!listLimit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(listLimit.resetIn);
        return { error: "Rate limit exceeded. Try again later." };
      }

      if (!NANOID_PATTERN.test(params.id)) {
        set.status = 404;
        return { error: "Not found" };
      }

      const files = await getFileMetadataForOwnedTransfer(me.id, params.id);
      if (files === null) {
        set.status = 404;
        return { error: "Not found" };
      }

      return { files };
    },
    {
      params: t.Object({ id: t.String({ minLength: 21, maxLength: 21 }) }),
    },
  )

  // Owner-only title rewrite. The title is encrypted client-side
  // under the transfer's fragment key; the server only persists the
  // opaque ciphertext + IV. `null` for both fields clears the title;
  // both-or-neither is enforced. Non-owner / not-found /
  // soft-deleted collapse to 404.
  .put(
    "/transfers/:id/title",
    async ({ me, params, body, originRejected, set }) => {
      if (originRejected) {
        set.status = 403;
        return { error: "Forbidden" };
      }
      if (!me) {
        set.status = 401;
        return { error: "Not authenticated" };
      }

      const limit = await checkRateLimit(me.id, rateLimiters.meTransferTitle);
      if (!limit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(limit.resetIn);
        return { error: "Rate limit exceeded. Try again later." };
      }

      if (!NANOID_PATTERN.test(params.id)) {
        set.status = 404;
        return { error: "Not found" };
      }

      const result = validateEncryptedTitle(body?.encryptedTitle, body?.encryptedTitleIv, {
        allowNullToClear: true,
      });
      if (!result.ok) {
        set.status = 400;
        return { error: result.error };
      }

      const ok = await setOwnedTransferTitle(
        me.id,
        params.id,
        result.value?.encryptedTitle ?? null,
        result.value?.encryptedTitleIv ?? null,
      );
      if (!ok) {
        set.status = 404;
        return { error: "Not found" };
      }

      set.status = 204;
      return null;
    },
    {
      body: t.Object({
        encryptedTitle: t.Union([
          t.String({ maxLength: ENCRYPTED_TITLE_MAX_LENGTH }),
          t.Null(),
        ]),
        encryptedTitleIv: t.Union([
          t.String({ maxLength: ENCRYPTED_TITLE_IV_LENGTH }),
          t.Null(),
        ]),
      }),
    },
  )

  .delete(
    "/transfers/:id",
    async ({ me, params, ipContext, originRejected, request, set }) => {
      if (originRejected) {
        set.status = 403;
        return { error: "Forbidden" };
      }
      if (!me) {
        set.status = 401;
        return { error: "Not authenticated" };
      }

      const deleteLimit = await checkRateLimit(me.id, rateLimiters.meTransfersDelete);
      if (!deleteLimit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(deleteLimit.resetIn);
        return { error: "Rate limit exceeded. Try again later." };
      }

      const id = params.id;
      if (!NANOID_PATTERN.test(id)) {
        set.status = 404;
        return { error: "Not found" };
      }

      const ok = await softDeleteOwnedTransfer(me.id, id);
      if (!ok) {
        // Not found, not owned, or already deleted — all collapse to 404.
        set.status = 404;
        return { error: "Not found" };
      }

      await logAuthEvent({
        eventType: "transfer_deleted",
        userId: me.id,
        email: me.email,
        ipContext,
        userAgent: request.headers.get("user-agent"),
      });

      set.status = 204;
      return null;
    },
  )

  // Account export — GDPR Article 20 (data portability).
  .get(
    "/export",
    async ({ me, ipContext, request, set }) => {
      if (!me) {
        set.status = 401;
        return { error: "Not authenticated" };
      }

      const limit = await checkRateLimit(me.id, rateLimiters.accountExport);
      if (!limit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(limit.resetIn);
        return { error: "Rate limit exceeded. Try again later." };
      }

      const exportData = await buildAccountExport(me);

      await logAuthEvent({
        eventType: "account_exported",
        userId: me.id,
        email: me.email,
        ipContext,
        userAgent: request.headers.get("user-agent"),
      });

      const stamp = new Date().toISOString().replace(/[:.]/g, "-");
      set.headers["Content-Type"] = "application/json; charset=utf-8";
      set.headers["Content-Disposition"] = `attachment; filename="tessil-export-${me.id}-${stamp}.json"`;
      set.headers["Cache-Control"] = "no-store, max-age=0";
      set.headers["Pragma"] = "no-cache";

      return exportData;
    },
  )

  // Account erasure — GDPR Article 17 (right to erasure).
  .delete(
    "/",
    async ({ me, ipContext, originRejected, request, body, cookie, set }) => {
      if (originRejected) {
        set.status = 403;
        return { error: "Forbidden" };
      }
      if (!me) {
        set.status = 401;
        return { error: "Not authenticated" };
      }

      const limit = await checkRateLimit(me.id, rateLimiters.accountDelete);
      if (!limit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(limit.resetIn);
        return { error: "Rate limit exceeded. Try again later." };
      }

      // Typed-email confirmation gate. Case-insensitive + trimmed
      // via normaliseEmail; mismatch is opaque.
      const confirmEmail = typeof body?.confirmEmail === "string" ? body.confirmEmail : "";
      if (!confirmEmail || normaliseEmail(confirmEmail) !== me.email) {
        set.status = 400;
        return { error: "Confirmation does not match account email." };
      }

      const userAgent = request.headers.get("user-agent");

      // Snapshot email before erasure — we need it for the notification send
      // after the user row is gone.
      const formerEmail = me.email;

      await eraseAccount({ user: me, ipContext, userAgent });

      // Best-effort notification. The erasure already committed, so
      // a send failure must not turn the response into a 5xx.
      try {
        await sendAccountDeletedNotification({ to: formerEmail });
      } catch (err) {
        console.error("[erasure] account-deleted notification send failed:", err);
      }

      // Clear the session cookie so the client drops its stale state.
      cookie[SESSION_COOKIE_NAME]?.set({
        value: "",
        ...SESSION_COOKIE_OPTIONS,
        maxAge: 0,
      });

      set.status = 204;
      return null;
    },
    {
      body: t.Object({
        confirmEmail: t.String({ maxLength: 320 }),
      }),
    },
  );
