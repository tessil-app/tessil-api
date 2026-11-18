// Form templates: a form's questions and texts, kept for reuse. Each is
// one blob encrypted in the browser under the owner's vault; this file
// stores, lists and deletes blobs and reads none of them.
// See docs/adr/0016-encrypted-forms.md.

import { Elysia, t } from "elysia";
import { and, count, desc, eq, sql } from "drizzle-orm";
import { authPlugin } from "../auth/middleware";
import { limitFor, resolveCaps } from "../config/tiers";
import { db } from "../db";
import { formTemplates } from "../db/schema";
import { checkRateLimit, rateLimiters } from "../services/ratelimit.service";

const NANOID_PATTERN = /^[A-Za-z0-9_-]{21}$/;

/** Templates one account may keep. */
export const MAX_FORM_TEMPLATES = 20;
// version(1) + iv(12) + tag(16) at the least; the ceiling is a form's bundle with some room.
const TEMPLATE_MIN_BYTES = 1 + 12 + 16;
export const TEMPLATE_MAX_BYTES = 72 * 1024;
const TEMPLATE_MAX_CHARS = Math.ceil((TEMPLATE_MAX_BYTES * 4) / 3) + 4;

function decodeBounded(input: string, min: number, max: number): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(input)) return null;
  const bytes = new Uint8Array(Buffer.from(input, "base64url"));
  return bytes.length >= min && bytes.length <= max ? bytes : null;
}

export const formTemplateRoutes = new Elysia({ prefix: "/api/form-templates" })
  .use(authPlugin)

  .get("/", async ({ me, set }) => {
    if (!me) {
      set.status = 401;
      return { error: "Not authenticated" };
    }
    const rows = await db
      .select()
      .from(formTemplates)
      .where(eq(formTemplates.userId, me.id))
      .orderBy(desc(formTemplates.createdAt));
    return {
      max: MAX_FORM_TEMPLATES,
      templates: rows.map((row) => ({
        id: row.id,
        ciphertext: Buffer.from(row.ciphertext).toString("base64url"),
        createdAt: row.createdAt.toISOString(),
      })),
    };
  })

  .post(
    "/",
    async ({ me, body, originRejected, set }) => {
      if (originRejected) {
        set.status = 403;
        return { error: "Forbidden" };
      }
      if (!me) {
        set.status = 401;
        return { error: "Not authenticated" };
      }
      const limit = await checkRateLimit(me.id, rateLimiters.portalWrite);
      if (!limit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(limit.resetIn);
        return { error: "Rate limit exceeded. Try again later." };
      }
      // A template is for making forms, so it comes with the plans that have them.
      if (limitFor(resolveCaps(me), "form") === 0) {
        set.status = 402;
        return { error: "Forms are part of the paid plans.", code: "forms_require_paid_plan", upgradeUrl: "/pricing" };
      }
      const ciphertext = decodeBounded(body.ciphertext, TEMPLATE_MIN_BYTES, TEMPLATE_MAX_BYTES);
      if (!NANOID_PATTERN.test(body.id) || !ciphertext) {
        set.status = 400;
        return { error: "Not a template." };
      }

      const result = await db.transaction(async (tx) => {
        // One at a time per account, so two saves cannot both slip under the limit.
        await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${`form-templates:${me.id}`}, 0))`);
        const [held] = await tx.select({ n: count() }).from(formTemplates).where(eq(formTemplates.userId, me.id));
        if (Number(held?.n ?? 0) >= MAX_FORM_TEMPLATES) return "limit" as const;
        const rows = await tx
          .insert(formTemplates)
          .values({ id: body.id, userId: me.id, ciphertext })
          .onConflictDoNothing()
          .returning({ createdAt: formTemplates.createdAt });
        // Nothing returned: the ID was there already.
        return rows.length > 0 ? rows[0] : ("taken" as const);
      });
      if (result === "limit") {
        set.status = 409;
        return {
          error: `You can keep ${MAX_FORM_TEMPLATES} templates. Delete one first.`,
          code: "template_limit_reached",
        };
      }
      if (result === "taken") {
        set.status = 409;
        return { error: "That template ID is taken. Try again.", code: "template_id_taken" };
      }
      set.status = 201;
      return { id: body.id, createdAt: result.createdAt.toISOString() };
    },
    {
      body: t.Object({
        id: t.String({ maxLength: 21 }),
        ciphertext: t.String({ maxLength: TEMPLATE_MAX_CHARS }),
      }),
    },
  )

  .delete("/:id", async ({ me, params, originRejected, set }) => {
    if (originRejected) {
      set.status = 403;
      return { error: "Forbidden" };
    }
    if (!me) {
      set.status = 401;
      return { error: "Not authenticated" };
    }
    const removed = NANOID_PATTERN.test(params.id)
      ? await db
          .delete(formTemplates)
          .where(and(eq(formTemplates.id, params.id), eq(formTemplates.userId, me.id)))
          .returning({ id: formTemplates.id })
      : [];
    if (removed.length === 0) {
      set.status = 404;
      return { error: "Template not found" };
    }
    return { ok: true };
  });
