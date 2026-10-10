// Billing routes — Polar checkout, customer portal, and webhook
// receiver. The webhook handler is the only thing that mutates
// `subscriptions` or `users.tier`; the public-facing endpoints just
// redirect the browser to Polar-hosted pages.

import { Elysia, t } from "elysia";
import { desc, eq } from "drizzle-orm";
import { nanoid } from "nanoid";
import { authPlugin } from "../auth/middleware";
import { ipContextPlugin } from "../auth/ipContextPlugin";
import { env } from "../config/env";
import { paidCaps } from "../config/tiers";
import { db } from "../db";
import { billingEvents, subscriptions, users, type Subscription } from "../db/schema";
import { createPass, resolvePass } from "../services/pass.service";
import {
  createPortalSession,
  createProCheckout,
  parseWebhook,
  WebhookVerificationError,
} from "../services/polar.service";
import { checkIpRateLimit, rateLimiters } from "../services/ratelimit.service";

// Polar `subscription.status` values that map to "user is currently
// Pro". `canceled` is terminal; everything else keeps Pro caps.
const PRO_STATUSES = new Set(["active", "past_due", "trialing"]);
function tierFromStatus(status: string): "free" | "pro" {
  return PRO_STATUSES.has(status) ? "pro" : "free";
}

// `externalId` is the user ID we set at checkout — every subsequent
// webhook event replays it back, so we route inbound events to the
// right user row without a lookup table.
interface PolarSubscriptionData {
  id: string;
  status: string;
  currentPeriodEnd: Date | string;
  cancelAtPeriodEnd: boolean;
  customerId: string;
  customer: {
    id: string;
    externalId?: string | null;
  };
}

interface HandlerResult {
  ok: boolean;
  reason?: string;
  subscriptionId?: string;
}

// Single upsert path for every "subscription is currently in state X"
// event. `subscription.created`, `.updated`, `.active`, `.past_due`,
// `.uncanceled` all funnel through here. `.canceled` and `.revoked`
// route through `applyTerminalCancel` instead because they set
// canceled_at and flip tier to 'free' regardless of status string.
async function applySubscriptionState(data: PolarSubscriptionData): Promise<HandlerResult> {
  const externalId = data.customer.externalId;
  if (!externalId) {
    console.warn(`[billing] event for ${data.id} has no externalCustomerId, skipping`);
    return { ok: false, reason: "no external id" };
  }

  const [user] = await db.select().from(users).where(eq(users.id, externalId));
  if (!user) {
    console.warn(`[billing] event for ${data.id} references unknown user ${externalId}`);
    return { ok: false, reason: "user not found" };
  }

  const periodEnd =
    typeof data.currentPeriodEnd === "string"
      ? new Date(data.currentPeriodEnd)
      : data.currentPeriodEnd;

  const now = new Date();
  const [existing] = await db
    .select({ id: subscriptions.id })
    .from(subscriptions)
    .where(eq(subscriptions.polarSubscriptionId, data.id));

  let subscriptionId: string;
  if (existing) {
    await db
      .update(subscriptions)
      .set({
        status: data.status,
        currentPeriodEnd: periodEnd,
        cancelAtPeriodEnd: data.cancelAtPeriodEnd,
        updatedAt: now,
      })
      .where(eq(subscriptions.id, existing.id));
    subscriptionId = existing.id;
  } else {
    subscriptionId = nanoid();
    await db.insert(subscriptions).values({
      id: subscriptionId,
      userId: user.id,
      polarSubscriptionId: data.id,
      status: data.status,
      currentPeriodEnd: periodEnd,
      cancelAtPeriodEnd: data.cancelAtPeriodEnd,
      createdAt: now,
      updatedAt: now,
    });
  }

  // Sync the user's tier and persist the customer ID on first sight.
  // polarCustomerId is set-once.
  await db
    .update(users)
    .set({
      tier: tierFromStatus(data.status),
      ...(user.polarCustomerId ? {} : { polarCustomerId: data.customerId }),
    })
    .where(eq(users.id, user.id));

  return { ok: true, subscriptionId };
}

// Terminal cancel — row is closed out, user drops to Free.
async function applyTerminalCancel(data: PolarSubscriptionData): Promise<HandlerResult> {
  const externalId = data.customer.externalId;
  if (!externalId) {
    return { ok: false, reason: "no external id" };
  }

  const now = new Date();
  const [existing] = await db
    .select({ id: subscriptions.id, userId: subscriptions.userId })
    .from(subscriptions)
    .where(eq(subscriptions.polarSubscriptionId, data.id));

  if (!existing) {
    // Never saw the create event — insert a row in terminal state so
    // the audit trail isn't a gap.
    const subscriptionId = nanoid();
    await db.insert(subscriptions).values({
      id: subscriptionId,
      userId: externalId,
      polarSubscriptionId: data.id,
      status: data.status,
      currentPeriodEnd:
        typeof data.currentPeriodEnd === "string"
          ? new Date(data.currentPeriodEnd)
          : data.currentPeriodEnd,
      cancelAtPeriodEnd: data.cancelAtPeriodEnd,
      createdAt: now,
      updatedAt: now,
      canceledAt: now,
    });
    await db.update(users).set({ tier: "free" }).where(eq(users.id, externalId));
    return { ok: true, subscriptionId };
  }

  await db
    .update(subscriptions)
    .set({
      status: data.status,
      cancelAtPeriodEnd: data.cancelAtPeriodEnd,
      updatedAt: now,
      canceledAt: now,
    })
    .where(eq(subscriptions.id, existing.id));

  await db.update(users).set({ tier: "free" }).where(eq(users.id, existing.userId));
  return { ok: true, subscriptionId: existing.id };
}

export const billingRoutes = new Elysia({ prefix: "/api/billing" })
  .use(authPlugin)
  .use(ipContextPlugin)

  // What the upload page needs before it lets a sender start: is the
  // paywall on, is this session already paid for, and what paying buys.
  .get("/entitlement", ({ me }) => {
    const caps = paidCaps();
    return {
      paywall: env.PAYWALL_ENABLED,
      entitled: !env.PAYWALL_ENABLED || me?.tier === "pro",
      paidCaps: {
        maxTransferSize: caps.maxTransferSize,
        allowedExpiryHours: caps.allowedExpiryHours,
      },
    };
  })

  // Open a checkout for one single-transfer pass. Public: the buyer may
  // be anonymous. The token is returned once and only to this caller.
  .post("/pass/checkout", async ({ ipContext, set }) => {
    const limit = await checkIpRateLimit(ipContext, rateLimiters.passCheckout);
    if (!limit.allowed) {
      set.status = 429;
      set.headers["Retry-After"] = String(limit.resetIn);
      return { error: "Too many checkouts started. Try again later." };
    }
    try {
      const { token, url } = await createPass();
      return { token, url };
    } catch (err) {
      console.error("[billing] pass checkout creation failed:", err);
      set.status = 500;
      return { error: "Checkout creation failed. Please try again." };
    }
  })

  // Polled by the buyer's tab while the Polar checkout is open.
  .post(
    "/pass/status",
    async ({ body, ipContext, set }) => {
      const limit = await checkIpRateLimit(ipContext, rateLimiters.passStatus);
      if (!limit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(limit.resetIn);
        return { error: "Rate limit exceeded. Try again later." };
      }
      try {
        const { state } = await resolvePass(body.token);
        return { state };
      } catch (err) {
        console.error("[billing] pass status check failed:", err);
        set.status = 502;
        return { error: "Could not confirm the payment yet. Please try again." };
      }
    },
    { body: t.Object({ token: t.String({ minLength: 16, maxLength: 64 }) }) },
  )

  // Subscription summary for the authenticated user. Returns the
  // live row when present, otherwise the most-recent terminal row
  // so the UI can still surface "ended on {date}". `subscription`
  // is null only for users who have never had a Subscription row.
  .get("/status", async ({ me, set }) => {
    if (!me) {
      set.status = 401;
      return { error: "Not authenticated" };
    }

    const [live] = await db
      .select()
      .from(subscriptions)
      .where(eq(subscriptions.userId, me.id))
      .orderBy(desc(subscriptions.updatedAt))
      .limit(1);

    return {
      tier: me.tier,
      subscription: live
        ? {
            status: live.status,
            currentPeriodEnd: live.currentPeriodEnd.toISOString(),
            cancelAtPeriodEnd: live.cancelAtPeriodEnd,
            canceledAt: live.canceledAt ? live.canceledAt.toISOString() : null,
          }
        : null,
    };
  })

  .post(
    "/checkout",
    async ({ me, body, set }) => {
      if (!me) {
        set.status = 401;
        return { error: "Not authenticated" };
      }
      const cycle = body.cycle === "annual" ? "annual" : "monthly";
      try {
        const { url } = await createProCheckout(me, cycle);
        return { url };
      } catch (err) {
        console.error("[billing] checkout creation failed:", err);
        set.status = 500;
        return { error: "Checkout creation failed. Please try again." };
      }
    },
    {
      body: t.Object({
        cycle: t.Union([t.Literal("monthly"), t.Literal("annual")]),
      }),
    },
  )

  .post("/portal", async ({ me, set }) => {
    if (!me) {
      set.status = 401;
      return { error: "Not authenticated" };
    }
    if (!me.polarCustomerId) {
      set.status = 404;
      return { error: "No active billing relationship to manage." };
    }
    try {
      const { url } = await createPortalSession(me.polarCustomerId);
      return { url };
    } catch (err) {
      console.error("[billing] portal session creation failed:", err);
      set.status = 500;
      return { error: "Couldn't open the billing portal. Please try again." };
    }
  })

  // Public webhook receiver. Security is the HMAC signature verified
  // inside `parseWebhook`. `parse: 'text'` is required because the
  // raw bytes are what Polar signed — JSON-parsing would re-serialise
  // and break verification.
  .post("/webhook", async ({ body, request, set }) => {
      const rawBody = typeof body === "string" ? body : "";

      // Fetch normalises header names to lowercase.
      const headers: Record<string, string> = {};
      request.headers.forEach((value, key) => {
        headers[key] = value;
      });

      // Check webhook-id presence before signature verification so a
      // missing header returns a clear 400 rather than 401.
      const polarEventId = headers["webhook-id"] ?? "";
      if (!polarEventId) {
        set.status = 400;
        return { error: "Missing webhook-id header" };
      }

      let event: ReturnType<typeof parseWebhook>;
      try {
        event = parseWebhook(rawBody, headers);
      } catch (err) {
        if (err instanceof WebhookVerificationError) {
          set.status = 401;
          return { error: "Invalid signature" };
        }
        console.error("[billing] webhook parse error:", err);
        set.status = 400;
        return { error: "Malformed webhook payload" };
      }

      const eventRowId = nanoid();
      try {
        await db.insert(billingEvents).values({
          id: eventRowId,
          polarEventId,
          polarEventType: event.type,
          rawPayload: event as unknown as Record<string, unknown>,
        });
      } catch {
        // UNIQUE violation on polar_event_id = already processed.
        // Return 200 so Polar stops retrying.
        console.warn("[billing] duplicate webhook delivery, skipping:", event.type);
        return { ok: true, deduplicated: true };
      }

      // Unknown event types are audited but otherwise ignored, so
      // Polar doesn't retry them forever.
      let result: HandlerResult;
      try {
        switch (event.type) {
          case "subscription.created":
          case "subscription.active":
          case "subscription.updated":
          case "subscription.uncanceled":
          case "subscription.past_due":
            result = await applySubscriptionState(event.data as unknown as PolarSubscriptionData);
            break;
          case "subscription.canceled":
          case "subscription.revoked":
            result = await applyTerminalCancel(event.data as unknown as PolarSubscriptionData);
            break;
          default:
            result = { ok: true, reason: "ignored event type" };
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        await db
          .update(billingEvents)
          .set({ error: message })
          .where(eq(billingEvents.id, eventRowId));
        console.error(`[billing] handler for ${event.type} failed:`, err);
        // Return 500 so Polar retries.
        set.status = 500;
        return { error: "Handler failed" };
      }

      await db
        .update(billingEvents)
        .set({
          processedAt: new Date(),
          subscriptionId: result.subscriptionId ?? null,
          error: result.ok ? null : result.reason ?? "handler returned not-ok",
        })
        .where(eq(billingEvents.id, eventRowId));

      return { ok: result.ok };
    },
    {
      // Force Elysia to give us the body as a raw string regardless
      // of Content-Type. Polar sends `application/json`; the default
      // parser would re-serialise the parsed object before we ever
      // see the bytes, and the re-serialisation breaks the HMAC.
      parse: "text",
    },
  );
