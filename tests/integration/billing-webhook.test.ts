// Polar webhook integration per ADR-0006 / ADR-0007. Covers:
//
//   - HMAC signature verification (real crypto — payloads are signed
//     by `standardwebhooks`'s Webhook class with the same secret the
//     route handler verifies against, set in `tests/setup.ts`).
//   - Missing `webhook-id` header → 400.
//   - `subscription.created` → tier='pro', subscription row, sets
//     polar_customer_id on first sight.
//   - `subscription.canceled` → tier='free', canceledAt timestamp set.
//   - Idempotent delivery: same `webhook-id` twice → second is a no-op
//     via the billing_events UNIQUE constraint, no second mutation.
//   - Unknown externalCustomerId → handler returns ok=false but the
//     event is still audited (billing_events row exists with `error`).
//   - Auth gates on `POST /api/billing/checkout` and `/portal`.

import { afterAll, beforeAll, beforeEach, describe, expect, it, mock } from "bun:test";
import { eq } from "drizzle-orm";
import { Webhook, WebhookVerificationError } from "standardwebhooks";
import { createApp } from "../../src/app";
import { db } from "../../src/db";
import { billingEvents, subscriptions, users } from "../../src/db/schema";
import { authedRequest, createAuthedUser } from "../helpers/auth";
import { ensureMigrations, resetDb } from "../helpers/db";

const APP_URL = process.env.APP_URL!;
const WEBHOOK_SECRET = process.env.POLAR_WEBHOOK_SECRET!;

// Replace `parseWebhook` with a version that does real signature
// verification (so the security check is still tested end-to-end)
// but skips Polar's strict Zod parsing of every Subscription field.
// We're testing OUR handler logic — routing, idempotency, tier sync —
// not Polar's wire-format schema. The auth-gate tests for checkout
// and portal don't call the stubbed Polar functions so they keep
// working under this mock.
mock.module("../../src/services/polar.service", () => ({
  parseWebhook: (body: string, headers: Record<string, string>) => {
    const webhook = new Webhook(WEBHOOK_SECRET);
    webhook.verify(body, headers); // throws WebhookVerificationError on bad sig
    return JSON.parse(body);
  },
  WebhookVerificationError,
  createProCheckout: async () => {
    throw new Error("createProCheckout not exercised in webhook tests");
  },
  createPortalSession: async () => {
    throw new Error("createPortalSession not exercised in webhook tests");
  },
  cancelSubscriptionImmediately: async () => {
    throw new Error("cancelSubscriptionImmediately not exercised in webhook tests");
  },
  createPassCheckout: async () => {
    throw new Error("createPassCheckout not exercised in webhook tests");
  },
  isPassCheckoutPaid: async () => {
    throw new Error("isPassCheckoutPaid not exercised in webhook tests");
  },
}));

let app: ReturnType<typeof createApp>;

beforeAll(async () => {
  await ensureMigrations();
  app = createApp();
});

beforeEach(async () => {
  await resetDb();
});

afterAll(async () => {
  await resetDb();
});

interface SignedRequest {
  body: string;
  headers: Record<string, string>;
}

// Sign a payload with the test webhook secret. Uses the same library
// the production handler uses to verify, so a successful sign-here →
// verify-there is end-to-end proof of the wiring.
function signEvent(payload: object, msgId = `msg_${Math.random().toString(36).slice(2)}`): SignedRequest {
  const body = JSON.stringify(payload);
  const timestamp = new Date();
  const webhook = new Webhook(WEBHOOK_SECRET);
  const signature = webhook.sign(msgId, timestamp, body);
  return {
    body,
    headers: {
      "Content-Type": "application/json",
      "webhook-id": msgId,
      "webhook-timestamp": String(Math.floor(timestamp.getTime() / 1000)),
      "webhook-signature": signature,
    },
  };
}

// Test fixtures use camelCase because the mocked `parseWebhook`
// skips the SDK's snake_case→camelCase normalisation. The handler
// accesses fields by camelCase (matching its `PolarSubscriptionData`
// interface), so the mock returns what the handler expects to see.
function subscriptionCreatedPayload(opts: {
  subscriptionId: string;
  customerId: string;
  externalId: string | null;
  status?: string;
  cancelAtPeriodEnd?: boolean;
  currentPeriodEnd?: Date;
}) {
  return {
    type: "subscription.created",
    timestamp: new Date().toISOString(),
    data: {
      id: opts.subscriptionId,
      status: opts.status ?? "active",
      currentPeriodEnd: (
        opts.currentPeriodEnd ?? new Date(Date.now() + 30 * 24 * 3600 * 1000)
      ).toISOString(),
      cancelAtPeriodEnd: opts.cancelAtPeriodEnd ?? false,
      canceledAt: null,
      customerId: opts.customerId,
      customer: {
        id: opts.customerId,
        externalId: opts.externalId,
        email: "buyer@example.test",
      },
    },
  };
}

function subscriptionCanceledPayload(opts: {
  subscriptionId: string;
  customerId: string;
  externalId: string;
}) {
  const created = subscriptionCreatedPayload(opts);
  return {
    ...created,
    type: "subscription.canceled",
    data: {
      ...created.data,
      status: "canceled",
      canceledAt: new Date().toISOString(),
    },
  };
}

// ─── Signature verification ─────────────────────────────────────────────────

describe("POST /api/billing/webhook — signature verification", () => {
  it("401 on invalid signature", async () => {
    const payload = subscriptionCreatedPayload({
      subscriptionId: "sub_x",
      customerId: "cus_x",
      externalId: "user_x",
    });
    const res = await app.handle(
      new Request(`${APP_URL}/api/billing/webhook`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "webhook-id": "msg_invalid",
          "webhook-timestamp": String(Math.floor(Date.now() / 1000)),
          "webhook-signature": "v1,not_a_real_signature",
        },
        body: JSON.stringify(payload),
      }),
    );
    expect(res.status).toBe(401);
  });

  it("400 when webhook-id header is missing", async () => {
    const payload = subscriptionCreatedPayload({
      subscriptionId: "sub_x",
      customerId: "cus_x",
      externalId: "user_x",
    });
    const signed = signEvent(payload);
    delete signed.headers["webhook-id"];
    const res = await app.handle(
      new Request(`${APP_URL}/api/billing/webhook`, {
        method: "POST",
        headers: signed.headers,
        body: signed.body,
      }),
    );
    expect(res.status).toBe(400);
  });
});

// ─── subscription.created ────────────────────────────────────────────────────

describe("POST /api/billing/webhook — subscription.created", () => {
  it("sets users.tier='pro', users.polar_customer_id, and inserts subscriptions row", async () => {
    const { user } = await createAuthedUser();

    const signed = signEvent(
      subscriptionCreatedPayload({
        subscriptionId: "sub_abc",
        customerId: "cus_abc",
        externalId: user.id,
      }),
    );

    const res = await app.handle(
      new Request(`${APP_URL}/api/billing/webhook`, {
        method: "POST",
        headers: signed.headers,
        body: signed.body,
      }),
    );
    expect(res.status).toBe(200);

    const [updated] = await db.select().from(users).where(eq(users.id, user.id));
    expect(updated.tier).toBe("pro");
    expect(updated.polarCustomerId).toBe("cus_abc");

    const [sub] = await db
      .select()
      .from(subscriptions)
      .where(eq(subscriptions.polarSubscriptionId, "sub_abc"));
    expect(sub.userId).toBe(user.id);
    expect(sub.status).toBe("active");
    expect(sub.cancelAtPeriodEnd).toBe(false);
    expect(sub.canceledAt).toBeNull();
  });

  it("audits the event in billing_events", async () => {
    const { user } = await createAuthedUser();
    const signed = signEvent(
      subscriptionCreatedPayload({
        subscriptionId: "sub_audit",
        customerId: "cus_audit",
        externalId: user.id,
      }),
      "msg_audit_1",
    );

    await app.handle(
      new Request(`${APP_URL}/api/billing/webhook`, {
        method: "POST",
        headers: signed.headers,
        body: signed.body,
      }),
    );

    const [row] = await db
      .select()
      .from(billingEvents)
      .where(eq(billingEvents.polarEventId, "msg_audit_1"));
    expect(row.polarEventType).toBe("subscription.created");
    expect(row.processedAt).not.toBeNull();
    expect(row.error).toBeNull();
  });

  it("unknown externalId is audited but no user row mutates", async () => {
    const signed = signEvent(
      subscriptionCreatedPayload({
        subscriptionId: "sub_unknown",
        customerId: "cus_unknown",
        externalId: "user_never_existed",
      }),
      "msg_unknown_1",
    );

    const res = await app.handle(
      new Request(`${APP_URL}/api/billing/webhook`, {
        method: "POST",
        headers: signed.headers,
        body: signed.body,
      }),
    );
    expect(res.status).toBe(200);

    const [row] = await db
      .select()
      .from(billingEvents)
      .where(eq(billingEvents.polarEventId, "msg_unknown_1"));
    expect(row.processedAt).not.toBeNull();
    expect(row.error).toContain("user not found");
  });
});

// ─── subscription.canceled ───────────────────────────────────────────────────

describe("POST /api/billing/webhook — subscription.canceled", () => {
  it("flips users.tier to 'free' and sets canceled_at on the subscription", async () => {
    const { user } = await createAuthedUser();

    // First create the subscription.
    const created = signEvent(
      subscriptionCreatedPayload({
        subscriptionId: "sub_to_cancel",
        customerId: "cus_to_cancel",
        externalId: user.id,
      }),
      "msg_created_2",
    );
    await app.handle(
      new Request(`${APP_URL}/api/billing/webhook`, {
        method: "POST",
        headers: created.headers,
        body: created.body,
      }),
    );

    // Then cancel it.
    const canceled = signEvent(
      subscriptionCanceledPayload({
        subscriptionId: "sub_to_cancel",
        customerId: "cus_to_cancel",
        externalId: user.id,
      }),
      "msg_canceled_2",
    );
    const res = await app.handle(
      new Request(`${APP_URL}/api/billing/webhook`, {
        method: "POST",
        headers: canceled.headers,
        body: canceled.body,
      }),
    );
    expect(res.status).toBe(200);

    const [updatedUser] = await db.select().from(users).where(eq(users.id, user.id));
    expect(updatedUser.tier).toBe("free");

    const [sub] = await db
      .select()
      .from(subscriptions)
      .where(eq(subscriptions.polarSubscriptionId, "sub_to_cancel"));
    expect(sub.status).toBe("canceled");
    expect(sub.canceledAt).not.toBeNull();
  });
});

// ─── Idempotency ─────────────────────────────────────────────────────────────

describe("POST /api/billing/webhook — idempotent delivery", () => {
  it("second delivery of the same webhook-id is a no-op", async () => {
    const { user } = await createAuthedUser();
    const signed = signEvent(
      subscriptionCreatedPayload({
        subscriptionId: "sub_dup",
        customerId: "cus_dup",
        externalId: user.id,
      }),
      "msg_dup_3",
    );

    const first = await app.handle(
      new Request(`${APP_URL}/api/billing/webhook`, {
        method: "POST",
        headers: signed.headers,
        body: signed.body,
      }),
    );
    expect(first.status).toBe(200);
    const firstBody = (await first.json()) as { ok: boolean; deduplicated?: boolean };
    expect(firstBody.deduplicated).toBeUndefined();

    const second = await app.handle(
      new Request(`${APP_URL}/api/billing/webhook`, {
        method: "POST",
        headers: signed.headers,
        body: signed.body,
      }),
    );
    expect(second.status).toBe(200);
    const secondBody = (await second.json()) as { ok: boolean; deduplicated?: boolean };
    expect(secondBody.deduplicated).toBe(true);

    // Only one subscription row should exist for that polar_subscription_id
    // (the UNIQUE on polar_subscription_id catches it anyway, but the
    // billing_events dedup keeps us from even reaching the handler).
    const rows = await db
      .select()
      .from(subscriptions)
      .where(eq(subscriptions.polarSubscriptionId, "sub_dup"));
    expect(rows).toHaveLength(1);

    // And only one billing_events row.
    const eventRows = await db
      .select()
      .from(billingEvents)
      .where(eq(billingEvents.polarEventId, "msg_dup_3"));
    expect(eventRows).toHaveLength(1);
  });
});

describe("POST /api/billing/webhook — retry after a failed delivery", () => {
  it("re-runs a delivery whose handler failed instead of deduplicating it", async () => {
    // A cancel for a user that does not exist yet violates the FK on
    // subscriptions.user_id, so the handler throws on the first delivery.
    const userId = "retry-user-0000000001";
    const signed = signEvent(
      subscriptionCanceledPayload({
        subscriptionId: "sub_retry",
        customerId: "cus_retry",
        externalId: userId,
      }),
      "msg_retry_1",
    );
    const deliver = () =>
      app.handle(
        new Request(`${APP_URL}/api/billing/webhook`, {
          method: "POST",
          headers: signed.headers,
          body: signed.body,
        }),
      );

    const first = await deliver();
    expect(first.status).toBe(500);
    const [failed] = await db
      .select()
      .from(billingEvents)
      .where(eq(billingEvents.polarEventId, "msg_retry_1"));
    expect(failed?.processedAt).toBeNull();
    expect(failed?.error).not.toBeNull();

    // The transient cause clears; Polar redelivers with the same webhook-id.
    await db.insert(users).values({ id: userId, email: "retry@tessil.test", tier: "pro" });
    const second = await deliver();
    expect(second.status).toBe(200);
    const body = (await second.json()) as { ok: boolean; deduplicated?: boolean };
    expect(body.deduplicated).toBeUndefined();

    const [user] = await db.select().from(users).where(eq(users.id, userId));
    expect(user?.tier).toBe("free");
    const eventRows = await db
      .select()
      .from(billingEvents)
      .where(eq(billingEvents.polarEventId, "msg_retry_1"));
    expect(eventRows).toHaveLength(1);
    expect(eventRows[0]?.processedAt).not.toBeNull();
    expect(eventRows[0]?.error).toBeNull();

    // Once it has been applied, a further delivery is a true duplicate.
    const third = await deliver();
    expect(((await third.json()) as { deduplicated?: boolean }).deduplicated).toBe(true);
  });
});

// ─── Auth gates on checkout + portal ─────────────────────────────────────────

describe("POST /api/billing/checkout — auth gate", () => {
  it("401 when not authenticated", async () => {
    const res = await app.handle(
      new Request(`${APP_URL}/api/billing/checkout`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Origin: APP_URL },
        body: JSON.stringify({ cycle: "monthly" }),
      }),
    );
    expect(res.status).toBe(401);
  });
});

describe("POST /api/billing/portal — auth + customer gate", () => {
  it("401 when not authenticated", async () => {
    const res = await app.handle(
      new Request(`${APP_URL}/api/billing/portal`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Origin: APP_URL },
      }),
    );
    expect(res.status).toBe(401);
  });

  it("404 when user has no polar_customer_id", async () => {
    const { cookie } = await createAuthedUser();
    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/billing/portal`, { method: "POST" }),
    );
    expect(res.status).toBe(404);
  });
});
