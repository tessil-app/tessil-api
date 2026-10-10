// Polar SDK wrapper. The browser never talks to Polar directly — all
// calls (checkout / portal / webhook verification) go through these
// helpers. Webhook signatures use the standard-webhooks spec via
// `validateEvent`.

import { Polar } from "@polar-sh/sdk";
import { validateEvent, WebhookVerificationError } from "@polar-sh/sdk/webhooks";
import { env } from "../config/env";
import type { User } from "../db/schema";

let cachedClient: Polar | null = null;

// Lazy init so test environments without an access token can still
// import this module.
function client(): Polar {
  if (!cachedClient) {
    if (!env.POLAR_ACCESS_TOKEN) {
      throw new Error(
        "POLAR_ACCESS_TOKEN is not set. Polar API calls are disabled until it's configured.",
      );
    }
    cachedClient = new Polar({
      accessToken: env.POLAR_ACCESS_TOKEN,
      server: env.POLAR_SERVER,
    });
  }
  return cachedClient;
}

export type BillingCycle = "monthly" | "annual";

/**
 * Create a checkout session for the Pro plan. The returned `url` is
 * Polar-hosted; the frontend redirects the user there. We set
 * `externalCustomerId` to our user ID so subsequent webhook events
 * can be routed back to the right user row.
 */
export async function createProCheckout(
  user: User,
  cycle: BillingCycle,
): Promise<{ url: string; checkoutId: string }> {
  const productId =
    cycle === "monthly" ? env.POLAR_PRODUCT_ID_MONTHLY : env.POLAR_PRODUCT_ID_ANNUAL;
  if (!productId) {
    throw new Error(
      `POLAR_PRODUCT_ID_${cycle.toUpperCase()} is not set — billing cycle "${cycle}" cannot be checked out.`,
    );
  }

  const successUrl = env.POLAR_SUCCESS_URL || `${env.APP_URL.replace(/\/$/, "")}/thanks`;

  const checkout = await client().checkouts.create({
    products: [productId],
    externalCustomerId: user.id,
    customerEmail: user.email,
    successUrl,
  });

  return { url: checkout.url, checkoutId: checkout.id };
}

/**
 * Create a checkout for the one-time single-transfer pass. No customer
 * is attached: the buyer may be anonymous, and we never learn who paid.
 */
export async function createPassCheckout(): Promise<{ url: string; checkoutId: string }> {
  if (!env.POLAR_PRODUCT_ID_PASS) {
    throw new Error("POLAR_PRODUCT_ID_PASS is not set. Passes cannot be checked out.");
  }
  const checkout = await client().checkouts.create({
    products: [env.POLAR_PRODUCT_ID_PASS],
    successUrl: `${env.APP_URL.replace(/\/$/, "")}/thanks`,
  });
  return { url: checkout.url, checkoutId: checkout.id };
}

/** True once Polar reports the pass checkout as paid. */
export async function isPassCheckoutPaid(checkoutId: string): Promise<boolean> {
  const checkout = await client().checkouts.get({ id: checkoutId });
  return checkout.status === "succeeded" && checkout.productId === env.POLAR_PRODUCT_ID_PASS;
}

/**
 * Create a customer portal session URL for an existing Polar customer.
 * The user lands on Polar's hosted portal to manage their subscription.
 */
export async function createPortalSession(customerId: string): Promise<{ url: string }> {
  const session = await client().customerSessions.create({ customerId });
  return { url: session.customerPortalUrl };
}

/**
 * Cancel a subscription immediately (no proration). Used by the
 * account-erasure flow — Polar handles the invoice/refund logic.
 */
export async function cancelSubscriptionImmediately(
  polarSubscriptionId: string,
): Promise<void> {
  await client().subscriptions.revoke({ id: polarSubscriptionId });
}

/**
 * Parse + verify an inbound webhook payload. Throws
 * `WebhookVerificationError` on signature mismatch. Header keys are
 * case-insensitive per the standard-webhooks spec.
 */
export function parseWebhook(
  body: string,
  headers: Record<string, string>,
): ReturnType<typeof validateEvent> {
  if (!env.POLAR_WEBHOOK_SECRET) {
    throw new Error(
      "POLAR_WEBHOOK_SECRET is not set — refusing to process Polar webhooks without verification.",
    );
  }
  return validateEvent(body, headers, env.POLAR_WEBHOOK_SECRET);
}

export { WebhookVerificationError };
