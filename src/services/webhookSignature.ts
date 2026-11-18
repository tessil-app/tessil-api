// Verifies a Polar webhook under either of the two ways Polar has signed
// them. A secret generated since 8 September 2026 is a Standard Webhooks
// secret (`whsec_` and a base64 key). An older one is keyed by the bytes
// of the secret string itself. Polar sends one signature either way, so
// which applies depends only on when the secret was made; both are tried.
// https://polar.sh/docs/integrate/webhooks/delivery

import { Webhook, WebhookVerificationError } from "standardwebhooks";

export { WebhookVerificationError };

type Headers = Record<string, string>;

function standardKey(secret: string): Webhook | null {
  try {
    return new Webhook(secret);
  } catch {
    // Not base64 after the prefix: an older secret, which has no such form.
    return null;
  }
}

function legacyKey(secret: string): Webhook {
  return new Webhook(Buffer.from(secret, "utf-8").toString("base64"));
}

/** Throws WebhookVerificationError unless the body was signed with this secret, new way or old. */
export function verifyWebhookSignature(body: string, headers: Headers, secret: string): void {
  const standard = standardKey(secret);
  if (standard) {
    try {
      standard.verify(body, headers);
      return;
    } catch (err) {
      if (!(err instanceof WebhookVerificationError)) throw err;
      // Fall through: an older secret can happen to be valid base64 too.
    }
  }
  legacyKey(secret).verify(body, headers);
}

/**
 * The same delivery, signed again the old way under a key made for this
 * call. The SDK's parser only comes with its own verification, which knows
 * the old way alone; this lets a body already verified here go through it.
 */
export function resignForSdk(body: string, headers: Headers): { headers: Headers; secret: string } {
  const secret = crypto.randomUUID();
  const id = headers["webhook-id"] ?? "";
  const seconds = Number(headers["webhook-timestamp"]);
  const signature = legacyKey(secret).sign(id, new Date(seconds * 1000), body);
  return {
    secret,
    headers: { "webhook-id": id, "webhook-timestamp": String(seconds), "webhook-signature": signature },
  };
}
