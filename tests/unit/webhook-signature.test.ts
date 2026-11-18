// Polar signs webhooks one of two ways, depending on when the endpoint's
// secret was made. Both must verify; anything else must not.

import { describe, expect, it } from "bun:test";
import { Webhook } from "standardwebhooks";
import { resignForSdk, verifyWebhookSignature, WebhookVerificationError } from "../../src/services/webhookSignature";

const BODY = JSON.stringify({ type: "subscription.active", data: { id: "sub_1" } });
const ID = "msg_2Z9";

function signed(key: Webhook, body = BODY, at = new Date()) {
  return {
    "webhook-id": ID,
    "webhook-timestamp": String(Math.floor(at.getTime() / 1000)),
    "webhook-signature": key.sign(ID, at, body),
  };
}

describe("a Polar webhook signature", () => {
  // As Polar issues them since 8 September 2026: the key is the base64 after the prefix.
  const NEW_SECRET = `whsec_${Buffer.from("thirty-two bytes of signing key!").toString("base64")}`;
  // As Polar issued them before: the key is the bytes of the whole string.
  const OLD_SECRET = "polar_whs_Qm9vdHN0cmFwU2VjcmV0MTIzNDU2";

  it("verifies under a secret made the new way", () => {
    const headers = signed(new Webhook(NEW_SECRET));
    expect(() => verifyWebhookSignature(BODY, headers, NEW_SECRET)).not.toThrow();
  });

  it("verifies under a secret made the old way", () => {
    const headers = signed(new Webhook(Buffer.from(OLD_SECRET, "utf-8").toString("base64")));
    expect(() => verifyWebhookSignature(BODY, headers, OLD_SECRET)).not.toThrow();
  });

  it("verifies an old secret that happens to carry the new prefix", () => {
    const secret = "whsec_dGVzdHdlYmhvb2tzZWNyZXQ";
    const headers = signed(new Webhook(Buffer.from(secret, "utf-8").toString("base64")));
    expect(() => verifyWebhookSignature(BODY, headers, secret)).not.toThrow();
  });

  it("refuses another secret, a changed body and a missing signature", () => {
    const headers = signed(new Webhook(NEW_SECRET));
    const other = `whsec_${Buffer.from("a different signing key entirely").toString("base64")}`;
    expect(() => verifyWebhookSignature(BODY, headers, other)).toThrow(WebhookVerificationError);
    expect(() => verifyWebhookSignature(BODY, headers, OLD_SECRET)).toThrow(WebhookVerificationError);
    expect(() => verifyWebhookSignature(BODY.replace("sub_1", "sub_2"), headers, NEW_SECRET)).toThrow(
      WebhookVerificationError,
    );
    expect(() => verifyWebhookSignature(BODY, { "webhook-id": ID }, NEW_SECRET)).toThrow(WebhookVerificationError);
  });

  it("refuses a delivery that is too old", () => {
    const headers = signed(new Webhook(NEW_SECRET), BODY, new Date(Date.now() - 3600_000));
    expect(() => verifyWebhookSignature(BODY, headers, NEW_SECRET)).toThrow(WebhookVerificationError);
  });

  it("signs a verified body again in the form the SDK's parser accepts", () => {
    const headers = signed(new Webhook(NEW_SECRET));
    const again = resignForSdk(BODY, headers);
    // What the SDK does with the secret it is given.
    const sdkKey = new Webhook(Buffer.from(again.secret, "utf-8").toString("base64"));
    expect(() => sdkKey.verify(BODY, again.headers)).not.toThrow();
    expect(again.headers["webhook-id"]).toBe(ID);
  });
});
