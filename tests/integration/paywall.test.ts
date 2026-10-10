// Pay-to-send gate: with PAYWALL_ENABLED, a transfer needs an active
// subscription or a paid, unused single-transfer pass.
//
// Verifies:
//   - Off: nothing changes, and a stray passToken is ignored.
//   - On: anonymous and free-account senders get 402 without a pass.
//   - A pass must be paid (as reported by Polar) before it opens the gate.
//   - A pass lifts the transfer to the paid caps (expiry, file size).
//   - The pass is spent on /complete, not on create, so a failed upload
//     can be retried, and only one transfer per pass can ever complete.
//   - Completing clears the transfer's pointer to the pass.

import { afterAll, beforeAll, beforeEach, describe, expect, it, mock } from "bun:test";
import { eq } from "drizzle-orm";

// Polar is replaced wholesale: checkouts are handed out from a counter
// and "paid" is whatever the test says it is.
const paidCheckouts = new Set<string>();
let checkoutCounter = 0;
mock.module("../../src/services/polar.service", () => ({
  createPassCheckout: async () => {
    const checkoutId = `chk_test_${++checkoutCounter}`;
    return { url: `https://polar.test.invalid/${checkoutId}`, checkoutId };
  },
  isPassCheckoutPaid: async (checkoutId: string) => paidCheckouts.has(checkoutId),
  createProCheckout: async () => ({ url: "https://polar.test.invalid/pro", checkoutId: "chk_pro" }),
  createPortalSession: async () => ({ url: "https://polar.test.invalid/portal" }),
  cancelSubscriptionImmediately: async () => undefined,
  parseWebhook: () => {
    throw new Error("parseWebhook not exercised in paywall tests");
  },
  WebhookVerificationError: class extends Error {},
}));

import { createApp } from "../../src/app";
import { env } from "../../src/config/env";
import { db } from "../../src/db";
import { transferPasses, transfers, users } from "../../src/db/schema";
import { createFile } from "../../src/services/file.service";
import { cleanupUnpaidPasses, voidPassByCheckout } from "../../src/services/pass.service";
import { resetRateLimits } from "../../src/services/ratelimit.service";
import { authedRequest, createAuthedUser } from "../helpers/auth";
import { ensureMigrations, resetDb } from "../helpers/db";

const APP_URL = process.env.APP_URL!;
const ORIGIN_HEADER = { Origin: APP_URL, "Content-Type": "application/json" };
const GB = 1024 * 1024 * 1024;

let app: ReturnType<typeof createApp>;

function post(path: string, body: object = {}): Request {
  return new Request(`${APP_URL}${path}`, {
    method: "POST",
    headers: ORIGIN_HEADER,
    body: JSON.stringify(body),
  });
}

async function buyPass(pay = true): Promise<string> {
  const res = await app.handle(post("/api/billing/pass/checkout"));
  expect(res.status).toBe(200);
  const { token } = (await res.json()) as { token: string; url: string };
  if (pay) paidCheckouts.add(`chk_test_${checkoutCounter}`);
  return token;
}

async function createTransferWith(body: object): Promise<Response> {
  return app.handle(post("/api/upload/create-transfer", body));
}

async function seedFile(transferId: string, size = 1024) {
  return createFile({
    transferId,
    encryptedName: "x".repeat(32),
    encryptedNameIv: "y".repeat(24),
    fileIv: "z".repeat(24),
    size,
    mimeType: "application/octet-stream",
  });
}

beforeAll(async () => {
  await ensureMigrations();
  app = createApp();
});

beforeEach(async () => {
  await resetDb();
  await resetRateLimits();
  paidCheckouts.clear();
  env.PAYWALL_ENABLED = true;
});

afterAll(async () => {
  env.PAYWALL_ENABLED = false;
  await resetDb();
});

describe("paywall off", () => {
  it("anonymous transfers work and a stray passToken is ignored", async () => {
    env.PAYWALL_ENABLED = false;
    const res = await createTransferWith({ expiresInHours: 24, passToken: "x".repeat(43) });
    expect(res.status).toBe(200);
    const { transferId } = (await res.json()) as { transferId: string };
    const [row] = await db.select().from(transfers).where(eq(transfers.id, transferId));
    expect(row?.passId).toBeNull();
  });

  it("entitlement reports everyone as entitled", async () => {
    env.PAYWALL_ENABLED = false;
    const res = await app.handle(new Request(`${APP_URL}/api/billing/entitlement`));
    const body = (await res.json()) as { paywall: boolean; entitled: boolean };
    expect(body).toMatchObject({ paywall: false, entitled: true });
  });
});

describe("paywall on: who gets through", () => {
  it("anonymous without a pass gets 402", async () => {
    const res = await createTransferWith({ expiresInHours: 24 });
    expect(res.status).toBe(402);
    const body = (await res.json()) as { code: string; upgradeUrl: string };
    expect(body.code).toBe("payment_required");
    expect(body.upgradeUrl).toBe("/pricing");
  });

  it("a free account without a pass gets 402", async () => {
    const { cookie } = await createAuthedUser();
    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/upload/create-transfer`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ expiresInHours: 24 }),
      }),
    );
    expect(res.status).toBe(402);
  });

  it("a subscriber gets through with no pass", async () => {
    const { user, cookie } = await createAuthedUser();
    await db.update(users).set({ tier: "pro" }).where(eq(users.id, user.id));
    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/upload/create-transfer`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ expiresInHours: 720 }),
      }),
    );
    expect(res.status).toBe(200);
  });

  it("an unknown token gets 402", async () => {
    const res = await createTransferWith({ expiresInHours: 24, passToken: "n".repeat(43) });
    expect(res.status).toBe(402);
  });

  it("an unpaid pass gets 402, and opens the gate once Polar reports it paid", async () => {
    const token = await buyPass(false);
    const before = await createTransferWith({ expiresInHours: 24, passToken: token });
    expect(before.status).toBe(402);

    paidCheckouts.add(`chk_test_${checkoutCounter}`);
    const after = await createTransferWith({ expiresInHours: 24, passToken: token });
    expect(after.status).toBe(200);
  });

  it("entitlement is false for anonymous and true for a subscriber", async () => {
    const anon = await app.handle(new Request(`${APP_URL}/api/billing/entitlement`));
    const anonBody = (await anon.json()) as {
      paywall: boolean;
      entitled: boolean;
      paidCaps: { maxTransferSize: number; allowedExpiryHours: number[] };
    };
    expect(anonBody.paywall).toBe(true);
    expect(anonBody.entitled).toBe(false);
    expect(anonBody.paidCaps.maxTransferSize).toBe(2 * GB);
    expect(anonBody.paidCaps.allowedExpiryHours).toContain(720);

    const { user, cookie } = await createAuthedUser();
    await db.update(users).set({ tier: "pro" }).where(eq(users.id, user.id));
    const pro = await app.handle(authedRequest(cookie, `${APP_URL}/api/billing/entitlement`));
    expect(((await pro.json()) as { entitled: boolean }).entitled).toBe(true);
  });
});

describe("paywall on: what a pass buys", () => {
  it("lifts expiry and file size to the paid caps", async () => {
    const token = await buyPass();
    const res = await createTransferWith({ expiresInHours: 720, passToken: token });
    expect(res.status).toBe(200);
    const { transferId } = (await res.json()) as { transferId: string };

    // 1.5 GB is three times the anonymous per-file cap.
    const init = await app.handle(
      post("/api/upload/init-multipart", {
        transferId,
        contentType: "application/octet-stream",
        encryptedName: "x".repeat(32),
        encryptedNameIv: "y".repeat(24),
        fileIv: "z".repeat(24),
        size: 1.5 * GB,
      }),
    );
    expect(init.status).toBe(200);
  });

  it("status reports unpaid, then paid, then used", async () => {
    const token = await buyPass(false);
    const status = async () =>
      ((await (await app.handle(post("/api/billing/pass/status", { token }))).json()) as {
        state: string;
      }).state;

    expect(await status()).toBe("unpaid");
    paidCheckouts.add(`chk_test_${checkoutCounter}`);
    expect(await status()).toBe("paid");

    const created = await createTransferWith({ expiresInHours: 24, passToken: token });
    const { transferId } = (await created.json()) as { transferId: string };
    await seedFile(transferId);
    await app.handle(post("/api/upload/complete", { transferId }));
    expect(await status()).toBe("used");
  });

  it("stores only a hash of the token", async () => {
    const token = await buyPass();
    const [row] = await db.select().from(transferPasses);
    expect(row?.tokenHash).not.toBe(token);
    expect(row?.tokenHash).toHaveLength(64);
  });
});

describe("paywall on: spending a pass", () => {
  it("is spent on complete, which also unlinks it from the transfer", async () => {
    const token = await buyPass();
    const created = await createTransferWith({ expiresInHours: 24, passToken: token });
    const { transferId } = (await created.json()) as { transferId: string };

    const [open] = await db.select().from(transfers).where(eq(transfers.id, transferId));
    expect(open?.passId).not.toBeNull();
    const [unspent] = await db.select().from(transferPasses);
    expect(unspent?.consumedAt).toBeNull();

    await seedFile(transferId);
    const done = await app.handle(post("/api/upload/complete", { transferId }));
    expect(done.status).toBe(200);

    const [closed] = await db.select().from(transfers).where(eq(transfers.id, transferId));
    expect(closed?.isCompleted).toBe(true);
    expect(closed?.passId).toBeNull();
    const [spent] = await db.select().from(transferPasses);
    expect(spent?.consumedAt).not.toBeNull();

    const again = await createTransferWith({ expiresInHours: 24, passToken: token });
    expect(again.status).toBe(402);
    expect(((await again.json()) as { code: string }).code).toBe("pass_already_used");
  });

  it("survives a failed upload: the same pass can start a second transfer", async () => {
    const token = await buyPass();
    const first = await createTransferWith({ expiresInHours: 24, passToken: token });
    expect(first.status).toBe(200);
    const retry = await createTransferWith({ expiresInHours: 24, passToken: token });
    expect(retry.status).toBe(200);
  });

  it("lets only one of two open transfers complete", async () => {
    const token = await buyPass();
    const a = (await (await createTransferWith({ expiresInHours: 24, passToken: token })).json()) as {
      transferId: string;
    };
    const b = (await (await createTransferWith({ expiresInHours: 24, passToken: token })).json()) as {
      transferId: string;
    };
    await seedFile(a.transferId);
    await seedFile(b.transferId);

    const first = await app.handle(post("/api/upload/complete", { transferId: a.transferId }));
    expect(first.status).toBe(200);
    const second = await app.handle(post("/api/upload/complete", { transferId: b.transferId }));
    expect(second.status).toBe(402);
    expect(((await second.json()) as { code: string }).code).toBe("pass_already_used");

    const [loser] = await db.select().from(transfers).where(eq(transfers.id, b.transferId));
    expect(loser?.isCompleted).toBe(false);
  });

  it("caps the number of unfinished transfers on one pass", async () => {
    const token = await buyPass();
    for (let i = 0; i < 3; i++) {
      const ok = await createTransferWith({ expiresInHours: 24, passToken: token });
      expect(ok.status).toBe(200);
    }
    const fourth = await createTransferWith({ expiresInHours: 24, passToken: token });
    expect(fourth.status).toBe(429);
  });
});

describe("paywall on: every upload route holds the gate", () => {
  const fileBody = (transferId: string) => ({
    transferId,
    contentType: "application/octet-stream",
    encryptedName: "x".repeat(32),
    encryptedNameIv: "y".repeat(24),
    fileIv: "z".repeat(24),
    size: 1024,
  });

  it("a transfer created before the paywall cannot take files or complete", async () => {
    env.PAYWALL_ENABLED = false;
    const created = await createTransferWith({ expiresInHours: 24 });
    const { transferId } = (await created.json()) as { transferId: string };
    await seedFile(transferId);
    env.PAYWALL_ENABLED = true;

    const init = await app.handle(post("/api/upload/init-multipart", fileBody(transferId)));
    expect(init.status).toBe(402);
    const done = await app.handle(post("/api/upload/complete", { transferId }));
    expect(done.status).toBe(402);
  });

  it("a completed transfer takes no more files", async () => {
    const token = await buyPass();
    const created = await createTransferWith({ expiresInHours: 24, passToken: token });
    const { transferId } = (await created.json()) as { transferId: string };
    await seedFile(transferId);
    await app.handle(post("/api/upload/complete", { transferId }));

    const init = await app.handle(post("/api/upload/init-multipart", fileBody(transferId)));
    expect(init.status).toBe(409);
    const again = await app.handle(post("/api/upload/complete", { transferId }));
    expect(again.status).toBe(409);
  });

  it("a sibling transfer stops taking files once the pass is spent", async () => {
    const token = await buyPass();
    const a = (await (await createTransferWith({ expiresInHours: 24, passToken: token })).json()) as {
      transferId: string;
    };
    const b = (await (await createTransferWith({ expiresInHours: 24, passToken: token })).json()) as {
      transferId: string;
    };
    await seedFile(a.transferId);
    await app.handle(post("/api/upload/complete", { transferId: a.transferId }));

    const init = await app.handle(post("/api/upload/init-multipart", fileBody(b.transferId)));
    expect(init.status).toBe(402);
  });

  it("a lapsed subscriber cannot finish a transfer started while subscribed", async () => {
    const { user, cookie } = await createAuthedUser();
    await db.update(users).set({ tier: "pro" }).where(eq(users.id, user.id));
    const authedPost = (path: string, body: object) =>
      authedRequest(cookie, `${APP_URL}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
    const created = await app.handle(authedPost("/api/upload/create-transfer", { expiresInHours: 24 }));
    const { transferId } = (await created.json()) as { transferId: string };
    await seedFile(transferId);

    await db.update(users).set({ tier: "free" }).where(eq(users.id, user.id));
    const done = await app.handle(authedPost("/api/upload/complete", { transferId }));
    expect(done.status).toBe(402);
  });

  it("a refund voids an unused pass and leaves a spent one alone", async () => {
    const unused = await buyPass();
    const unusedCheckout = `chk_test_${checkoutCounter}`;
    expect(await voidPassByCheckout(unusedCheckout)).toBe(true);
    const res = await createTransferWith({ expiresInHours: 24, passToken: unused });
    expect(res.status).toBe(402);

    const spent = await buyPass();
    const spentCheckout = `chk_test_${checkoutCounter}`;
    const created = await createTransferWith({ expiresInHours: 24, passToken: spent });
    const { transferId } = (await created.json()) as { transferId: string };
    await seedFile(transferId);
    await app.handle(post("/api/upload/complete", { transferId }));
    expect(await voidPassByCheckout(spentCheckout)).toBe(false);
  });
});

describe("unpaid pass sweep", () => {
  it("drops stale unpaid passes and keeps paid and fresh ones", async () => {
    const stale = new Date(Date.now() - 25 * 60 * 60 * 1000);
    await db.insert(transferPasses).values([
      { id: "stale-unpaid-0000000a", tokenHash: "a".repeat(64), polarCheckoutId: "c1", createdAt: stale },
      { id: "stale-paid-000000000b", tokenHash: "b".repeat(64), polarCheckoutId: "c2", createdAt: stale, paidAt: stale },
      { id: "fresh-unpaid-0000000c", tokenHash: "c".repeat(64), polarCheckoutId: "c3" },
    ]);
    expect(await cleanupUnpaidPasses()).toBe(1);
    const left = await db.select({ id: transferPasses.id }).from(transferPasses);
    expect(left.map((r) => r.id).sort()).toEqual(["fresh-unpaid-0000000c", "stale-paid-000000000b"]);
  });
});
