// Tier-aware caps and the /api/me/usage endpoint per ADR-0006.
//
// Verifies:
//   - Free/Anonymous expiry options stay capped at ≤72h (`expiresInHours`
//     ∉ [1,6,12,24,72] → 400 with `expiry_not_allowed_for_tier`).
//   - Pro accepts the longer-retention options (168h / 336h / 720h).
//   - `/api/me/usage` returns tier-resolved caps and the correct shape
//     for both Free and Pro.
//
// Volume-counter enforcement (the 2 GB vs 100 GB cap actually firing)
// shares Redis/memory state across the test process, so it's covered
// in the existing volume-limit tests rather than re-asserted here.

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import { eq } from "drizzle-orm";
import { createApp } from "../../src/app";
import { db } from "../../src/db";
import { transfers, users } from "../../src/db/schema";
import { createFile, createTransfer } from "../../src/services/file.service";
import { authedRequest, createAuthedUser } from "../helpers/auth";
import { ensureMigrations, resetDb } from "../helpers/db";
import { resetRateLimits } from "../../src/services/ratelimit.service";

const APP_URL = process.env.APP_URL!;
const ORIGIN_HEADER = { Origin: APP_URL, "Content-Type": "application/json" };

let app: ReturnType<typeof createApp>;

beforeAll(async () => {
  await ensureMigrations();
  app = createApp();
});

beforeEach(async () => {
  await resetDb();
  // The rate-limit store is process-global and survives resetDb, so
  // anonymous requests across the suite share one per-IP bucket and trip
  // the low anon daily cap (5). Clear it so each test starts fresh.
  await resetRateLimits();
});

afterAll(async () => {
  await resetDb();
});

function jsonBody<T extends object>(body: T): RequestInit {
  return { method: "POST", headers: ORIGIN_HEADER, body: JSON.stringify(body) };
}

const GB = 1024 * 1024 * 1024;

// ─── Expiry options per tier ─────────────────────────────────────────────────

describe("create-transfer — tier-aware expiry options", () => {
  it("anonymous request: 72h rejected (72h is Free-and-up)", async () => {
    // Anonymous caps step below Free everywhere (file size, daily count),
    // and expiry is no exception: anon tops out at 24h, 72h needs Free.
    const res = await app.handle(
      new Request(`${APP_URL}/api/upload/create-transfer`, jsonBody({ expiresInHours: 72 })),
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { code?: string; upgradeUrl?: string };
    expect(body.code).toBe("expiry_not_allowed_for_tier");
    expect(body.upgradeUrl).toBe("/pricing");
  });

  it("anonymous request: 24h allowed", async () => {
    const res = await app.handle(
      new Request(`${APP_URL}/api/upload/create-transfer`, jsonBody({ expiresInHours: 24 })),
    );
    expect(res.status).toBe(200);
  });

  it("anonymous request: 168h (7d) rejected with upgrade code", async () => {
    const res = await app.handle(
      new Request(`${APP_URL}/api/upload/create-transfer`, jsonBody({ expiresInHours: 168 })),
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string; code?: string; upgradeUrl?: string };
    expect(body.code).toBe("expiry_not_allowed_for_tier");
    expect(body.upgradeUrl).toBe("/pricing");
  });

  it("authed Free user: 168h (7d) rejected", async () => {
    const { cookie } = await createAuthedUser();
    const res = await app.handle(
      authedRequest(
        cookie,
        `${APP_URL}/api/upload/create-transfer`,
        jsonBody({ expiresInHours: 168 }),
      ),
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { code?: string };
    expect(body.code).toBe("expiry_not_allowed_for_tier");
  });

  it("authed Pro user: 168h (7d) accepted", async () => {
    const { user, cookie } = await createAuthedUser();
    await db.update(users).set({ tier: "pro" }).where(eq(users.id, user.id));

    const res = await app.handle(
      authedRequest(
        cookie,
        `${APP_URL}/api/upload/create-transfer`,
        jsonBody({ expiresInHours: 168 }),
      ),
    );
    expect(res.status).toBe(200);
  });

  it("authed Pro user: 720h (30d) accepted", async () => {
    const { user, cookie } = await createAuthedUser();
    await db.update(users).set({ tier: "pro" }).where(eq(users.id, user.id));

    const res = await app.handle(
      authedRequest(
        cookie,
        `${APP_URL}/api/upload/create-transfer`,
        jsonBody({ expiresInHours: 720 }),
      ),
    );
    expect(res.status).toBe(200);
  });

  it("authed Pro user: 999h (not in allow-list) rejected", async () => {
    const { user, cookie } = await createAuthedUser();
    await db.update(users).set({ tier: "pro" }).where(eq(users.id, user.id));

    const res = await app.handle(
      authedRequest(
        cookie,
        `${APP_URL}/api/upload/create-transfer`,
        jsonBody({ expiresInHours: 999 }),
      ),
    );
    expect(res.status).toBe(400);
  });

  it("unknown tier value falls back to Free caps (fail-closed)", async () => {
    const { user, cookie } = await createAuthedUser();
    await db.update(users).set({ tier: "garbage" }).where(eq(users.id, user.id));

    // 168h should be rejected because unknown tier resolves to Free.
    const res = await app.handle(
      authedRequest(
        cookie,
        `${APP_URL}/api/upload/create-transfer`,
        jsonBody({ expiresInHours: 168 }),
      ),
    );
    expect(res.status).toBe(400);
  });
});

// ─── /api/me/usage ───────────────────────────────────────────────────────────

interface UsageResponse {
  tier: string;
  storage: { usedBytes: number; quotaBytes: number } | null;
  monthlyVolume: { usedBytes: number; capBytes: number; resetAt: string };
  dailyTransfers: { used: number; cap: number; resetAt: string };
  caps: { maxFileSize: number; maxTransferSize: number; allowedExpiryHours: number[] };
}

describe("GET /api/me/usage", () => {
  it("401 when not authenticated", async () => {
    const res = await app.handle(new Request(`${APP_URL}/api/me/usage`));
    expect(res.status).toBe(401);
  });

  it("returns Free caps for a default user", async () => {
    const { cookie } = await createAuthedUser();
    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/me/usage`, { method: "GET" }),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as UsageResponse;

    expect(body.tier).toBe("free");
    expect(body.monthlyVolume.capBytes).toBe(2 * GB);
    expect(body.dailyTransfers.cap).toBe(20);
    expect(body.caps.maxFileSize).toBe(1 * GB);
    expect(body.caps.maxTransferSize).toBe(1 * GB);
    expect(body.caps.allowedExpiryHours).toEqual([1, 6, 12, 24, 72]);
    expect(body.storage).toBeNull();
  });

  it("returns Pro caps when tier='pro'", async () => {
    const { user, cookie } = await createAuthedUser();
    await db.update(users).set({ tier: "pro" }).where(eq(users.id, user.id));

    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/me/usage`, { method: "GET" }),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as UsageResponse;

    expect(body.tier).toBe("pro");
    expect(body.monthlyVolume.capBytes).toBe(100 * GB);
    expect(body.dailyTransfers.cap).toBe(100);
    expect(body.caps.maxFileSize).toBe(5 * GB);
    expect(body.caps.maxTransferSize).toBe(10 * GB);
    expect(body.caps.allowedExpiryHours).toContain(168);
    expect(body.caps.allowedExpiryHours).toContain(720);
    expect(body.caps.allowedExpiryHours).not.toContain(2160);
    expect(body.storage).toEqual({ usedBytes: 0, quotaBytes: 20 * GB });
  });

  it("returns the higher plan's storage and retention when tier='max'", async () => {
    const { user, cookie } = await createAuthedUser();
    await db.update(users).set({ tier: "max" }).where(eq(users.id, user.id));

    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/me/usage`, { method: "GET" }),
    );
    const body = (await res.json()) as UsageResponse;

    expect(body.tier).toBe("max");
    expect(body.storage).toEqual({ usedBytes: 0, quotaBytes: 100 * GB });
    expect(body.caps.maxFileSize).toBe(5 * GB);
    expect(body.caps.allowedExpiryHours).toContain(2160);
  });

  it("usedBytes and used start at non-negative integers", async () => {
    const { cookie } = await createAuthedUser();
    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/me/usage`, { method: "GET" }),
    );
    const body = (await res.json()) as UsageResponse;

    // The exact value depends on prior state in the shared limiter
    // (memory in tests; we don't reset between processes). The
    // contract is: non-negative integers, and reset timestamps in
    // the future.
    expect(body.monthlyVolume.usedBytes).toBeGreaterThanOrEqual(0);
    expect(body.dailyTransfers.used).toBeGreaterThanOrEqual(0);
    expect(new Date(body.monthlyVolume.resetAt).getTime()).toBeGreaterThan(Date.now());
    expect(new Date(body.dailyTransfers.resetAt).getTime()).toBeGreaterThan(Date.now());
  });
});

// ─── Storage quota on paid plans ─────────────────────────────────────────────

describe("storage quota", () => {
  const FILE_FIELDS = {
    contentType: "application/octet-stream",
    encryptedName: "x".repeat(32),
    encryptedNameIv: "y".repeat(24),
    fileIv: "z".repeat(24),
  };

  async function paidUser(tier = "pro") {
    const authed = await createAuthedUser();
    await db.update(users).set({ tier }).where(eq(users.id, authed.user.id));
    return authed;
  }

  async function newTransfer(cookie: string): Promise<string> {
    const res = await app.handle(
      authedRequest(cookie, `${APP_URL}/api/upload/create-transfer`, jsonBody({ expiresInHours: 24 })),
    );
    return ((await res.json()) as { transferId: string }).transferId;
  }

  function addFile(cookie: string, transferId: string, size: number) {
    return app.handle(
      authedRequest(cookie, `${APP_URL}/api/upload/init-multipart`, jsonBody({
        transferId,
        size,
        ...FILE_FIELDS,
      })),
    );
  }

  it("counts everything the account has stored and refuses what does not fit", async () => {
    const { user, cookie } = await paidUser();
    // 18 GB already stored across earlier transfers, out of 20.
    for (let i = 0; i < 6; i++) {
      const earlier = await createTransfer(24, undefined, undefined, user.id);
      await createFile({ transferId: earlier.id, size: 3 * GB, mimeType: null, encryptedName: "n", encryptedNameIv: "i", fileIv: "f" });
    }

    const transferId = await newTransfer(cookie);
    expect((await addFile(cookie, transferId, 1 * GB)).status).toBe(200);

    const full = await addFile(cookie, transferId, 2 * GB);
    expect(full.status).toBe(413);
    expect(((await full.json()) as { code: string }).code).toBe("storage_quota_exceeded");

    const usage = await app.handle(authedRequest(cookie, `${APP_URL}/api/me/usage`, { method: "GET" }));
    const body = (await usage.json()) as UsageResponse;
    expect(body.storage).toEqual({ usedBytes: 19 * GB, quotaBytes: 20 * GB });
  });

  it("frees the space as soon as the owner deletes a transfer", async () => {
    const { user, cookie } = await paidUser();
    const kept = [];
    for (let i = 0; i < 4; i++) {
      const earlier = await createTransfer(24, undefined, undefined, user.id);
      await createFile({ transferId: earlier.id, size: 5 * GB, mimeType: null, encryptedName: "n", encryptedNameIv: "i", fileIv: "f" });
      kept.push(earlier.id);
    }
    const transferId = await newTransfer(cookie);
    expect((await addFile(cookie, transferId, 1 * GB)).status).toBe(413);

    await db.update(transfers).set({ isDeleted: true }).where(eq(transfers.id, kept[0]));
    expect((await addFile(cookie, transferId, 1 * GB)).status).toBe(200);
  });

  it("does not let parallel uploads each claim the last of the space", async () => {
    const { user, cookie } = await paidUser();
    for (let i = 0; i < 3; i++) {
      const earlier = await createTransfer(24, undefined, undefined, user.id);
      await createFile({ transferId: earlier.id, size: 5 * GB, mimeType: null, encryptedName: "n", encryptedNameIv: "i", fileIv: "f" });
    }
    // 5 GB left. Six parallel 1 GB files across two transfers: five fit.
    const a = await newTransfer(cookie);
    const b = await newTransfer(cookie);
    const results = await Promise.all(
      [a, b, a, b, a, b].map((id) => addFile(cookie, id, 1 * GB)),
    );
    expect(results.filter((r) => r.status === 200)).toHaveLength(5);
    expect(results.filter((r) => r.status === 413)).toHaveLength(1);
  });

  it("gives the higher plan more room", async () => {
    const { user, cookie } = await paidUser("max");
    for (let i = 0; i < 5; i++) {
      const earlier = await createTransfer(24, undefined, undefined, user.id);
      await createFile({ transferId: earlier.id, size: 5 * GB, mimeType: null, encryptedName: "n", encryptedNameIv: "i", fileIv: "f" });
    }
    const transferId = await newTransfer(cookie);
    expect((await addFile(cookie, transferId, 5 * GB)).status).toBe(200);
  });

  // An ownerless transfer is not in anyone's quota, so it must not get
  // a paid plan's size caps just because a paying user is signed in.
  it("gives a paying user anonymous limits on an ownerless transfer", async () => {
    const { cookie } = await paidUser();
    const anonymous = await createTransfer(1);

    const tooBig = await addFile(cookie, anonymous.id, 1 * GB);
    expect(tooBig.status).toBe(400);
    expect(((await tooBig.json()) as { code: string }).code).toBe("file_too_large");

    expect((await addFile(cookie, anonymous.id, 1024)).status).toBe(200);
  });

  it("does not apply to free accounts", async () => {
    const { cookie } = await createAuthedUser();
    const transferId = await newTransfer(cookie);
    expect((await addFile(cookie, transferId, 1024)).status).toBe(200);
  });
});
