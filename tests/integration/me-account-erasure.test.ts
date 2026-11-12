// Account erasure invariants. See docs/audit/23-right-to-erasure.md §11.
//
// Covers: typed-email confirmation gate, cascade correctness (transfers +
// sessions + tokens + auth_events scrub + account_deleted row + user row),
// anonymous-transfer protection, replay-after-success, partial R2 failure,
// notification best-effort, and rate limiting.

import { afterAll, beforeAll, beforeEach, describe, expect, it, mock } from "bun:test";
import { and, eq, isNull } from "drizzle-orm";
import { createApp } from "../../src/app";
import { db } from "../../src/db";
import {
  authEvents,
  magicLinkTokens,
  sessions,
  subscriptions,
  transfers,
  users,
} from "../../src/db/schema";
import { eraseAccount } from "../../src/auth/users";
import { nanoid } from "nanoid";
import { createSession, SESSION_COOKIE_NAME } from "../../src/auth/sessions";
import { issueMagicLink } from "../../src/auth/magicLinks";
import { logAuthEvent } from "../../src/auth/events";
import { createFile, createTransfer } from "../../src/services/file.service";
import { authedRequest, createAuthedUser, createTestUser, testIpContext } from "../helpers/auth";
import { defaultR2Mock } from "../helpers/r2-mock";
import { ensureMigrations, resetDb } from "../helpers/db";

const APP_URL = process.env.APP_URL!;
const ORIGIN_HEADER = { Origin: APP_URL, "Content-Type": "application/json" };

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

function deleteAccountInit(body: object, cookie?: string): RequestInit {
  const headers: Record<string, string> = { ...ORIGIN_HEADER };
  if (cookie) headers["Cookie"] = cookie;
  return { method: "DELETE", headers, body: JSON.stringify(body) };
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

// ─── 1. Happy path ─────────────────────────────────────────────────────────

describe("DELETE /api/me — happy path", () => {
  it("erases the account end-to-end and writes the expected audit trail", async () => {
    const { user, cookie } = await createAuthedUser("erase-me@tessil.test");

    // A pre-existing auth_events row (e.g. magic_link_consumed at signin) — we
    // want to verify its email column gets scrubbed during the cascade.
    await logAuthEvent({
      eventType: "magic_link_consumed",
      userId: user.id,
      email: user.email,
      ipContext: testIpContext(),
    });

    // Seed an owned transfer with a file.
    const owned = await createTransfer(1, undefined, undefined, user.id);
    await seedFile(owned.id, 512);

    // An open second session (will get hard-deleted with the user).
    await createSession({ userId: user.id, ipContext: testIpContext(), userAgent: "second-device" });

    // An unconsumed magic-link token for the same email (sign-in attempt
    // dangling in the wild).
    await issueMagicLink({ email: user.email, userAgent: null });

    const res = await app.handle(
      new Request(`${APP_URL}/api/me`, deleteAccountInit({ confirmEmail: user.email }, cookie)),
    );
    expect(res.status).toBe(204);

    // Set-Cookie clears the session cookie (Max-Age=0).
    const setCookie = res.headers.get("set-cookie");
    expect(setCookie).toBeTruthy();
    expect(setCookie!.toLowerCase()).toContain(SESSION_COOKIE_NAME.toLowerCase());
    expect(setCookie!.toLowerCase()).toContain("max-age=0");

    // Users row is gone.
    const userRows = await db.select().from(users).where(eq(users.id, user.id));
    expect(userRows).toHaveLength(0);

    // Sessions are gone.
    const sessionRows = await db.select().from(sessions).where(eq(sessions.userId, user.id));
    expect(sessionRows).toHaveLength(0);

    // Magic-link tokens for the email are gone.
    const tokenRows = await db
      .select()
      .from(magicLinkTokens)
      .where(eq(magicLinkTokens.email, user.email));
    expect(tokenRows).toHaveLength(0);

    // Transfer row is gone (purged hard-delete).
    const transferRows = await db.select().from(transfers).where(eq(transfers.id, owned.id));
    expect(transferRows).toHaveLength(0);

    // auth_events for this user_id: prior row has email scrubbed, and
    // exactly one account_deleted row exists with email=NULL.
    const eventsForUser = await db
      .select()
      .from(authEvents)
      .where(eq(authEvents.userId, user.id));
    expect(eventsForUser.length).toBeGreaterThanOrEqual(2);
    for (const ev of eventsForUser) {
      expect(ev.email).toBeNull();
    }
    const deletedEvents = eventsForUser.filter((e) => e.eventType === "account_deleted");
    expect(deletedEvents).toHaveLength(1);
  });
});

// ─── 2. Anonymous transfers untouched ──────────────────────────────────────

describe("DELETE /api/me — anonymous transfers are not affected", () => {
  it("leaves pre-existing anonymous (NULL user_id) transfers in place", async () => {
    const { user, cookie } = await createAuthedUser();
    const anon = await createTransfer(1); // user_id = NULL

    const res = await app.handle(
      new Request(`${APP_URL}/api/me`, deleteAccountInit({ confirmEmail: user.email }, cookie)),
    );
    expect(res.status).toBe(204);

    const anonRows = await db.select().from(transfers).where(eq(transfers.id, anon.id));
    expect(anonRows).toHaveLength(1);
    expect(anonRows[0].userId).toBeNull();
    expect(anonRows[0].isDeleted).toBe(false);
  });
});

// ─── 3. Confirmation gate ──────────────────────────────────────────────────

describe("DELETE /api/me — confirmation gate (D-091)", () => {
  it("400 when confirmEmail does not match", async () => {
    const { user, cookie } = await createAuthedUser("real@tessil.test");

    const res = await app.handle(
      new Request(
        `${APP_URL}/api/me`,
        deleteAccountInit({ confirmEmail: "wrong@tessil.test" }, cookie),
      ),
    );
    expect(res.status).toBe(400);

    // Nothing was deleted.
    const userRows = await db.select().from(users).where(eq(users.id, user.id));
    expect(userRows).toHaveLength(1);
  });

  it("accepts trimmed + uppercased email (case-insensitive normalisation)", async () => {
    const { user, cookie } = await createAuthedUser("user@tessil.test");

    const res = await app.handle(
      new Request(
        `${APP_URL}/api/me`,
        deleteAccountInit({ confirmEmail: "  USER@TESSIL.TEST  " }, cookie),
      ),
    );
    expect(res.status).toBe(204);

    const userRows = await db.select().from(users).where(eq(users.id, user.id));
    expect(userRows).toHaveLength(0);
  });

  it("400 when confirmEmail is empty string", async () => {
    const { user, cookie } = await createAuthedUser();
    const res = await app.handle(
      new Request(`${APP_URL}/api/me`, deleteAccountInit({ confirmEmail: "" }, cookie)),
    );
    expect(res.status).toBe(400);
    const userRows = await db.select().from(users).where(eq(users.id, user.id));
    expect(userRows).toHaveLength(1);
  });
});

// ─── 4. Auth gate ──────────────────────────────────────────────────────────

describe("DELETE /api/me — auth gate", () => {
  it("401 when no session cookie is present", async () => {
    const res = await app.handle(
      new Request(`${APP_URL}/api/me`, deleteAccountInit({ confirmEmail: "x@y.z" })),
    );
    expect(res.status).toBe(401);
  });

  it("403 when Origin is disallowed", async () => {
    const { cookie } = await createAuthedUser();
    const res = await app.handle(
      new Request(`${APP_URL}/api/me`, {
        method: "DELETE",
        headers: {
          Origin: "https://attacker.example",
          "Content-Type": "application/json",
          Cookie: cookie,
        },
        body: JSON.stringify({ confirmEmail: "anything@x.y" }),
      }),
    );
    expect(res.status).toBe(403);
  });
});

// ─── 5. Replay after success ───────────────────────────────────────────────

describe("DELETE /api/me — replay after success", () => {
  it("a second call with the same cookie returns 401 (session is gone)", async () => {
    const { user, cookie } = await createAuthedUser();

    const first = await app.handle(
      new Request(`${APP_URL}/api/me`, deleteAccountInit({ confirmEmail: user.email }, cookie)),
    );
    expect(first.status).toBe(204);

    const second = await app.handle(
      new Request(`${APP_URL}/api/me`, deleteAccountInit({ confirmEmail: user.email }, cookie)),
    );
    expect(second.status).toBe(401);
  });
});

// ─── 6. Partial R2 failure ─────────────────────────────────────────────────

describe("DELETE /api/me — partial R2 failure does not block erasure", () => {
  it("if R2 deleteFromR2 throws on one object, the user row is still deleted", async () => {
    // Override the R2 stub for this single test to throw, then restore.
    let calls = 0;
    mock.module("../../src/services/r2.service", () => ({
      ...defaultR2Mock(),
      deleteFromR2: async () => {
        calls += 1;
        if (calls === 1) throw new Error("simulated R2 failure");
      },
    }));

    const { user, cookie } = await createAuthedUser();
    const owned = await createTransfer(1, undefined, undefined, user.id);
    await seedFile(owned.id, 100);
    await seedFile(owned.id, 200);

    const res = await app.handle(
      new Request(`${APP_URL}/api/me`, deleteAccountInit({ confirmEmail: user.email }, cookie)),
    );
    expect(res.status).toBe(204);

    const userRows = await db.select().from(users).where(eq(users.id, user.id));
    expect(userRows).toHaveLength(0);

    // Restore the default benign R2 stub for the rest of the suite.
    mock.module("../../src/services/r2.service", () => defaultR2Mock());
  });
});

// ─── 6b. Transfers the purge cannot remove ─────────────────────────────────

describe("eraseAccount: leftovers and billing", () => {
  it("erases an account that has a soft-deleted transfer awaiting the sweep", async () => {
    const { user, cookie } = await createAuthedUser();
    const owned = await createTransfer(1, undefined, undefined, user.id);
    await seedFile(owned.id, 100);
    await db.update(transfers).set({ isDeleted: true }).where(eq(transfers.id, owned.id));

    const res = await app.handle(
      new Request(`${APP_URL}/api/me`, deleteAccountInit({ confirmEmail: user.email }, cookie)),
    );
    expect(res.status).toBe(204);
    expect(await db.select().from(users).where(eq(users.id, user.id))).toHaveLength(0);
    expect(await db.select().from(transfers).where(eq(transfers.id, owned.id))).toHaveLength(0);
  });

  it("hands a transfer storage would not release to the sweep, detached from the user", async () => {
    mock.module("../../src/services/r2.service", () => ({
      ...defaultR2Mock(),
      deleteFromR2: async () => {
        throw new Error("simulated R2 failure");
      },
    }));

    const user = await createTestUser();
    const owned = await createTransfer(1, "a-password", undefined, user.id);
    await seedFile(owned.id, 100);

    await eraseAccount({ user, ipContext: testIpContext(), userAgent: null });
    mock.module("../../src/services/r2.service", () => defaultR2Mock());

    expect(await db.select().from(users).where(eq(users.id, user.id))).toHaveLength(0);
    const [left] = await db.select().from(transfers).where(eq(transfers.id, owned.id));
    expect(left.userId).toBeNull();
    expect(left.isDeleted).toBe(true);
    expect(left.passwordHash).toBeNull();
  });

  it("cancels a live subscription before erasing", async () => {
    const user = await createTestUser();
    await db.insert(subscriptions).values({
      id: nanoid(),
      userId: user.id,
      polarSubscriptionId: "sub_live",
      status: "active",
      currentPeriodEnd: new Date(Date.now() + 86_400_000),
    });

    const cancelled: string[] = [];
    await eraseAccount({
      user,
      ipContext: testIpContext(),
      userAgent: null,
      cancelSubscription: async (id) => {
        cancelled.push(id);
      },
    });

    expect(cancelled).toEqual(["sub_live"]);
    expect(await db.select().from(users).where(eq(users.id, user.id))).toHaveLength(0);
  });

  it("leaves the account intact when the subscription cannot be cancelled", async () => {
    const user = await createTestUser();
    const owned = await createTransfer(1, undefined, undefined, user.id);
    await db.insert(subscriptions).values({
      id: nanoid(),
      userId: user.id,
      polarSubscriptionId: "sub_stuck",
      status: "active",
      currentPeriodEnd: new Date(Date.now() + 86_400_000),
    });

    const attempt = eraseAccount({
      user,
      ipContext: testIpContext(),
      userAgent: null,
      cancelSubscription: async () => {
        throw new Error("simulated processor outage");
      },
    });
    await expect(attempt).rejects.toThrow("simulated processor outage");

    expect(await db.select().from(users).where(eq(users.id, user.id))).toHaveLength(1);
    expect(await db.select().from(transfers).where(eq(transfers.id, owned.id))).toHaveLength(1);
  });
});

// ─── 7. Notification best-effort ───────────────────────────────────────────

describe("DELETE /api/me — notification email is best-effort", () => {
  it("returns 204 and commits the cascade even if the notification send throws", async () => {
    mock.module("../../src/services/email.service", () => ({
      sendMagicLink: async () => undefined,
      sendAccountDeletedNotification: async () => {
        throw new Error("simulated email failure");
      },
    }));

    const { user, cookie } = await createAuthedUser();

    const res = await app.handle(
      new Request(`${APP_URL}/api/me`, deleteAccountInit({ confirmEmail: user.email }, cookie)),
    );
    expect(res.status).toBe(204);

    const userRows = await db.select().from(users).where(eq(users.id, user.id));
    expect(userRows).toHaveLength(0);

    // Restore default benign email stub.
    mock.module("../../src/services/email.service", () => ({
      sendMagicLink: async () => undefined,
      sendAccountDeletedNotification: async () => undefined,
    }));
  });
});

// ─── 8. Rate limit ─────────────────────────────────────────────────────────

describe("DELETE /api/me — rate limit", () => {
  it("6th call within the hour returns 429", async () => {
    // Use one user so the limiter is keyed on a single user.id. The cascade
    // permanently deletes the user, so we need separate sessions on the SAME
    // user that we keep re-creating after each delete — which contradicts
    // erasure. Instead: hit the endpoint with mismatched confirmEmail to drive
    // 400 responses; the rate limiter increments before the gate so we still
    // exhaust the quota. The 6th call is rejected with 429.
    const { user, cookie } = await createAuthedUser();

    for (let i = 0; i < 5; i++) {
      const res = await app.handle(
        new Request(
          `${APP_URL}/api/me`,
          deleteAccountInit({ confirmEmail: "nope@nope.test" }, cookie),
        ),
      );
      expect(res.status).toBe(400);
    }

    const sixth = await app.handle(
      new Request(
        `${APP_URL}/api/me`,
        deleteAccountInit({ confirmEmail: "nope@nope.test" }, cookie),
      ),
    );
    expect(sixth.status).toBe(429);

    // User still exists — none of the 6 actually committed an erasure.
    const userRows = await db.select().from(users).where(eq(users.id, user.id));
    expect(userRows).toHaveLength(1);
  });
});

// Make TS happy about unused imports used only by helpers/inline checks.
void createTestUser;
void and;
void isNull;
