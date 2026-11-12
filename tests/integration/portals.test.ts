// Portal creation, listing, ownership and the public read.
// See docs/adr/0014-portal-keys-and-vault-items.md.

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import { eq } from "drizzle-orm";
import { nanoid } from "nanoid";
import { createApp } from "../../src/app";
import { db } from "../../src/db";
import { portalMembers, portals, sessions, users } from "../../src/db/schema";
import { resetRateLimits } from "../../src/services/ratelimit.service";
import { authedRequest, createAuthedUser } from "../helpers/auth";
import { ensureMigrations, resetDb } from "../helpers/db";

const APP_URL = process.env.APP_URL!;
const JSON_HEADERS = { Origin: APP_URL, "Content-Type": "application/json" };

let app: ReturnType<typeof createApp>;

beforeAll(async () => {
  await ensureMigrations();
  app = createApp();
});
beforeEach(async () => {
  await resetDb();
  await resetRateLimits();
});
afterAll(resetDb);

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
const newId = () => nanoid();
const BUNDLE = b64(new Uint8Array(140).fill(3));
const SEALED = b64(new Uint8Array(260).fill(4));
const TOKEN = b64(new Uint8Array(32).fill(6));

async function account(tier: string, withKeypair = true) {
  const authed = await createAuthedUser();
  await db
    .update(users)
    .set({ tier, publicKey: withKeypair ? new Uint8Array(65).fill(4) : null })
    .where(eq(users.id, authed.user.id));
  return authed;
}

function call(cookie: string | null, method: string, path: string, body?: object) {
  const init: RequestInit = { method, headers: JSON_HEADERS };
  if (body) init.body = JSON.stringify(body);
  const url = `${APP_URL}/api/portals${path}`;
  return app.handle(cookie ? authedRequest(cookie, url, init) : new Request(url, init));
}

async function createOne(cookie: string): Promise<string> {
  const id = newId();
  const res = await call(cookie, "POST", "", { id, publicBundle: BUNDLE, sealedKeys: SEALED, depositToken: TOKEN });
  expect(res.status).toBe(201);
  expect(((await res.json()) as { id: string }).id).toBe(id);
  return id;
}

describe("creating a portal", () => {
  it("creates it with the owner as its first member", async () => {
    const { user, cookie } = await account("pro");
    const id = await createOne(cookie);

    const members = await db.select().from(portalMembers).where(eq(portalMembers.portalId, id));
    expect(members).toHaveLength(1);
    expect(members[0].userId).toBe(user.id);
    expect(members[0].role).toBe("owner");

    const list = await call(cookie, "GET", "");
    const body = (await list.json()) as {
      maxPortals: number;
      portals: { id: string; role: string; publicBundle: string; sealedKeys: string }[];
    };
    expect(body.maxPortals).toBe(3);
    expect(body.portals).toHaveLength(1);
    expect(body.portals[0]).toMatchObject({ id, role: "owner", publicBundle: BUNDLE, sealedKeys: SEALED });
    // The token and its hash never come back out.
    expect(JSON.stringify(body)).not.toContain(TOKEN);
  });

  it("is refused on the free plan", async () => {
    const { cookie } = await account("free");
    const res = await call(cookie, "POST", "", { id: newId(), publicBundle: BUNDLE, sealedKeys: SEALED, depositToken: TOKEN });
    expect(res.status).toBe(402);
    expect(((await res.json()) as { code: string }).code).toBe("portals_require_paid_plan");
  });

  it("needs the account to have a keypair", async () => {
    const { cookie } = await account("pro", false);
    const res = await call(cookie, "POST", "", { id: newId(), publicBundle: BUNDLE, sealedKeys: SEALED, depositToken: TOKEN });
    expect(res.status).toBe(409);
    expect(((await res.json()) as { code: string }).code).toBe("keypair_required");
  });

  it("stops at the plan's portal limit, even for parallel requests", async () => {
    const { user, cookie } = await account("pro");
    const results = await Promise.all(
      Array.from({ length: 6 }, () =>
        call(cookie, "POST", "", { id: newId(), publicBundle: BUNDLE, sealedKeys: SEALED, depositToken: TOKEN }),
      ),
    );
    expect(results.filter((r) => r.status === 201)).toHaveLength(3);
    expect(results.filter((r) => r.status === 409)).toHaveLength(3);
    expect(await db.select().from(portals).where(eq(portals.ownerId, user.id))).toHaveLength(3);
  });

  it("gives the higher plan more portals", async () => {
    const { cookie } = await account("max");
    for (let i = 0; i < 4; i++) await createOne(cookie);
  });

  it("rejects blobs that are too small or too large", async () => {
    const { cookie } = await account("pro");
    const tiny = await call(cookie, "POST", "", { id: newId(), publicBundle: b64(new Uint8Array(10)), sealedKeys: SEALED, depositToken: TOKEN });
    expect(tiny.status).toBe(400);
    const huge = await call(cookie, "POST", "", {
      publicBundle: BUNDLE,
      sealedKeys: b64(new Uint8Array(1500)),
      depositToken: TOKEN,
    });
    expect(huge.status).toBe(400);
  });

  it("refuses an ID that is taken or malformed, without touching the existing portal", async () => {
    const first = await account("pro");
    const second = await account("pro");
    const id = await createOne(first.cookie);

    const taken = await call(second.cookie, "POST", "", { id, publicBundle: BUNDLE, sealedKeys: SEALED, depositToken: TOKEN });
    expect(taken.status).toBe(409);
    expect(((await taken.json()) as { code: string }).code).toBe("portal_id_taken");
    const [row] = await db.select().from(portals).where(eq(portals.id, id));
    expect(row.ownerId).toBe(first.user.id);

    const malformed = await call(second.cookie, "POST", "", {
      id: "../".repeat(7),
      publicBundle: BUNDLE,
      sealedKeys: SEALED,
      depositToken: TOKEN,
    });
    expect(malformed.status).toBe(400);
  });

  it("requires a session", async () => {
    const res = await call(null, "POST", "", { id: newId(), publicBundle: BUNDLE, sealedKeys: SEALED, depositToken: TOKEN });
    expect(res.status).toBe(401);
  });
});

describe("ownership", () => {
  it("hides a portal from other accounts and refuses their changes", async () => {
    const owner = await account("pro");
    const stranger = await account("pro");
    const id = await createOne(owner.cookie);

    const list = await call(stranger.cookie, "GET", "");
    expect(((await list.json()) as { portals: unknown[] }).portals).toHaveLength(0);

    expect((await call(stranger.cookie, "PATCH", `/${id}`, { isDisabled: true })).status).toBe(404);
    expect((await call(stranger.cookie, "DELETE", `/${id}`)).status).toBe(404);
    expect(await db.select().from(portals).where(eq(portals.id, id))).toHaveLength(1);
  });

  it("lets the owner delete it, members included", async () => {
    const { cookie } = await account("pro");
    const id = await createOne(cookie);
    expect((await call(cookie, "DELETE", `/${id}`)).status).toBe(204);
    expect(await db.select().from(portalMembers).where(eq(portalMembers.portalId, id))).toHaveLength(0);
  });

  it("goes with the account", async () => {
    const { user, cookie } = await account("pro");
    const id = await createOne(cookie);
    await db.delete(sessions).where(eq(sessions.userId, user.id));
    await db.delete(users).where(eq(users.id, user.id));
    expect(await db.select().from(portals).where(eq(portals.id, id))).toHaveLength(0);
  });
});

describe("the public read", () => {
  it("returns the bundle and says the portal is accepting", async () => {
    const { cookie } = await account("pro");
    const id = await createOne(cookie);

    const res = await call(null, "GET", `/${id}/public`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toEqual({ id, publicBundle: BUNDLE, keyVersion: 1, accepting: true });
  });

  it("stops accepting when the owner switches it off", async () => {
    const { cookie } = await account("pro");
    const id = await createOne(cookie);
    expect((await call(cookie, "PATCH", `/${id}`, { isDisabled: true })).status).toBe(200);

    const body = (await (await call(null, "GET", `/${id}/public`)).json()) as { accepting: boolean };
    expect(body.accepting).toBe(false);
  });

  it("stops accepting when the owner is no longer on a paid plan", async () => {
    const { user, cookie } = await account("pro");
    const id = await createOne(cookie);
    await db.update(users).set({ tier: "free" }).where(eq(users.id, user.id));

    const body = (await (await call(null, "GET", `/${id}/public`)).json()) as { accepting: boolean };
    expect(body.accepting).toBe(false);
  });

  it("returns 404 for an unknown or malformed ID", async () => {
    expect((await call(null, "GET", `/${"A".repeat(21)}/public`)).status).toBe(404);
    expect((await call(null, "GET", "/not-an-id/public")).status).toBe(404);
  });
});
