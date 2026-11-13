// Sharing a portal with one other account: invite, hand over the keys,
// remove. See docs/adr/0014-portal-keys-and-vault-items.md, points 8 and 9.

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import { eq } from "drizzle-orm";
import { nanoid } from "nanoid";
import { createApp } from "../../src/app";
import { db } from "../../src/db";
import { portalInvites, portalMembers, users } from "../../src/db/schema";
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
const HANDED = b64(new Uint8Array(260).fill(8));
const KEPT = b64(new Uint8Array(210).fill(9));

function call(cookie: string | null, method: string, path: string, body?: object) {
  const init: RequestInit = { method, headers: JSON_HEADERS };
  if (body) init.body = JSON.stringify(body);
  const url = `${APP_URL}${path}`;
  return app.handle(cookie ? authedRequest(cookie, url, init) : new Request(url, init));
}

async function account(email: string, opts: { tier?: string; keypair?: boolean } = {}) {
  const authed = await createAuthedUser(email);
  const publicKey = opts.keypair === false ? null : crypto.getRandomValues(new Uint8Array(65));
  await db
    .update(users)
    .set({ tier: opts.tier ?? "free", publicKey })
    .where(eq(users.id, authed.user.id));
  return { ...authed, publicKey };
}

async function ownerWithPortal(email = "owner@tessil.test") {
  const owner = await account(email, { tier: "pro" });
  const portalId = nanoid();
  const res = await call(owner.cookie, "POST", "/api/portals", {
    id: portalId,
    publicBundle: b64(new Uint8Array(140).fill(3)),
    sealedKeys: b64(new Uint8Array(200).fill(4)),
    depositToken: b64(new Uint8Array(32).fill(6)),
  });
  expect(res.status).toBe(201);
  return { ...owner, portalId };
}

type Sharing = {
  maxGuests: number;
  guests: { userId: string; email: string }[];
  invites: { id: string; email: string; ready: { userId: string; publicKey: string } | null }[];
};
const sharing = async (cookie: string, portalId: string) =>
  (await (await call(cookie, "GET", `/api/portals/${portalId}/sharing`)).json()) as Sharing;

async function invite(cookie: string, portalId: string, email: string) {
  const res = await call(cookie, "POST", `/api/portals/${portalId}/invites`, { email });
  return { res, id: res.status === 201 ? ((await res.clone().json()) as { id: string }).id : "" };
}

/** Owner invites `guest` and hands them the keys. */
async function share(owner: { cookie: string; portalId: string }, guest: { user: { email: string }; publicKey: Uint8Array | null }) {
  const { id } = await invite(owner.cookie, owner.portalId, guest.user.email);
  const res = await call(owner.cookie, "POST", `/api/portals/${owner.portalId}/members`, {
    inviteId: id,
    sealedKeys: HANDED,
    sealedTo: b64(guest.publicKey!),
  });
  expect(res.status).toBe(201);
}

describe("inviting", () => {
  it("waits when the invitee has no account yet, and becomes ready when they do", async () => {
    const owner = await ownerWithPortal();
    const { res } = await invite(owner.cookie, owner.portalId, "  Friend@Tessil.Test ");
    expect(res.status).toBe(201);

    let s = await sharing(owner.cookie, owner.portalId);
    expect(s.maxGuests).toBe(1);
    expect(s.invites).toMatchObject([{ email: "friend@tessil.test", ready: null }]);

    // They sign up, but have no keypair until they open a vault.
    const friend = await account("friend@tessil.test", { keypair: false });
    expect((await sharing(owner.cookie, owner.portalId)).invites[0].ready).toBeNull();

    const key = crypto.getRandomValues(new Uint8Array(65));
    await db.update(users).set({ publicKey: key }).where(eq(users.id, friend.user.id));
    s = await sharing(owner.cookie, owner.portalId);
    expect(s.invites[0].ready).toEqual({ userId: friend.user.id, publicKey: b64(key) });
  });

  it("refuses the owner's own address, duplicates, and a second guest", async () => {
    const owner = await ownerWithPortal();
    const own = await invite(owner.cookie, owner.portalId, "OWNER@tessil.test");
    expect(own.res.status).toBe(409);

    expect((await invite(owner.cookie, owner.portalId, "a@tessil.test")).res.status).toBe(201);
    const again = await invite(owner.cookie, owner.portalId, "a@tessil.test");
    expect(((await again.res.json()) as { code: string }).code).toBe("invite_already_invited");
    const second = await invite(owner.cookie, owner.portalId, "b@tessil.test");
    expect(((await second.res.json()) as { code: string }).code).toBe("invite_full");
    expect((await invite(owner.cookie, owner.portalId, "not an email")).res.status).toBe(400);
  });

  it("can be withdrawn, which frees the place", async () => {
    const owner = await ownerWithPortal();
    const { id } = await invite(owner.cookie, owner.portalId, "a@tessil.test");
    expect((await call(owner.cookie, "DELETE", `/api/portals/${owner.portalId}/invites/${id}`)).status).toBe(204);
    expect((await invite(owner.cookie, owner.portalId, "b@tessil.test")).res.status).toBe(201);
  });

  it("is only for the owner", async () => {
    const owner = await ownerWithPortal();
    const stranger = await account("stranger@tessil.test", { tier: "pro" });
    expect((await invite(stranger.cookie, owner.portalId, "x@tessil.test")).res.status).toBe(404);
    expect((await call(stranger.cookie, "GET", `/api/portals/${owner.portalId}/sharing`)).status).toBe(404);
    expect((await call(null, "GET", `/api/portals/${owner.portalId}/sharing`)).status).toBe(401);
  });
});

describe("handing over the keys", () => {
  it("makes the invitee a member who can see the portal and its deposits", async () => {
    const owner = await ownerWithPortal();
    const guest = await account("guest@tessil.test");
    await share(owner, guest);

    const s = await sharing(owner.cookie, owner.portalId);
    expect(s.invites).toHaveLength(0);
    expect(s.guests).toMatchObject([{ userId: guest.user.id, email: "guest@tessil.test" }]);

    const list = (await (await call(guest.cookie, "GET", "/api/portals")).json()) as {
      portals: { id: string; role: string; sealedKeys: string; owner: { email: string; publicKey: string } }[];
    };
    expect(list.portals).toHaveLength(1);
    expect(list.portals[0]).toMatchObject({
      id: owner.portalId,
      role: "member",
      sealedKeys: HANDED,
      owner: { email: "owner@tessil.test", publicKey: b64(owner.publicKey!) },
    });
    expect((await call(guest.cookie, "GET", `/api/portals/${owner.portalId}/deposits`)).status).toBe(200);
  });

  it("refuses when the invitee is not ready or their key is not the one sealed to", async () => {
    const owner = await ownerWithPortal();
    const { id } = await invite(owner.cookie, owner.portalId, "guest@tessil.test");
    const body = { inviteId: id, sealedKeys: HANDED, sealedTo: b64(new Uint8Array(65).fill(1)) };

    const early = await call(owner.cookie, "POST", `/api/portals/${owner.portalId}/members`, body);
    expect(((await early.json()) as { code: string }).code).toBe("admit_not_ready");

    await account("guest@tessil.test");
    const stale = await call(owner.cookie, "POST", `/api/portals/${owner.portalId}/members`, body);
    expect(((await stale.json()) as { code: string }).code).toBe("admit_key_changed");
    expect(await db.select().from(portalMembers).where(eq(portalMembers.portalId, owner.portalId))).toHaveLength(1);
  });

  it("needs an invite, and only the owner can do it", async () => {
    const owner = await ownerWithPortal();
    const guest = await account("guest@tessil.test");
    const stranger = await account("stranger@tessil.test", { tier: "pro" });
    const { id } = await invite(owner.cookie, owner.portalId, "guest@tessil.test");
    const body = { inviteId: id, sealedKeys: HANDED, sealedTo: b64(guest.publicKey!) };

    expect((await call(stranger.cookie, "POST", `/api/portals/${owner.portalId}/members`, body)).status).toBe(404);
    expect((await call(guest.cookie, "POST", `/api/portals/${owner.portalId}/members`, body)).status).toBe(404);
    expect(
      (await call(owner.cookie, "POST", `/api/portals/${owner.portalId}/members`, { ...body, inviteId: nanoid() })).status,
    ).toBe(404);
  });

  it("lets a member replace their own copy of the keys, and nobody else's", async () => {
    const owner = await ownerWithPortal();
    const guest = await account("guest@tessil.test");
    const stranger = await account("stranger@tessil.test");
    await share(owner, guest);

    expect((await call(guest.cookie, "PUT", `/api/portals/${owner.portalId}/members/me`, { sealedKeys: KEPT })).status).toBe(200);
    const [row] = await db.select().from(portalMembers).where(eq(portalMembers.userId, guest.user.id));
    expect(b64(row.sealedKeys)).toBe(KEPT);
    expect((await call(stranger.cookie, "PUT", `/api/portals/${owner.portalId}/members/me`, { sealedKeys: KEPT })).status).toBe(404);
  });
});

describe("removing", () => {
  it("cuts the guest off at once when the owner removes them", async () => {
    const owner = await ownerWithPortal();
    const guest = await account("guest@tessil.test");
    await share(owner, guest);

    expect((await call(owner.cookie, "DELETE", `/api/portals/${owner.portalId}/members/${guest.user.id}`)).status).toBe(204);
    expect((await call(guest.cookie, "GET", `/api/portals/${owner.portalId}/deposits`)).status).toBe(404);
    const list = (await (await call(guest.cookie, "GET", "/api/portals")).json()) as { portals: unknown[] };
    expect(list.portals).toHaveLength(0);
    // The place is free again.
    expect((await invite(owner.cookie, owner.portalId, "next@tessil.test")).res.status).toBe(201);
  });

  it("lets a guest leave, but not remove the owner or act as one", async () => {
    const owner = await ownerWithPortal();
    const guest = await account("guest@tessil.test");
    await share(owner, guest);

    expect((await call(guest.cookie, "DELETE", `/api/portals/${owner.portalId}/members/${owner.user.id}`)).status).toBe(404);
    expect((await call(guest.cookie, "PATCH", `/api/portals/${owner.portalId}`, { isDisabled: true })).status).toBe(404);
    expect((await call(guest.cookie, "DELETE", `/api/portals/${owner.portalId}`)).status).toBe(404);
    expect((await invite(guest.cookie, owner.portalId, "x@tessil.test")).res.status).toBe(404);

    expect((await call(guest.cookie, "DELETE", `/api/portals/${owner.portalId}/members/${guest.user.id}`)).status).toBe(204);
    expect(await db.select().from(portalMembers).where(eq(portalMembers.portalId, owner.portalId))).toHaveLength(1);
  });

  it("does not let the owner remove themselves, or a stranger remove anyone", async () => {
    const owner = await ownerWithPortal();
    const guest = await account("guest@tessil.test");
    const stranger = await account("stranger@tessil.test");
    await share(owner, guest);
    expect((await call(owner.cookie, "DELETE", `/api/portals/${owner.portalId}/members/${owner.user.id}`)).status).toBe(404);
    expect((await call(stranger.cookie, "DELETE", `/api/portals/${owner.portalId}/members/${guest.user.id}`)).status).toBe(404);
  });

  it("takes invites and memberships with the portal", async () => {
    const owner = await ownerWithPortal();
    await invite(owner.cookie, owner.portalId, "a@tessil.test");
    expect((await call(owner.cookie, "DELETE", `/api/portals/${owner.portalId}`)).status).toBe(204);
    expect(await db.select().from(portalInvites)).toHaveLength(0);
    expect(await db.select().from(portalMembers)).toHaveLength(0);
  });
});
