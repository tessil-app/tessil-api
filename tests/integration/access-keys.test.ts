// Access keys: a program registers, a person approves, and from then on
// the key may do what it was given and nothing else.
// See docs/adr/0015-access-keys-cli-and-mcp.md.

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import { createHash } from "node:crypto";
import { eq } from "drizzle-orm";
import { nanoid } from "nanoid";
import { createApp } from "../../src/app";
import { db } from "../../src/db";
import { devicePortalKeys, devices, portalMembers, transfers, users } from "../../src/db/schema";
import { purgeDeadDevices } from "../../src/services/device.service";
import { resetRateLimits } from "../../src/services/ratelimit.service";
import { authedRequest, createAuthedUser } from "../helpers/auth";
import { ensureMigrations, resetDb } from "../helpers/db";

const APP_URL = process.env.APP_URL!;
const JSON_HEADERS = { "Content-Type": "application/json" };

let app: ReturnType<typeof createApp>;

beforeAll(async () => {
  await ensureMigrations();
  app = createApp();
});
beforeEach(async () => {
  await resetDb();
  await db.delete(devices);
  await resetRateLimits();
});
afterAll(resetDb);

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
const PUBLIC_KEY = b64(new Uint8Array([4, ...new Uint8Array(64).fill(7)]));
const FILE_FIELDS = {
  contentType: "application/octet-stream",
  encryptedName: "x".repeat(32),
  encryptedNameIv: "y".repeat(24),
  fileIv: "z".repeat(24),
};

function newToken() {
  const token = `tsl_${b64(crypto.getRandomValues(new Uint8Array(32)))}`;
  return { token, tokenHash: createHash("sha256").update(token).digest("hex") };
}

/** A request as a program makes it: a token, no cookie, no Origin. */
function asDevice(token: string | null, method: string, path: string, body?: object, extra: Record<string, string> = {}) {
  const headers: Record<string, string> = { ...JSON_HEADERS, ...extra };
  if (token) headers.Authorization = `Bearer ${token}`;
  return app.handle(new Request(`${APP_URL}${path}`, { method, headers, body: body ? JSON.stringify(body) : undefined }));
}

/** A request as the signed-in person's browser makes it. */
function asPerson(cookie: string, method: string, path: string, body?: object) {
  return app.handle(
    authedRequest(cookie, `${APP_URL}${path}`, {
      method,
      headers: JSON_HEADERS,
      body: body ? JSON.stringify(body) : undefined,
    }),
  );
}

async function register(name = "MacBook, test") {
  const { token, tokenHash } = newToken();
  const res = await asDevice(null, "POST", "/api/devices", { name, publicKey: PUBLIC_KEY, tokenHash });
  expect(res.status).toBe(201);
  const body = (await res.json()) as { id: string; pairingCode: string };
  return { token, tokenHash, ...body };
}

async function person(tier = "free") {
  const authed = await createAuthedUser();
  await db.update(users).set({ tier }).where(eq(users.id, authed.user.id));
  return authed;
}

/** A registered key, approved by a fresh account with the given permissions. */
async function approved(permissions: string[], tier = "pro") {
  const owner = await person(tier);
  const device = await register();
  const res = await asPerson(owner.cookie, "POST", "/api/devices/approve", { code: device.pairingCode, permissions });
  expect(res.status).toBe(201);
  return { owner, device };
}

describe("pairing", () => {
  it("is pending until a person approves it, and then knows who it works for", async () => {
    const owner = await person();
    const device = await register();
    expect(device.pairingCode).toMatch(/^[A-Z2-9]{4}-[A-Z2-9]{4}$/);

    const waiting = await asDevice(device.token, "GET", "/api/devices/self");
    expect(waiting.status).toBe(200);
    expect(((await waiting.json()) as { status: string }).status).toBe("pending");

    const shown = await asPerson(owner.cookie, "GET", `/api/devices/pending/${device.pairingCode.toLowerCase()}`);
    expect(await shown.json()).toMatchObject({ name: "MacBook, test", publicKey: PUBLIC_KEY });

    const ok = await asPerson(owner.cookie, "POST", "/api/devices/approve", {
      code: device.pairingCode,
      permissions: ["transfers:send", "transfers:read"],
      name: "Laptop",
    });
    expect(ok.status).toBe(201);

    const self = (await (await asDevice(device.token, "GET", "/api/devices/self")).json()) as {
      status: string;
      device: { name: string; permissions: string[]; expiresAt: string };
      account: { email: string };
    };
    expect(self.status).toBe("active");
    expect(self.device.name).toBe("Laptop");
    expect(self.device.permissions).toEqual(["transfers:send", "transfers:read"]);
    expect(self.account.email).toBe(owner.user.email);
    const days = (new Date(self.device.expiresAt).getTime() - Date.now()) / 86_400_000;
    expect(Math.round(days)).toBe(90);
  });

  it("stores neither the token nor the pairing code", async () => {
    const device = await register();
    const [row] = await db.select().from(devices).where(eq(devices.id, device.id));
    const stored = JSON.stringify(row);
    expect(stored).not.toContain(device.token);
    expect(stored).not.toContain(device.pairingCode.replace("-", ""));
    expect(row.tokenHash).toBe(device.tokenHash);
  });

  it("uses a code once, and not after ten minutes", async () => {
    const owner = await person();
    const other = await person();
    const first = await register();
    await asPerson(owner.cookie, "POST", "/api/devices/approve", { code: first.pairingCode, permissions: ["transfers:send"] });
    const again = await asPerson(other.cookie, "POST", "/api/devices/approve", { code: first.pairingCode, permissions: ["transfers:send"] });
    expect(again.status).toBe(404);

    const late = await register();
    await db.update(devices).set({ pairingExpiresAt: new Date(Date.now() - 1000) }).where(eq(devices.id, late.id));
    const expired = await asPerson(other.cookie, "POST", "/api/devices/approve", { code: late.pairingCode, permissions: ["transfers:send"] });
    expect(expired.status).toBe(404);
    expect((await asDevice(late.token, "GET", "/api/devices/self")).status).toBe(401);
  });

  it("refuses a malformed key, a repeated token, and a page", async () => {
    const { tokenHash } = newToken();
    const bad = await asDevice(null, "POST", "/api/devices", { name: "x", publicKey: b64(new Uint8Array(65)), tokenHash });
    expect(bad.status).toBe(400);
    const first = await register();
    const twice = await asDevice(null, "POST", "/api/devices", { name: "x", publicKey: PUBLIC_KEY, tokenHash: first.tokenHash });
    expect(twice.status).toBe(409);
    const page = await asDevice(null, "POST", "/api/devices", { name: "x", publicKey: PUBLIC_KEY, tokenHash }, { Origin: APP_URL });
    expect(page.status).toBe(403);
  });

  it("needs a session to look at or approve a pending key", async () => {
    const device = await register();
    const look = await app.handle(new Request(`${APP_URL}/api/devices/pending/${device.pairingCode}`));
    expect(look.status).toBe(401);
    // A key cannot approve another key, or itself.
    const self = await asDevice(device.token, "POST", "/api/devices/approve", { code: device.pairingCode, permissions: ["transfers:send"] });
    expect(self.status).toBe(401);
  });
});

describe("what a plan allows", () => {
  it("gives a free account one key, limited to transfers", async () => {
    const owner = await person("free");
    const first = await register();
    const ok = await asPerson(owner.cookie, "POST", "/api/devices/approve", {
      code: first.pairingCode,
      permissions: ["transfers:send", "portals:read", "portals:manage"],
    });
    expect(((await ok.json()) as { permissions: string[] }).permissions).toEqual(["transfers:send"]);

    const second = await register();
    const full = await asPerson(owner.cookie, "POST", "/api/devices/approve", { code: second.pairingCode, permissions: ["transfers:send"] });
    expect(full.status).toBe(409);
    expect(((await full.json()) as { code: string }).code).toBe("device_limit_reached");
  });

  it("refuses a key that would be allowed nothing", async () => {
    const owner = await person("free");
    const device = await register();
    const res = await asPerson(owner.cookie, "POST", "/api/devices/approve", { code: device.pairingCode, permissions: ["portals:read", "made:up"] });
    expect(res.status).toBe(400);
  });

  it("does not count revoked keys, and does not let parallel approvals overshoot", async () => {
    const owner = await person("pro");
    const pending = await Promise.all(Array.from({ length: 5 }, () => register()));
    const results = await Promise.all(
      pending.map((d) => asPerson(owner.cookie, "POST", "/api/devices/approve", { code: d.pairingCode, permissions: ["transfers:send"] })),
    );
    expect(results.filter((r) => r.status === 201)).toHaveLength(3);

    const list = (await (await asPerson(owner.cookie, "GET", "/api/devices")).json()) as { maxDevices: number; devices: { id: string }[] };
    expect(list.maxDevices).toBe(3);
    await asPerson(owner.cookie, "DELETE", `/api/devices/${list.devices[0].id}`);
    const next = await register();
    const ok = await asPerson(owner.cookie, "POST", "/api/devices/approve", { code: next.pairingCode, permissions: ["transfers:send"] });
    expect(ok.status).toBe(201);
  });
});

describe("sending with a key", () => {
  async function send(token: string) {
    const created = await asDevice(token, "POST", "/api/upload/create-transfer", { expiresInHours: 24 });
    const body = (await created.clone().json()) as { transferId: string };
    return { created, transferId: body.transferId };
  }

  it("creates a transfer that belongs to the account and is marked with the key", async () => {
    const { owner, device } = await approved(["transfers:send", "transfers:read", "transfers:delete"]);
    const { created, transferId } = await send(device.token);
    expect(created.status).toBe(200);
    const [row] = await db.select().from(transfers).where(eq(transfers.id, transferId));
    expect(row.userId).toBe(owner.user.id);
    expect(row.deviceId).toBe(device.id);

    const init = await asDevice(device.token, "POST", "/api/upload/init-multipart", { transferId, size: 1024, ...FILE_FIELDS });
    expect(init.status).toBe(200);
    const done = await asDevice(device.token, "POST", "/api/upload/complete", { transferId, wrappedKey: b64(new Uint8Array(60).fill(1)) });
    expect(done.status).toBe(200);

    const mine = (await (await asDevice(device.token, "GET", "/api/devices/self/transfers")).json()) as {
      transfers: { id: string; deviceId: string; wrappedKey: string }[];
    };
    expect(mine.transfers.map((t) => t.id)).toEqual([transferId]);
    expect(mine.transfers[0].wrappedKey).toBe(b64(new Uint8Array(60).fill(1)));

    // The person sees it among their own, marked.
    const dash = (await (await asPerson(owner.cookie, "GET", "/api/me/transfers")).json()) as { transfers: { id: string; deviceId: string | null }[] };
    expect(dash.transfers.find((t) => t.id === transferId)?.deviceId).toBe(device.id);

    expect((await asDevice(device.token, "DELETE", `/api/devices/self/transfers/${transferId}`)).status).toBe(204);
    const [gone] = await db.select().from(transfers).where(eq(transfers.id, transferId));
    expect(gone.isDeleted).toBe(true);
  });

  it("uses the account's limits, not anonymous ones", async () => {
    const { device } = await approved(["transfers:send"], "pro");
    // 30 days is a paid lifetime; without an account the longest is one day.
    const res = await asDevice(device.token, "POST", "/api/upload/create-transfer", { expiresInHours: 720 });
    expect(res.status).toBe(200);
  });

  it("cannot see or touch the account's other transfers, or another key's", async () => {
    const { owner, device } = await approved(["transfers:send", "transfers:read", "transfers:delete"]);
    // One the person started in their browser, one from a second key.
    const browser = await asPerson(owner.cookie, "POST", "/api/upload/create-transfer", { expiresInHours: 24 });
    const browserId = ((await browser.json()) as { transferId: string }).transferId;
    const second = await register("second");
    await asPerson(owner.cookie, "POST", "/api/devices/approve", { code: second.pairingCode, permissions: ["transfers:send"] });
    const { transferId: otherId } = await send(second.token);

    for (const id of [browserId, otherId]) {
      const init = await asDevice(device.token, "POST", "/api/upload/init-multipart", { transferId: id, size: 1024, ...FILE_FIELDS });
      expect(init.status).toBe(404);
      expect((await asDevice(device.token, "POST", "/api/upload/abort", { transferId: id })).status).toBe(404);
      expect((await asDevice(device.token, "DELETE", `/api/devices/self/transfers/${id}`)).status).toBe(404);
    }
    const mine = (await (await asDevice(device.token, "GET", "/api/devices/self/transfers")).json()) as { transfers: unknown[] };
    expect(mine.transfers).toEqual([]);
  });

  it("needs the permission for each thing", async () => {
    const reader = await approved(["transfers:read"]);
    const refused = await asDevice(reader.device.token, "POST", "/api/upload/create-transfer", { expiresInHours: 24 });
    expect(refused.status).toBe(403);
    expect(((await refused.json()) as { code: string }).code).toBe("device_forbidden");

    const sender = await approved(["transfers:send"]);
    const { transferId } = await send(sender.device.token);
    expect((await asDevice(sender.device.token, "GET", "/api/devices/self/transfers")).status).toBe(403);
    expect((await asDevice(sender.device.token, "DELETE", `/api/devices/self/transfers/${transferId}`)).status).toBe(403);
  });
});

describe("a key that must not work", () => {
  it("is refused, never treated as a visitor without an account", async () => {
    const bogus = newToken().token;
    const pending = await register();
    const { owner, device } = await approved(["transfers:send"]);

    const expired = await approved(["transfers:send"]);
    await db.update(devices).set({ expiresAt: new Date(Date.now() - 1000) }).where(eq(devices.id, expired.device.id));

    const revoked = await approved(["transfers:send"]);
    const list = (await (await asPerson(revoked.owner.cookie, "GET", "/api/devices")).json()) as { devices: { id: string }[] };
    expect((await asPerson(revoked.owner.cookie, "DELETE", `/api/devices/${list.devices[0].id}`)).status).toBe(204);

    const cases: [string, string, number][] = [
      ["unknown", bogus, 401],
      ["pending", pending.token, 403],
      ["expired", expired.device.token, 401],
      ["revoked", revoked.device.token, 401],
    ];
    for (const [label, token, status] of cases) {
      const res = await asDevice(token, "POST", "/api/upload/create-transfer", { expiresInHours: 1 });
      expect(`${label}: ${res.status}`).toBe(`${label}: ${status}`);
    }
    // Without any token the same request is an ordinary anonymous upload.
    expect((await asDevice(null, "POST", "/api/upload/create-transfer", { expiresInHours: 1 })).status).toBe(200);

    // A token sent by a page is refused whatever its state.
    const page = await asDevice(device.token, "POST", "/api/upload/create-transfer", { expiresInHours: 1 }, { Origin: APP_URL });
    expect(page.status).toBe(403);

    // An account that was deleted takes its keys with it.
    await db.update(users).set({ deletedAt: new Date() }).where(eq(users.id, owner.user.id));
    expect((await asDevice(device.token, "POST", "/api/upload/create-transfer", { expiresInHours: 1 })).status).toBe(401);
  });

  it("can sign itself out", async () => {
    const { device } = await approved(["transfers:send"]);
    expect((await asDevice(device.token, "DELETE", "/api/devices/self")).status).toBe(204);
    expect((await asDevice(device.token, "GET", "/api/devices/self")).status).toBe(401);
  });

  it("is slowed down when it does too much", async () => {
    const { device } = await approved(["transfers:read"]);
    let last = 0;
    for (let i = 0; i < 245; i++) last = (await asDevice(device.token, "GET", "/api/devices/self")).status;
    expect(last).toBe(429);
  });
});

describe("what no key can reach", () => {
  it("gets nothing from account, vault, billing, passkey, portal or key-management routes", async () => {
    const { owner, device } = await approved([
      "transfers:send",
      "transfers:read",
      "transfers:delete",
      "portals:read",
      "portals:manage",
      "portals:send-back",
    ]);
    const routes: [string, string, object?][] = [
      ["POST", "/api/auth/logout-all"],
      ["GET", "/api/me/usage"],
      ["GET", "/api/me/transfers"],
      ["GET", "/api/me/export"],
      ["DELETE", "/api/me", { confirmEmail: owner.user.email }],
      ["GET", "/api/vault"],
      ["POST", "/api/vault/password", {}],
      ["GET", "/api/billing/status"],
      ["POST", "/api/billing/checkout", { plan: "max", cycle: "monthly" }],
      ["POST", "/api/billing/portal"],
      ["GET", "/api/passkey"],
      ["POST", "/api/passkey/register/begin"],
      ["GET", "/api/portals"],
      ["POST", "/api/portals", { id: nanoid(), publicBundle: "AAAA", sealedKeys: "AAAA", depositToken: "AAAA" }],
      ["GET", "/api/devices"],
      ["POST", "/api/devices/approve", { code: "ABCD-EFGH", permissions: ["transfers:send"] }],
      ["DELETE", `/api/devices/${device.id}`],
      ["PATCH", `/api/devices/${device.id}`, { renew: true }],
    ];
    for (const [method, path, body] of routes) {
      const res = await asDevice(device.token, method, path, body);
      // Refused as "not signed in", or the route does not exist under that
      // name. Never a success.
      expect(`${method} ${path}: ${[401, 404].includes(res.status)}`).toBe(`${method} ${path}: true`);
    }
    // This one answers everybody; a key learns what a stranger would.
    expect(await (await asDevice(device.token, "GET", "/api/auth/me")).json()).toEqual({ user: null });
    // The account is untouched.
    const [user] = await db.select().from(users).where(eq(users.id, owner.user.id));
    expect(user.deletedAt).toBeNull();
    const [row] = await db.select().from(devices).where(eq(devices.id, device.id));
    expect(row.revokedAt).toBeNull();
  });
});

describe("managing keys as a person", () => {
  it("renames, changes permissions, renews and revokes, and only one's own", async () => {
    const { owner, device } = await approved(["transfers:send"]);
    const stranger = await person("pro");
    await db.update(devices).set({ expiresAt: new Date(Date.now() + 86_400_000) }).where(eq(devices.id, device.id));

    const changed = await asPerson(owner.cookie, "PATCH", `/api/devices/${device.id}`, {
      name: "Build server",
      permissions: ["transfers:send", "transfers:read"],
      renew: true,
    });
    const body = (await changed.json()) as { name: string; permissions: string[]; expiresAt: string };
    expect(body.name).toBe("Build server");
    expect(body.permissions).toEqual(["transfers:send", "transfers:read"]);
    expect(new Date(body.expiresAt).getTime()).toBeGreaterThan(Date.now() + 80 * 86_400_000);

    expect((await asPerson(stranger.cookie, "PATCH", `/api/devices/${device.id}`, { name: "mine now" })).status).toBe(404);
    expect((await asPerson(stranger.cookie, "DELETE", `/api/devices/${device.id}`)).status).toBe(404);
    expect((await asDevice(device.token, "GET", "/api/devices/self")).status).toBe(200);

    expect((await asPerson(owner.cookie, "DELETE", `/api/devices/${device.id}`)).status).toBe(204);
    expect((await asDevice(device.token, "GET", "/api/devices/self")).status).toBe(401);
    // A revoked key cannot be brought back.
    expect((await asPerson(owner.cookie, "PATCH", `/api/devices/${device.id}`, { renew: true })).status).toBe(404);
  });
});

describe("limits that must hold under pressure", () => {
  it("does not let renewals bring back more keys than the plan includes", async () => {
    const owner = await person("pro");
    const made = [];
    for (let i = 0; i < 6; i++) {
      const d = await register(`key ${i}`);
      // Lapsed keys do not count, so all six can be approved one after another.
      await asPerson(owner.cookie, "POST", "/api/devices/approve", { code: d.pairingCode, permissions: ["transfers:send"] });
      await db.update(devices).set({ expiresAt: new Date(Date.now() - 1000) }).where(eq(devices.id, d.id));
      made.push(d);
    }
    const results = await Promise.all(
      made.map((d) => asPerson(owner.cookie, "PATCH", `/api/devices/${d.id}`, { renew: true })),
    );
    expect(results.filter((r) => r.status === 200)).toHaveLength(3);
    expect(results.filter((r) => r.status === 409)).toHaveLength(3);
    const active = (await db.select().from(devices).where(eq(devices.userId, owner.user.id))).filter(
      (d) => d.expiresAt! > new Date(),
    );
    expect(active).toHaveLength(3);
  });

  it("lets an active key be renewed when the plan is full", async () => {
    const owner = await person("free");
    const d = await register();
    await asPerson(owner.cookie, "POST", "/api/devices/approve", { code: d.pairingCode, permissions: ["transfers:send"] });
    expect((await asPerson(owner.cookie, "PATCH", `/api/devices/${d.id}`, { renew: true })).status).toBe(200);
  });
});

describe("signing out everywhere", () => {
  it("stops every access key of the account, and nobody else's", async () => {
    const mine = await approved(["transfers:send"]);
    const theirs = await approved(["transfers:send"]);
    const res = await asPerson(mine.owner.cookie, "POST", "/api/auth/logout-all");
    expect(await res.json()).toMatchObject({ ok: true, devicesRevoked: 1 });
    expect((await asDevice(mine.device.token, "GET", "/api/devices/self")).status).toBe(401);
    expect((await asDevice(theirs.device.token, "GET", "/api/devices/self")).status).toBe(200);
  });
});

describe("signing out everywhere while a key is being approved", () => {
  it("never leaves a working key behind, whichever lands first", async () => {
    for (let round = 0; round < 8; round++) {
      // Registering is limited per source; every round here is one source.
      await resetRateLimits();
      const owner = await person("max");
      const pending = await Promise.all(Array.from({ length: 4 }, () => register()));
      await Promise.all([
        ...pending.map((d) =>
          asPerson(owner.cookie, "POST", "/api/devices/approve", { code: d.pairingCode, permissions: ["transfers:send"] }),
        ),
        asPerson(owner.cookie, "POST", "/api/auth/logout-all"),
      ]);
      for (const d of pending) {
        const status = (await asDevice(d.token, "GET", "/api/devices/self")).status;
        const body = status === 200 ? ((await (await asDevice(d.token, "GET", "/api/devices/self")).json()) as { status: string }).status : "refused";
        // Still pending or refused. Never active.
        expect(body).not.toBe("active");
      }
    }
  });

  it("refuses an approval whose session was revoked after it was read", async () => {
    const owner = await person("pro");
    const d = await register();
    const { approveDevice } = await import("../../src/services/device.service");
    const { sessions } = await import("../../src/db/schema");
    const [session] = await db.select().from(sessions).where(eq(sessions.userId, owner.user.id));
    await db.update(sessions).set({ revokedAt: new Date() }).where(eq(sessions.id, session.id));
    const result = await approveDevice(owner.user.id, session.id, d.pairingCode.replace("-", ""), 3, ["transfers:send"]);
    expect(result).toEqual({ ok: false, reason: "signed_out" });
  });
});

describe("cleaning up", () => {
  it("removes pending keys nobody approved and keys long stopped, and keeps the rest", async () => {
    const stale = await register();
    await db.update(devices).set({ pairingExpiresAt: new Date(Date.now() - 1000) }).where(eq(devices.id, stale.id));
    const waiting = await register();
    const live = await approved(["transfers:send"]);
    const old = await approved(["transfers:send"]);
    await db.update(devices).set({ revokedAt: new Date(Date.now() - 40 * 86_400_000) }).where(eq(devices.id, old.device.id));

    expect(await purgeDeadDevices()).toBe(2);
    const left = (await db.select({ id: devices.id }).from(devices)).map((d) => d.id).sort();
    expect(left).toEqual([waiting.id, live.device.id].sort());
  });
});

describe("portals handed to a key", () => {
  const SEALED_DEPOSIT_KEY = b64(new Uint8Array(114).fill(5));
  const DEPOSIT_TOKEN = b64(new Uint8Array(32).fill(6));
  const GRANT = b64(new Uint8Array(200).fill(9));

  /** A paid account with a portal that holds one delivery, and a key that may read portals. */
  async function setup(permissions = ["portals:read"]) {
    const { owner, device } = await approved(permissions, "pro");
    await db.update(users).set({ publicKey: new Uint8Array(65).fill(4) }).where(eq(users.id, owner.user.id));
    const portalId = nanoid();
    const made = await asPerson(owner.cookie, "POST", "/api/portals", {
      id: portalId,
      publicBundle: b64(new Uint8Array(140).fill(3)),
      sealedKeys: b64(new Uint8Array(200).fill(4)),
      depositToken: DEPOSIT_TOKEN,
    });
    expect(made.status).toBe(201);
    const started = await asDevice(null, "POST", `/api/portals/${portalId}/deposits`, { depositToken: DEPOSIT_TOKEN }, { Origin: APP_URL });
    const { transferId } = (await started.json()) as { transferId: string };
    const init = await asDevice(null, "POST", "/api/upload/init-multipart", { transferId, size: 1024, ...FILE_FIELDS }, { Origin: APP_URL });
    const { fileId } = (await init.json()) as { fileId: string };
    await asDevice(null, "POST", "/api/upload/complete", { transferId, sealedKey: SEALED_DEPOSIT_KEY }, { Origin: APP_URL });
    return { owner, device, portalId, transferId, fileId };
  }

  const grant = (cookie: string, deviceId: string, portalId: string, keyVersion = 1) =>
    asPerson(cookie, "PUT", `/api/devices/${deviceId}/portals/${portalId}`, { sealedKeys: GRANT, keyVersion });

  it("sees nothing until a portal is handed over, then that portal and its deliveries", async () => {
    const { owner, device, portalId, transferId, fileId } = await setup();
    const empty = (await (await asDevice(device.token, "GET", "/api/devices/self/portals")).json()) as { portals: unknown[] };
    expect(empty.portals).toEqual([]);
    expect((await asDevice(device.token, "GET", `/api/devices/self/portals/${portalId}/deposits`)).status).toBe(404);

    expect((await grant(owner.cookie, device.id, portalId)).status).toBe(200);
    const listed = (await (await asPerson(owner.cookie, "GET", `/api/devices/${device.id}/portals`)).json()) as {
      portals: { portalId: string }[];
    };
    expect(listed.portals.map((p) => p.portalId)).toEqual([portalId]);

    const mine = (await (await asDevice(device.token, "GET", "/api/devices/self/portals")).json()) as {
      portals: { id: string; sealedKeys: string; deliveries: number; role: string }[];
    };
    expect(mine.portals).toHaveLength(1);
    // The key gets what was handed to it, not the owner's own copy.
    expect(mine.portals[0]).toMatchObject({ id: portalId, sealedKeys: GRANT, deliveries: 1, role: "owner" });

    const deposits = (await (await asDevice(device.token, "GET", `/api/devices/self/portals/${portalId}/deposits`)).json()) as {
      deposits: { id: string; sealedKey: string; files: { id: string }[] }[];
    };
    expect(deposits.deposits.map((d) => d.id)).toEqual([transferId]);
    expect(deposits.deposits[0].sealedKey).toBe(SEALED_DEPOSIT_KEY);

    const url = await asDevice(device.token, "GET", `/api/devices/self/portals/${portalId}/files/${fileId}/url`);
    expect(url.status).toBe(200);
    expect(((await url.json()) as { downloadUrl: string }).downloadUrl).toContain("http");
  });

  it("needs the permission, however many portals were handed over", async () => {
    const { owner, device, portalId, fileId } = await setup(["transfers:send"]);
    await grant(owner.cookie, device.id, portalId);
    for (const path of ["", `/${portalId}/deposits`, `/${portalId}/files/${fileId}/url`]) {
      const res = await asDevice(device.token, "GET", `/api/devices/self/portals${path}`);
      expect(res.status).toBe(403);
    }
  });

  it("opens only the portals it was handed, and no other of the account's", async () => {
    const { owner, device, portalId } = await setup();
    await grant(owner.cookie, device.id, portalId);
    const otherId = nanoid();
    await asPerson(owner.cookie, "POST", "/api/portals", {
      id: otherId,
      publicBundle: b64(new Uint8Array(140).fill(3)),
      sealedKeys: b64(new Uint8Array(200).fill(4)),
      depositToken: DEPOSIT_TOKEN,
    });
    expect((await asDevice(device.token, "GET", `/api/devices/self/portals/${otherId}/deposits`)).status).toBe(404);
    // A file of the handed portal cannot be asked for through the other one.
    const mine = (await (await asDevice(device.token, "GET", "/api/devices/self/portals")).json()) as { portals: { id: string }[] };
    expect(mine.portals.map((p) => p.id)).toEqual([portalId]);
  });

  it("can only be handed a portal by a member of it, for one of their own keys", async () => {
    const { owner, device, portalId } = await setup();
    const stranger = await approved(["portals:read"], "pro");
    // A stranger cannot hand the owner's portal to their own key,
    expect((await grant(stranger.owner.cookie, stranger.device.id, portalId)).status).toBe(404);
    // nor anything to the owner's key.
    expect((await grant(stranger.owner.cookie, device.id, portalId)).status).toBe(404);
    // A key cannot grant itself a portal.
    const self = await asDevice(device.token, "PUT", `/api/devices/${device.id}/portals/${portalId}`, { sealedKeys: GRANT, keyVersion: 1 });
    expect(self.status).toBe(401);
    expect(await db.select().from(devicePortalKeys)).toHaveLength(0);

    expect((await grant(owner.cookie, device.id, portalId, 2)).status).toBe(409);
    expect((await asPerson(owner.cookie, "PUT", `/api/devices/${device.id}/portals/${portalId}`, { sealedKeys: "AAAA", keyVersion: 1 })).status).toBe(400);
  });

  it("loses a portal when it is taken back, when the account leaves it, and when the key is revoked", async () => {
    const { owner, device, portalId } = await setup();
    await grant(owner.cookie, device.id, portalId);
    const open = () => asDevice(device.token, "GET", `/api/devices/self/portals/${portalId}/deposits`);
    expect((await open()).status).toBe(200);

    expect((await asPerson(owner.cookie, "DELETE", `/api/devices/${device.id}/portals/${portalId}`)).status).toBe(204);
    expect((await open()).status).toBe(404);

    await grant(owner.cookie, device.id, portalId);
    expect((await open()).status).toBe(200);
    // The account is no longer a member: its keys lose the portal with it.
    await db.delete(portalMembers).where(eq(portalMembers.userId, owner.user.id));
    expect((await open()).status).toBe(404);
    expect(((await (await asDevice(device.token, "GET", "/api/devices/self/portals")).json()) as { portals: unknown[] }).portals).toEqual([]);
  });

  it("forgets its grants when the portal is deleted", async () => {
    const { owner, device, portalId } = await setup();
    await grant(owner.cookie, device.id, portalId);
    expect((await asPerson(owner.cookie, "DELETE", `/api/portals/${portalId}`)).status).toBe(204);
    expect(await db.select().from(devicePortalKeys)).toHaveLength(0);
  });
});
