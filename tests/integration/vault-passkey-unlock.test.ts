// Passkeys that can unlock the vault. The server stores a salt and an
// opaque wrap per passkey; see docs/adr/0014, point 10.

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import { eq } from "drizzle-orm";
import { nanoid } from "nanoid";
import { createApp } from "../../src/app";
import { db } from "../../src/db";
import { authenticators, vaultPasskeyWraps } from "../../src/db/schema";
import { resetRateLimits } from "../../src/services/ratelimit.service";
import { createUserVault } from "../../src/services/vault.service";
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
const SALT = b64(new Uint8Array(32).fill(1));
const WRAP = b64(new Uint8Array(60).fill(2));

async function account(withVault = true) {
  const authed = await createAuthedUser();
  if (withVault) {
    await createUserVault(authed.user.id, {
      saltPassword: new Uint8Array(16),
      saltPhrase: new Uint8Array(16),
      wrapPassword: new Uint8Array(60),
      wrapPhrase: new Uint8Array(60),
      kdfVersion: 1,
    });
  }
  const credentialId = crypto.getRandomValues(new Uint8Array(32));
  const [passkey] = await db
    .insert(authenticators)
    .values({
      id: nanoid(),
      userId: authed.user.id,
      credentialId,
      publicKey: new Uint8Array(77),
      deviceType: "multiDevice",
      backedUp: true,
    })
    .returning();
  return { ...authed, passkey, credentialId };
}

function call(cookie: string | null, method: string, path: string, body?: object) {
  const init: RequestInit = { method, headers: JSON_HEADERS };
  if (body) init.body = JSON.stringify(body);
  const url = `${APP_URL}${path}`;
  return app.handle(cookie ? authedRequest(cookie, url, init) : new Request(url, init));
}

const wrapsOf = async (cookie: string) =>
  ((await (await call(cookie, "GET", "/api/me/vault")).json()) as {
    passkeyWraps: { authenticatorId: string; credentialId: string; prfSalt: string; wrap: string }[];
  }).passkeyWraps;

describe("letting a passkey unlock the vault", () => {
  it("stores the wrap and returns it with what the browser needs", async () => {
    const { cookie, passkey, credentialId } = await account();
    expect(await wrapsOf(cookie)).toEqual([]);

    const res = await call(cookie, "PUT", `/api/me/vault/passkeys/${passkey.id}`, {
      prfSalt: SALT,
      wrap: WRAP,
    });
    expect(res.status).toBe(200);
    expect(await wrapsOf(cookie)).toEqual([
      { authenticatorId: passkey.id, credentialId: b64(credentialId), prfSalt: SALT, wrap: WRAP },
    ]);
  });

  it("replaces an earlier wrap for the same passkey", async () => {
    const { cookie, passkey } = await account();
    await call(cookie, "PUT", `/api/me/vault/passkeys/${passkey.id}`, { prfSalt: SALT, wrap: WRAP });
    const newer = b64(new Uint8Array(60).fill(9));
    await call(cookie, "PUT", `/api/me/vault/passkeys/${passkey.id}`, { prfSalt: SALT, wrap: newer });
    const wraps = await wrapsOf(cookie);
    expect(wraps).toHaveLength(1);
    expect(wraps[0].wrap).toBe(newer);
  });

  it("refuses someone else's passkey, and does not say it exists", async () => {
    const mine = await account();
    const theirs = await account();
    const res = await call(mine.cookie, "PUT", `/api/me/vault/passkeys/${theirs.passkey.id}`, {
      prfSalt: SALT,
      wrap: WRAP,
    });
    expect(res.status).toBe(404);
    expect(await db.select().from(vaultPasskeyWraps)).toHaveLength(0);
  });

  it("needs a vault, a session, and well-formed blobs", async () => {
    const noVault = await account(false);
    expect(
      (await call(noVault.cookie, "PUT", `/api/me/vault/passkeys/${noVault.passkey.id}`, { prfSalt: SALT, wrap: WRAP })).status,
    ).toBe(409);

    const { cookie, passkey } = await account();
    expect(
      (await call(null, "PUT", `/api/me/vault/passkeys/${passkey.id}`, { prfSalt: SALT, wrap: WRAP })).status,
    ).toBe(401);
    expect(
      (await call(cookie, "PUT", `/api/me/vault/passkeys/${passkey.id}`, { prfSalt: b64(new Uint8Array(8)), wrap: WRAP })).status,
    ).toBe(400);
    expect(
      (await call(cookie, "PUT", `/api/me/vault/passkeys/${passkey.id}`, { prfSalt: SALT, wrap: b64(new Uint8Array(59)) })).status,
    ).toBe(400);
  });
});

describe("stopping it", () => {
  it("removes the wrap on request", async () => {
    const { cookie, passkey } = await account();
    await call(cookie, "PUT", `/api/me/vault/passkeys/${passkey.id}`, { prfSalt: SALT, wrap: WRAP });
    expect((await call(cookie, "DELETE", `/api/me/vault/passkeys/${passkey.id}`)).status).toBe(200);
    expect(await wrapsOf(cookie)).toEqual([]);
    expect((await call(cookie, "DELETE", `/api/me/vault/passkeys/${passkey.id}`)).status).toBe(404);
  });

  it("cannot remove another account's wrap", async () => {
    const mine = await account();
    const theirs = await account();
    await call(theirs.cookie, "PUT", `/api/me/vault/passkeys/${theirs.passkey.id}`, { prfSalt: SALT, wrap: WRAP });
    expect((await call(mine.cookie, "DELETE", `/api/me/vault/passkeys/${theirs.passkey.id}`)).status).toBe(404);
    expect(await wrapsOf(theirs.cookie)).toHaveLength(1);
  });

  it("goes with the passkey when the passkey is deleted", async () => {
    const { cookie, passkey } = await account();
    await call(cookie, "PUT", `/api/me/vault/passkeys/${passkey.id}`, { prfSalt: SALT, wrap: WRAP });
    await db.delete(authenticators).where(eq(authenticators.id, passkey.id));
    expect(await wrapsOf(cookie)).toEqual([]);
  });
});

describe("the passkey list", () => {
  it("includes each passkey's credential ID", async () => {
    const { cookie, passkey, credentialId } = await account();
    const res = await call(cookie, "GET", "/api/auth/passkeys");
    const body = (await res.json()) as { authenticators: { id: string; credentialId: string }[] };
    expect(body.authenticators).toMatchObject([{ id: passkey.id, credentialId: b64(credentialId) }]);
  });
});
