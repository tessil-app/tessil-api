// User keypair storage. The server holds a public key and an opaque
// wrapped private key; see docs/adr/0014-portal-keys-and-vault-items.md.

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import { eq } from "drizzle-orm";
import { createApp } from "../../src/app";
import { db } from "../../src/db";
import { sessions, users, vaultItems } from "../../src/db/schema";
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
beforeEach(resetDb);
afterAll(resetDb);

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");

async function realPublicKey(): Promise<Uint8Array> {
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
    "deriveBits",
  ]);
  return new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
}

async function userWithVault() {
  const authed = await createAuthedUser();
  await createUserVault(authed.user.id, {
    saltPassword: new Uint8Array(16),
    saltPhrase: new Uint8Array(16),
    wrapPassword: new Uint8Array(60),
    wrapPhrase: new Uint8Array(60),
    kdfVersion: 1,
  });
  return authed;
}

function postKeypair(cookie: string, body: object) {
  return app.handle(
    authedRequest(cookie, `${APP_URL}/api/me/vault/keypair`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    }),
  );
}

const WRAPPED = b64(new Uint8Array(170).fill(9));

describe("POST /api/me/vault/keypair", () => {
  it("stores the keypair and returns it with the vault status", async () => {
    const { user, cookie } = await userWithVault();
    const publicKey = b64(await realPublicKey());

    const res = await postKeypair(cookie, { publicKey, wrappedPrivateKey: WRAPPED });
    expect(res.status).toBe(201);

    const status = await app.handle(authedRequest(cookie, `${APP_URL}/api/me/vault`, {}));
    const body = (await status.json()) as { publicKey: string; wrappedPrivateKey: string };
    expect(body.publicKey).toBe(publicKey);
    expect(body.wrappedPrivateKey).toBe(WRAPPED);

    const [row] = await db.select().from(users).where(eq(users.id, user.id));
    expect(row.publicKey).not.toBeNull();
  });

  it("refuses to replace an existing keypair", async () => {
    const { user, cookie } = await userWithVault();
    const first = b64(await realPublicKey());
    await postKeypair(cookie, { publicKey: first, wrappedPrivateKey: WRAPPED });

    const again = await postKeypair(cookie, {
      publicKey: b64(await realPublicKey()),
      wrappedPrivateKey: WRAPPED,
    });
    expect(again.status).toBe(409);

    const [row] = await db.select().from(users).where(eq(users.id, user.id));
    expect(b64(row.publicKey!)).toBe(first);
    expect(await db.select().from(vaultItems).where(eq(vaultItems.userId, user.id))).toHaveLength(1);
  });

  it("requires a vault", async () => {
    const { cookie } = await createAuthedUser();
    const res = await postKeypair(cookie, {
      publicKey: b64(await realPublicKey()),
      wrappedPrivateKey: WRAPPED,
    });
    expect(res.status).toBe(409);
  });

  it("rejects bytes that are not a point on the curve", async () => {
    const { cookie } = await userWithVault();
    const offCurve = new Uint8Array(65).fill(1);
    offCurve[0] = 0x04;
    const res = await postKeypair(cookie, { publicKey: b64(offCurve), wrappedPrivateKey: WRAPPED });
    expect(res.status).toBe(400);

    const short = await postKeypair(cookie, {
      publicKey: b64(await realPublicKey()),
      wrappedPrivateKey: b64(new Uint8Array(10)),
    });
    expect(short.status).toBe(400);
  });

  it("requires a session", async () => {
    const res = await app.handle(
      new Request(`${APP_URL}/api/me/vault/keypair`, {
        method: "POST",
        headers: JSON_HEADERS,
        body: JSON.stringify({ publicKey: "x", wrappedPrivateKey: "y" }),
      }),
    );
    expect(res.status).toBe(401);
  });

  it("is removed with the account", async () => {
    const { user, cookie } = await userWithVault();
    await postKeypair(cookie, { publicKey: b64(await realPublicKey()), wrappedPrivateKey: WRAPPED });
    await db.delete(sessions).where(eq(sessions.userId, user.id));
    await db.delete(users).where(eq(users.id, user.id));
    expect(await db.select().from(vaultItems).where(eq(vaultItems.userId, user.id))).toHaveLength(0);
  });
});
