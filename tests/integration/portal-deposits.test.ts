// Deposits: uploads through a portal by an anonymous outsider, stored for
// the portal's owner. See docs/adr/0014-portal-keys-and-vault-items.md.

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import { eq } from "drizzle-orm";
import { nanoid } from "nanoid";
import { createApp } from "../../src/app";
import { db } from "../../src/db";
import { portalMembers, portals, transfers, users } from "../../src/db/schema";
import { eraseAccount } from "../../src/auth/users";
import { createFile, createTransfer, markOrphanedDepositsDeleted } from "../../src/services/file.service";
import { peekVolumeLimit, rateLimiters, resetRateLimits } from "../../src/services/ratelimit.service";
import { authedRequest, createAuthedUser, testIpContext } from "../helpers/auth";
import { ensureMigrations, resetDb } from "../helpers/db";

const APP_URL = process.env.APP_URL!;
const JSON_HEADERS = { Origin: APP_URL, "Content-Type": "application/json" };
const GB = 1024 * 1024 * 1024;

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
const SEALED_KEY = b64(new Uint8Array(114).fill(5));
const TOKEN = b64(new Uint8Array(32).fill(6));
const FILE_FIELDS = {
  contentType: "application/octet-stream",
  encryptedName: "x".repeat(32),
  encryptedNameIv: "y".repeat(24),
  fileIv: "z".repeat(24),
};

function call(cookie: string | null, method: string, path: string, body?: object) {
  const init: RequestInit = { method, headers: JSON_HEADERS };
  if (body) init.body = JSON.stringify(body);
  const url = `${APP_URL}${path}`;
  return app.handle(cookie ? authedRequest(cookie, url, init) : new Request(url, init));
}

async function ownerWithPortal(tier = "pro") {
  const authed = await createAuthedUser();
  await db
    .update(users)
    .set({ tier, publicKey: new Uint8Array(65).fill(4) })
    .where(eq(users.id, authed.user.id));
  const portalId = nanoid();
  const res = await call(authed.cookie, "POST", "/api/portals", {
    id: portalId,
    publicBundle: b64(new Uint8Array(140).fill(3)),
    sealedKeys: b64(new Uint8Array(200).fill(4)),
    depositToken: TOKEN,
  });
  expect(res.status).toBe(201);
  return { ...authed, portalId };
}

async function startDeposit(portalId: string, depositToken = TOKEN) {
  const res = await call(null, "POST", `/api/portals/${portalId}/deposits`, { depositToken });
  return { res, body: (await res.clone().json()) as { transferId: string; expiresAt: string } };
}

function addFile(transferId: string, size: number, cookie: string | null = null) {
  return call(cookie, "POST", "/api/upload/init-multipart", { transferId, size, ...FILE_FIELDS });
}

/** A whole deposit by an anonymous outsider. */
async function deposit(portalId: string, size = 1024) {
  const { res, body } = await startDeposit(portalId);
  expect(res.status).toBe(201);
  const init = await addFile(body.transferId, size);
  expect(init.status).toBe(200);
  const { fileId } = (await init.json()) as { fileId: string };
  const done = await call(null, "POST", "/api/upload/complete", {
    transferId: body.transferId,
    sealedKey: SEALED_KEY,
  });
  expect(done.status).toBe(200);
  return { transferId: body.transferId, fileId };
}

describe("depositing", () => {
  it("lets an outsider upload and a member list and fetch it", async () => {
    const { cookie, portalId } = await ownerWithPortal();
    const { transferId, fileId } = await deposit(portalId, 4096);

    const list = await call(cookie, "GET", `/api/portals/${portalId}/deposits`);
    expect(list.status).toBe(200);
    const body = (await list.json()) as {
      deposits: { id: string; sealedKey: string; files: { id: string; size: number }[] }[];
    };
    expect(body.deposits).toHaveLength(1);
    expect(body.deposits[0]).toMatchObject({ id: transferId, sealedKey: SEALED_KEY });
    expect(body.deposits[0].files).toMatchObject([{ id: fileId, size: 4096 }]);

    const url = await call(cookie, "GET", `/api/portals/${portalId}/deposits/files/${fileId}/url`);
    expect(url.status).toBe(200);
    expect(((await url.json()) as { downloadUrl: string }).downloadUrl).toContain(transferId);
  });

  it("keeps a deposit for the owner's retention period", async () => {
    const pro = await ownerWithPortal("pro");
    const max = await ownerWithPortal("max");
    const days = (iso: string) => Math.round((new Date(iso).getTime() - Date.now()) / 86_400_000);

    expect(days((await startDeposit(pro.portalId)).body.expiresAt)).toBe(30);
    expect(days((await startDeposit(max.portalId)).body.expiresAt)).toBe(90);
  });

  it("gives the depositor the owner's size limits, not anonymous ones", async () => {
    const { portalId } = await ownerWithPortal();
    const { body } = await startDeposit(portalId);
    // Anonymous senders stop at 500 MB per file and per month.
    expect((await addFile(body.transferId, 2 * GB)).status).toBe(200);
    expect((await addFile(body.transferId, 2 * GB)).status).toBe(200);
    // Still bounded by the owner's per-file cap.
    expect((await addFile(body.transferId, 6 * GB)).status).toBe(400);
  });

  it("counts deposits against the owner's storage and refuses when it is full", async () => {
    const { user, cookie, portalId } = await ownerWithPortal();
    for (let i = 0; i < 4; i++) {
      const own = await createTransfer(24, undefined, undefined, user.id);
      await createFile({ transferId: own.id, size: 4 * GB, mimeType: null, encryptedName: "n", encryptedNameIv: "i", fileIv: "f" });
    }
    // 16 of 20 GB used by the owner's own transfers.
    const { body } = await startDeposit(portalId);
    expect((await addFile(body.transferId, 3 * GB)).status).toBe(200);

    const full = await addFile(body.transferId, 2 * GB);
    expect(full.status).toBe(413);
    expect(((await full.json()) as { code: string }).code).toBe("portal_full");

    const usage = await call(cookie, "GET", "/api/me/usage");
    const storage = ((await usage.json()) as { storage: { usedBytes: number } }).storage;
    expect(storage.usedBytes).toBe(19 * GB);
  });

  it("requires the sealed key to complete, and refuses one on an ordinary transfer", async () => {
    const { portalId } = await ownerWithPortal();
    const { body } = await startDeposit(portalId);
    await addFile(body.transferId, 1024);

    const missing = await call(null, "POST", "/api/upload/complete", { transferId: body.transferId });
    expect(missing.status).toBe(400);
    const malformed = await call(null, "POST", "/api/upload/complete", {
      transferId: body.transferId,
      sealedKey: b64(new Uint8Array(20)),
    });
    expect(malformed.status).toBe(400);

    const ordinary = await createTransfer(1);
    await createFile({ transferId: ordinary.id, size: 10, mimeType: null, encryptedName: "n", encryptedNameIv: "i", fileIv: "f" });
    const stray = await call(null, "POST", "/api/upload/complete", {
      transferId: ordinary.id,
      sealedKey: SEALED_KEY,
    });
    expect(stray.status).toBe(400);
  });
});

describe("what an outsider with the link can use up", () => {
  // Space is reserved when an upload starts. Unfinished deposits in one
  // portal may hold at most one transfer's worth between them.
  it("cannot reserve the owner's whole storage with unfinished deposits", async () => {
    const { cookie, portalId } = await ownerWithPortal();
    const first = await startDeposit(portalId);
    const second = await startDeposit(portalId);
    expect((await addFile(first.body.transferId, 5 * GB)).status).toBe(200);
    expect((await addFile(second.body.transferId, 5 * GB)).status).toBe(200);

    const third = await startDeposit(portalId);
    const blocked = await addFile(third.body.transferId, 1 * GB);
    expect(blocked.status).toBe(413);

    // The owner can still send: half their storage is untouched.
    const own = await call(cookie, "POST", "/api/upload/create-transfer", { expiresInHours: 24 });
    const { transferId } = (await own.json()) as { transferId: string };
    expect((await addFile(transferId, 5 * GB, cookie)).status).toBe(200);
  });

  it("frees the reservation once a deposit completes", async () => {
    const { portalId } = await ownerWithPortal();
    const first = await startDeposit(portalId);
    await addFile(first.body.transferId, 5 * GB);
    const second = await startDeposit(portalId);
    await addFile(second.body.transferId, 5 * GB);
    await call(null, "POST", "/api/upload/complete", {
      transferId: first.body.transferId,
      sealedKey: SEALED_KEY,
    });

    const third = await startDeposit(portalId);
    expect((await addFile(third.body.transferId, 5 * GB)).status).toBe(200);
  });

  it("counts uploads against a monthly volume per portal, and gives it back on abort", async () => {
    const { user, portalId } = await ownerWithPortal();
    const config = { ...rateLimiters.monthlyUploadVolume, prefix: "portal-deposit-volume", maxBytes: 0, increment: 0 };
    const used = async () => (await peekVolumeLimit(portalId, config)).usedBytes;

    const { body } = await startDeposit(portalId);
    const init = await addFile(body.transferId, 3 * GB);
    const { fileId, uploadId } = (await init.json()) as { fileId: string; uploadId: string };
    expect(await used()).toBe(3 * GB);

    const abort = await call(null, "POST", "/api/upload/abort-multipart", {
      transferId: body.transferId,
      fileId,
      uploadId,
    });
    expect(abort.status).toBe(204);
    expect(await used()).toBe(0);

    // Parallel aborts of one file refund it once, not once each.
    const other = await addFile(body.transferId, 1 * GB);
    await other.json();
    const again = await addFile(body.transferId, 2 * GB);
    const second = (await again.json()) as { fileId: string; uploadId: string };
    expect(await used()).toBe(3 * GB);
    const aborts = await Promise.all(
      Array.from({ length: 5 }, () =>
        call(null, "POST", "/api/upload/abort-multipart", {
          transferId: body.transferId,
          fileId: second.fileId,
          uploadId: second.uploadId,
        }),
      ),
    );
    expect(aborts.every((r) => r.status === 204)).toBe(true);
    expect(await used()).toBe(1 * GB);

    // The owner's own monthly volume was never touched.
    expect((await peekVolumeLimit(user.id, { ...rateLimiters.monthlyUploadVolume, maxBytes: 0, increment: 0 })).usedBytes).toBe(0);
  });
});

describe("a portal that is not accepting", () => {
  it("refuses new deposits when switched off, and uploads to one already started", async () => {
    const { cookie, portalId } = await ownerWithPortal();
    const started = await startDeposit(portalId);
    await call(cookie, "PATCH", `/api/portals/${portalId}`, { isDisabled: true });

    const { res } = await startDeposit(portalId);
    expect(res.status).toBe(403);
    expect(((await res.json()) as { code: string }).code).toBe("portal_not_accepting");

    expect((await addFile(started.body.transferId, 1024)).status).toBe(403);
  });

  it("refuses when the owner has left the paid plans", async () => {
    const { user, portalId } = await ownerWithPortal();
    await db.update(users).set({ tier: "free" }).where(eq(users.id, user.id));
    expect((await startDeposit(portalId)).res.status).toBe(403);
  });

  // The portal's ID alone travels in places a fragment does not, such as
  // server and proxy logs. It must not be enough to fill a portal.
  it("refuses a deposit from someone who has the portal's ID but not its link", async () => {
    const { cookie, portalId } = await ownerWithPortal();
    const wrong = await startDeposit(portalId, b64(new Uint8Array(32).fill(9)));
    expect(wrong.res.status).toBe(404);
    const none = await call(null, "POST", `/api/portals/${portalId}/deposits`, {});
    expect(none.status).toBe(400);

    const list = await call(cookie, "GET", `/api/portals/${portalId}/deposits`);
    expect(((await list.json()) as { deposits: unknown[] }).deposits).toHaveLength(0);
    expect(await db.select().from(transfers).where(eq(transfers.portalId, portalId))).toHaveLength(0);
  });

  it("returns 404 for a portal that does not exist", async () => {
    expect((await startDeposit(nanoid())).res.status).toBe(404);
  });

  it("limits how many deposits one source can start", async () => {
    const { portalId } = await ownerWithPortal();
    const statuses: number[] = [];
    for (let i = 0; i < 12; i++) statuses.push((await startDeposit(portalId)).res.status);
    expect(statuses.filter((s) => s === 201)).toHaveLength(10);
    expect(statuses.filter((s) => s === 429)).toHaveLength(2);
  });
});

describe("who can read a deposit", () => {
  it("has no public download path, even for someone who knows its IDs", async () => {
    const { portalId } = await ownerWithPortal();
    const { transferId, fileId } = await deposit(portalId);

    expect((await call(null, "GET", `/api/download/transfer/${transferId}`)).status).toBe(404);
    expect((await call(null, "GET", `/api/download/file/${fileId}/url`)).status).toBe(404);
  });

  it("is hidden from accounts that are not members", async () => {
    const { portalId } = await ownerWithPortal();
    const { transferId, fileId } = await deposit(portalId);
    const stranger = await ownerWithPortal();

    expect((await call(stranger.cookie, "GET", `/api/portals/${portalId}/deposits`)).status).toBe(404);
    expect(
      (await call(stranger.cookie, "GET", `/api/portals/${portalId}/deposits/files/${fileId}/url`)).status,
    ).toBe(404);
    expect(
      (await call(stranger.cookie, "DELETE", `/api/portals/${portalId}/deposits/${transferId}`)).status,
    ).toBe(404);
    // Nor through their own portal.
    expect(
      (await call(stranger.cookie, "GET", `/api/portals/${stranger.portalId}/deposits/files/${fileId}/url`)).status,
    ).toBe(404);
    expect((await call(null, "GET", `/api/portals/${portalId}/deposits`)).status).toBe(401);
  });

  it("is readable by a second member", async () => {
    const { portalId } = await ownerWithPortal();
    const { fileId } = await deposit(portalId);
    const invited = await createAuthedUser();
    await db.insert(portalMembers).values({
      portalId,
      userId: invited.user.id,
      role: "member",
      sealedKeys: new Uint8Array(200),
    });

    expect((await call(invited.cookie, "GET", `/api/portals/${portalId}/deposits`)).status).toBe(200);
    expect(
      (await call(invited.cookie, "GET", `/api/portals/${portalId}/deposits/files/${fileId}/url`)).status,
    ).toBe(200);
  });

  it("does not list a deposit that was never completed", async () => {
    const { cookie, portalId } = await ownerWithPortal();
    const { body } = await startDeposit(portalId);
    await addFile(body.transferId, 1024);
    const list = await call(cookie, "GET", `/api/portals/${portalId}/deposits`);
    expect(((await list.json()) as { deposits: unknown[] }).deposits).toHaveLength(0);
  });
});

describe("removing deposits", () => {
  const isDeleted = async (id: string) =>
    (await db.select().from(transfers).where(eq(transfers.id, id)))[0]?.isDeleted;

  it("lets a member delete one, which frees the space at once", async () => {
    const { cookie, portalId } = await ownerWithPortal();
    const { transferId } = await deposit(portalId, 2 * GB);

    expect((await call(cookie, "DELETE", `/api/portals/${portalId}/deposits/${transferId}`)).status).toBe(204);
    expect(await isDeleted(transferId)).toBe(true);
    const usage = await call(cookie, "GET", "/api/me/usage");
    expect(((await usage.json()) as { storage: { usedBytes: number } }).storage.usedBytes).toBe(0);
  });

  it("marks every deposit deleted when the portal is deleted", async () => {
    const { cookie, portalId } = await ownerWithPortal();
    const { transferId } = await deposit(portalId);
    expect((await call(cookie, "DELETE", `/api/portals/${portalId}`)).status).toBe(204);
    expect(await isDeleted(transferId)).toBe(true);
    expect(await db.select().from(portals).where(eq(portals.id, portalId))).toHaveLength(0);
  });

  // A deposit started in the same instant its portal is deleted misses
  // the portal's own cleanup. It must not live on as an ordinary transfer.
  it("sweeps a deposit whose portal is gone, and never serves it publicly", async () => {
    const { portalId } = await ownerWithPortal();
    const { transferId, fileId } = await deposit(portalId);
    // Remove the portal without its cleanup, as a lost race would.
    await db.delete(portals).where(eq(portals.id, portalId));

    const [row] = await db.select().from(transfers).where(eq(transfers.id, transferId));
    expect(row.portalId).toBe(portalId);
    expect((await call(null, "GET", `/api/download/transfer/${transferId}`)).status).toBe(404);
    expect((await call(null, "GET", `/api/download/file/${fileId}/url`)).status).toBe(404);
    expect((await addFile(transferId, 1024)).status).toBe(409);

    expect(await markOrphanedDepositsDeleted()).toBe(1);
    expect(await isDeleted(transferId)).toBe(true);
  });

  it("marks every deposit deleted when the owner erases their account", async () => {
    const { user, portalId } = await ownerWithPortal();
    const { transferId } = await deposit(portalId);
    await eraseAccount({ user, ipContext: testIpContext(), userAgent: null });
    expect(await isDeleted(transferId)).toBe(true);
    expect(await db.select().from(users).where(eq(users.id, user.id))).toHaveLength(0);
  });
});
