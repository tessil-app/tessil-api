// Cleanup / expiry / GC job. Closes the HIGH test gap in audit doc 29 §5:
// the job that deletes user data from Postgres *and* R2 had no automated proof
// that it deletes the right rows, removes the R2 objects, or spares live
// transfers. A regression here either leaks expired files or destroys live ones.

import { afterAll, beforeEach, beforeAll, describe, expect, it, mock } from "bun:test";
import { eq } from "drizzle-orm";
import { db } from "../../src/db";
import { files, transferEvents, transfers } from "../../src/db/schema";
import {
  cleanupAbandonedTransfers,
  cleanupExpiredTransfers,
  cleanupSoftDeletedTransfers,
} from "../../src/services/cleanup.service";
import { createFile, createTransfer } from "../../src/services/file.service";
import { defaultR2Mock } from "../helpers/r2-mock";
import { ensureMigrations, resetDb } from "../helpers/db";

// Keys passed to deleteFromR2 during a sweep. Asserting on this is the only way
// to prove storage is purged and not just the DB row.
let deletedKeys: string[] = [];

function recordingR2Mock() {
  mock.module("../../src/services/r2.service", () => ({
    ...defaultR2Mock(),
    deleteFromR2: async (key: string) => {
      deletedKeys.push(key);
    },
  }));
}

function restoreDefaultR2Mock() {
  mock.module("../../src/services/r2.service", () => defaultR2Mock());
}

beforeAll(async () => {
  await ensureMigrations();
});

beforeEach(async () => {
  await resetDb();
  deletedKeys = [];
  recordingR2Mock();
});

afterAll(async () => {
  await resetDb();
  restoreDefaultR2Mock();
});

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

async function backdateCreatedAt(transferId: string, minutesAgo: number) {
  await db
    .update(transfers)
    .set({ createdAt: new Date(Date.now() - minutesAgo * 60_000) })
    .where(eq(transfers.id, transferId));
}

async function backdateFileCreatedAt(fileId: string, minutesAgo: number) {
  await db
    .update(files)
    .set({ createdAt: new Date(Date.now() - minutesAgo * 60_000) })
    .where(eq(files.id, fileId));
}

async function rowExists(transferId: string): Promise<boolean> {
  const rows = await db.select({ id: transfers.id }).from(transfers).where(eq(transfers.id, transferId));
  return rows.length > 0;
}

// ─── 1. Expired transfers are deleted from Postgres and R2 ──────────────────

describe("cleanupExpiredTransfers", () => {
  it("hard-deletes an expired transfer, its files, and its R2 objects", async () => {
    // Negative expiry puts expiresAt in the past.
    const transfer = await createTransfer(-1);
    const fileA = await seedFile(transfer.id, 2048);
    const fileB = await seedFile(transfer.id, 4096);
    await db.update(transfers).set({ isCompleted: true }).where(eq(transfers.id, transfer.id));

    const count = await cleanupExpiredTransfers();

    expect(count).toBe(1);
    expect(await rowExists(transfer.id)).toBe(false);
    const remainingFiles = await db.select().from(files).where(eq(files.transferId, transfer.id));
    expect(remainingFiles).toHaveLength(0);
    // Both objects purged from storage, not just the DB rows.
    expect(deletedKeys.sort()).toEqual([fileA.r2Key, fileB.r2Key].sort());
  });

  it("leaves a live transfer completely untouched", async () => {
    const live = await createTransfer(24);
    await seedFile(live.id);

    const count = await cleanupExpiredTransfers();

    expect(count).toBe(0);
    expect(await rowExists(live.id)).toBe(true);
    expect(await db.select().from(files).where(eq(files.transferId, live.id))).toHaveLength(1);
    expect(deletedKeys).toEqual([]);
  });

  // The regression that matters most: a predicate bug that sweeps live rows.
  it("deletes only the expired row when live and expired coexist", async () => {
    const expired = await createTransfer(-2);
    const live = await createTransfer(48);
    const expiredFile = await seedFile(expired.id);
    await seedFile(live.id);

    const count = await cleanupExpiredTransfers();

    expect(count).toBe(1);
    expect(await rowExists(expired.id)).toBe(false);
    expect(await rowExists(live.id)).toBe(true);
    expect(deletedKeys).toEqual([expiredFile.r2Key]);
  });

  it("writes an 'expired' transfer_events row that survives deletion", async () => {
    const transfer = await createTransfer(-1);
    await seedFile(transfer.id, 512);

    await cleanupExpiredTransfers();

    const events = await db
      .select()
      .from(transferEvents)
      .where(eq(transferEvents.transferId, transfer.id));
    expect(events).toHaveLength(1);
    expect(events[0]!.event).toBe("expired");
    expect(events[0]!.fileCount).toBe(1);
    expect(events[0]!.totalBytes).toBe(512);
  });

  it("skips soft-deleted rows, which the owner-delete sweep owns instead", async () => {
    const transfer = await createTransfer(-1);
    await seedFile(transfer.id);
    await db.update(transfers).set({ isDeleted: true }).where(eq(transfers.id, transfer.id));

    const count = await cleanupExpiredTransfers();

    expect(count).toBe(0);
    expect(await rowExists(transfer.id)).toBe(true);
  });
});

// ─── 2. Abandoned uploads ───────────────────────────────────────────────────

describe("cleanupAbandonedTransfers", () => {
  it("removes an incomplete transfer with no files after the 30 minute cutoff", async () => {
    const transfer = await createTransfer(24);
    await backdateCreatedAt(transfer.id, 45);

    const count = await cleanupAbandonedTransfers();

    expect(count).toBe(1);
    expect(await rowExists(transfer.id)).toBe(false);
  });

  // Upload URLs stay valid for 4 hours, so a large file on a slow line
  // is still arriving long after the transfer was created.
  it("spares an old transfer whose upload URLs are still valid", async () => {
    const transfer = await createTransfer(24);
    const file = await seedFile(transfer.id);
    await backdateCreatedAt(transfer.id, 180);
    await backdateFileCreatedAt(file.id, 170);

    const count = await cleanupAbandonedTransfers();

    expect(count).toBe(0);
    expect(await rowExists(transfer.id)).toBe(true);
  });

  it("removes an incomplete transfer once its upload URLs have lapsed", async () => {
    const transfer = await createTransfer(24);
    const file = await seedFile(transfer.id);
    await backdateCreatedAt(transfer.id, 300);
    await backdateFileCreatedAt(file.id, 290);

    const count = await cleanupAbandonedTransfers();

    expect(count).toBe(1);
    expect(await rowExists(transfer.id)).toBe(false);
    expect(deletedKeys).toEqual([file.r2Key]);
  });

  it("keeps the rows when storage refuses the delete, then retries", async () => {
    const transfer = await createTransfer(24);
    await backdateCreatedAt(transfer.id, 45);
    const file = await seedFile(transfer.id);
    await backdateFileCreatedAt(file.id, 290);
    await backdateCreatedAt(transfer.id, 300);

    mock.module("../../src/services/r2.service", () => ({
      ...defaultR2Mock(),
      deleteFromR2: async () => {
        throw new Error("simulated storage outage");
      },
    }));
    expect(await cleanupAbandonedTransfers()).toBe(0);
    expect(await rowExists(transfer.id)).toBe(true);

    recordingR2Mock();
    expect(await cleanupAbandonedTransfers()).toBe(1);
    expect(await rowExists(transfer.id)).toBe(false);
    expect(deletedKeys).toEqual([file.r2Key]);
  });

  it("spares a recent incomplete transfer still mid-upload", async () => {
    const transfer = await createTransfer(24);
    await seedFile(transfer.id);
    await backdateCreatedAt(transfer.id, 5);

    const count = await cleanupAbandonedTransfers();

    expect(count).toBe(0);
    expect(await rowExists(transfer.id)).toBe(true);
  });

  it("spares an old transfer that completed successfully", async () => {
    const transfer = await createTransfer(24);
    await seedFile(transfer.id);
    await db.update(transfers).set({ isCompleted: true }).where(eq(transfers.id, transfer.id));
    await backdateCreatedAt(transfer.id, 120);

    const count = await cleanupAbandonedTransfers();

    expect(count).toBe(0);
    expect(await rowExists(transfer.id)).toBe(true);
  });
});

// ─── 3. Owner-initiated deletes ─────────────────────────────────────────────

describe("cleanupSoftDeletedTransfers", () => {
  it("purges a soft-deleted transfer and its R2 objects", async () => {
    const transfer = await createTransfer(24);
    const file = await seedFile(transfer.id);
    await db.update(transfers).set({ isDeleted: true }).where(eq(transfers.id, transfer.id));

    const count = await cleanupSoftDeletedTransfers();

    expect(count).toBe(1);
    expect(await rowExists(transfer.id)).toBe(false);
    expect(deletedKeys).toEqual([file.r2Key]);
  });

  it("leaves rows that were never soft-deleted", async () => {
    const transfer = await createTransfer(24);
    await seedFile(transfer.id);

    const count = await cleanupSoftDeletedTransfers();

    expect(count).toBe(0);
    expect(await rowExists(transfer.id)).toBe(true);
    expect(deletedKeys).toEqual([]);
  });
});
