// Atomic download-slot claim. See docs/audit/25-external-audit-findings.md §B.1.
//
// `claimDownloadSlot` takes a file ID and collapses (expired / deleted / not completed / cap
// reached) into a single null return so the route layer can map all four to
// the same 404 — preserving the existence-oracle policy from doc 20 §4.
//
// The interesting case is the race: a burst of (cap + N) concurrent requests
// on a transfer at (max_downloads - 1) must yield exactly `cap` successful
// claims, not `cap + 1`. Pre-fix, two concurrent reads could both see
// `downloadCount < maxDownloads` and both increment, overshooting the limit.

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import { eq } from "drizzle-orm";
import { createApp } from "../../src/app";
import { db } from "../../src/db";
import { transfers } from "../../src/db/schema";
import {
  claimDownloadSlot,
  createTransfer,
  createFile,
  completeTransfer,
  markTransferAsDeleted,
} from "../../src/services/file.service";
import { ensureMigrations, resetDb } from "../helpers/db";

const APP_URL = process.env.APP_URL!;
const ORIGIN_HEADER = { Origin: APP_URL };

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

function seedFile(transferId: string) {
  return createFile({
    transferId,
    encryptedName: "x".repeat(32),
    encryptedNameIv: "y".repeat(24),
    fileIv: "z".repeat(24),
    size: 1024,
    mimeType: "application/octet-stream",
  });
}

async function seedCompletedTransfer(opts: {
  maxDownloads?: number | null;
  expiresInHours?: number;
} = {}) {
  const transfer = await createTransfer(opts.expiresInHours ?? 1, undefined, opts.maxDownloads ?? undefined);
  const file = await seedFile(transfer.id);
  await completeTransfer(transfer.id);
  return { transfer, file };
}

async function readDownloadCount(transferId: string): Promise<number> {
  const [row] = await db
    .select({ downloadCount: transfers.downloadCount })
    .from(transfers)
    .where(eq(transfers.id, transferId));
  return row?.downloadCount ?? 0;
}

// ─── 1. Service-level claim semantics ──────────────────────────────────────

describe("claimDownloadSlot — service-level", () => {
  it("increments once when transfer has no cap", async () => {
    const { transfer, file } = await seedCompletedTransfer({ maxDownloads: null });
    const result = await claimDownloadSlot(file.id);
    expect(result).toBe(1);
    expect(await readDownloadCount(transfer.id)).toBe(1);
  });

  it("returns null when the cap is exhausted", async () => {
    const { transfer, file } = await seedCompletedTransfer({ maxDownloads: 2 });
    expect(await claimDownloadSlot(file.id)).toBe(1);
    expect(await claimDownloadSlot(file.id)).toBe(2);
    expect(await claimDownloadSlot(file.id)).toBeNull();
    // Counter must not move past the cap.
    expect(await readDownloadCount(transfer.id)).toBe(2);
  });

  it("returns null when the transfer is soft-deleted", async () => {
    const { transfer, file } = await seedCompletedTransfer();
    await markTransferAsDeleted(transfer.id);
    expect(await claimDownloadSlot(file.id)).toBeNull();
    expect(await readDownloadCount(transfer.id)).toBe(0);
  });

  it("returns null when the transfer is not yet completed", async () => {
    const transfer = await createTransfer(1);
    const file = await seedFile(transfer.id);
    // No completeTransfer() call — upload still in progress.
    expect(await claimDownloadSlot(file.id)).toBeNull();
    expect(await readDownloadCount(transfer.id)).toBe(0);
  });

  it("returns null when the transfer has expired", async () => {
    const { transfer, file } = await seedCompletedTransfer();
    await db
      .update(transfers)
      .set({ expiresAt: new Date(Date.now() - 60_000) })
      .where(eq(transfers.id, transfer.id));
    expect(await claimDownloadSlot(file.id)).toBeNull();
  });

  // The key race: pre-fix, a burst of N concurrent claims on a transfer
  // capped at C (with C < N) could overshoot because each call did a
  // read-then-increment in two SQL statements. The atomic UPDATE...WHERE
  // collapses gate + increment into one statement, so exactly C succeed.
  it("a concurrent burst never overshoots the cap", async () => {
    const CAP = 3;
    const BURST = 20;
    const { transfer, file } = await seedCompletedTransfer({ maxDownloads: CAP });

    const results = await Promise.all(
      Array.from({ length: BURST }, () => claimDownloadSlot(file.id)),
    );

    const successes = results.filter((r) => r !== null).length;
    const failures = results.filter((r) => r === null).length;

    expect(successes).toBe(CAP);
    expect(failures).toBe(BURST - CAP);
    expect(await readDownloadCount(transfer.id)).toBe(CAP);
  });
});

// The cap is per file: one download of a transfer means every file once.
describe("claimDownloadSlot: transfers with several files", () => {
  it("lets one recipient fetch every file on a single download", async () => {
    const transfer = await createTransfer(1, undefined, 1);
    const first = await seedFile(transfer.id);
    const second = await seedFile(transfer.id);
    const third = await seedFile(transfer.id);
    await completeTransfer(transfer.id);

    // The transfer counts complete downloads, so it stays at 0 until
    // the last file has gone out.
    expect(await claimDownloadSlot(first.id)).toBe(0);
    expect(await claimDownloadSlot(second.id)).toBe(0);
    expect(await claimDownloadSlot(third.id)).toBe(1);

    expect(await claimDownloadSlot(first.id)).toBeNull();
    expect(await readDownloadCount(transfer.id)).toBe(1);
  });

  it("caps each file on its own", async () => {
    const transfer = await createTransfer(1, undefined, 1);
    const first = await seedFile(transfer.id);
    const second = await seedFile(transfer.id);
    await completeTransfer(transfer.id);

    expect(await claimDownloadSlot(first.id)).toBe(0);
    expect(await claimDownloadSlot(first.id)).toBeNull();
    expect(await claimDownloadSlot(second.id)).toBe(1);
  });
});

// ─── 2. Route-level surface — /api/download/file/:id/url ───────────────────

describe("GET /api/download/file/:id/url — atomic claim wiring", () => {
  it("returns 404 (not 200) once the cap is hit", async () => {
    const { transfer, file } = await seedCompletedTransfer({ maxDownloads: 1 });

    const ok = await app.handle(
      new Request(`${APP_URL}/api/download/file/${file.id}/url`, {
        headers: { ...ORIGIN_HEADER, "cf-connecting-ip": "203.0.113.10" },
      }),
    );
    expect(ok.status).toBe(200);

    const blocked = await app.handle(
      new Request(`${APP_URL}/api/download/file/${file.id}/url`, {
        headers: { ...ORIGIN_HEADER, "cf-connecting-ip": "203.0.113.11" },
      }),
    );
    expect(blocked.status).toBe(404);
    expect(await readDownloadCount(transfer.id)).toBe(1);
  });

  it("returns 404 on a soft-deleted transfer without revealing existence", async () => {
    const { transfer, file } = await seedCompletedTransfer();
    await markTransferAsDeleted(transfer.id);

    const res = await app.handle(
      new Request(`${APP_URL}/api/download/file/${file.id}/url`, {
        headers: { ...ORIGIN_HEADER, "cf-connecting-ip": "203.0.113.20" },
      }),
    );
    expect(res.status).toBe(404);
    expect(await readDownloadCount(transfer.id)).toBe(0);
  });

  it("returns 404 on an incomplete transfer", async () => {
    const transfer = await createTransfer(1);
    const file = await createFile({
      transferId: transfer.id,
      encryptedName: "x".repeat(32),
      encryptedNameIv: "y".repeat(24),
      fileIv: "z".repeat(24),
      size: 1024,
      mimeType: "application/octet-stream",
    });

    const res = await app.handle(
      new Request(`${APP_URL}/api/download/file/${file.id}/url`, {
        headers: { ...ORIGIN_HEADER, "cf-connecting-ip": "203.0.113.30" },
      }),
    );
    expect(res.status).toBe(404);
    expect(await readDownloadCount(transfer.id)).toBe(0);
  });
});
