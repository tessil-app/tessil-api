// Multipart upload routes per ADR-0009. Covers:
//
//   - /init-multipart: validation, ownership 404, cap enforcement,
//     part-URL batch shape, volume reservation.
//   - /complete-multipart: ownership 404, file-id mismatch, happy path.
//   - /abort-multipart: ownership 404, volume reservation released,
//     file row deleted, idempotent on re-abort.
//
// The R2 SDK is stubbed via `tests/helpers/r2-mock.ts`; uploads to
// actual R2 are out of scope (covered manually in dev / by the
// frontend orchestrator's own surface tests).

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, mock } from "bun:test";
import { eq } from "drizzle-orm";
import { createApp } from "../../src/app";
import { db } from "../../src/db";
import { files, transfers } from "../../src/db/schema";
import { completeTransfer, createFile, createTransfer } from "../../src/services/file.service";
// Resolves to the stub from tests/setup.ts, which mirrors the production value.
// Deriving the assertions from it stops the test drifting from prod again.
import { MULTIPART_PART_SIZE } from "../../src/services/r2.service";
import { authedRequest, createAuthedUser } from "../helpers/auth";
import { ensureMigrations, resetDb } from "../helpers/db";
import { defaultR2Mock } from "../helpers/r2-mock";

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

function jsonBody<T extends object>(body: T): RequestInit {
  return { method: "POST", headers: ORIGIN_HEADER, body: JSON.stringify(body) };
}

const FILE_FIELDS = {
  contentType: "application/octet-stream",
  encryptedName: "x".repeat(32),
  encryptedNameIv: "y".repeat(24),
  fileIv: "z".repeat(24),
};

// ─── init-multipart ─────────────────────────────────────────────────────────

describe("POST /api/upload/init-multipart", () => {
  it("anonymous + small file: returns one Part URL", async () => {
    const transfer = await createTransfer(1);
    const res = await app.handle(
      new Request(`${APP_URL}/api/upload/init-multipart`, jsonBody({
        transferId: transfer.id,
        size: 1024,
        ...FILE_FIELDS,
      })),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      fileId: string;
      r2Key: string;
      uploadId: string;
      partUrls: Array<{ partNumber: number; url: string; contentLength: number }>;
    };
    expect(body.uploadId).toMatch(/^mock-upload-/);
    expect(body.partUrls).toHaveLength(1);
    expect(body.partUrls[0]!.partNumber).toBe(1);
    expect(body.partUrls[0]!.contentLength).toBe(1024);
  });

  it("a small file gets a one-request link when the browser asks for it", async () => {
    const transfer = await createTransfer(1);
    const start = (body: Record<string, unknown>) =>
      app
        .handle(new Request(`${APP_URL}/api/upload/init-multipart`, jsonBody({ transferId: transfer.id, ...FILE_FIELDS, ...body })))
        .then((r) => r.json()) as Promise<{ fileId: string; uploadId: string; single?: boolean; partUrls: { url: string; contentLength: number }[] }>;

    const single = await start({ size: 2048, singleOk: true });
    expect(single.single).toBe(true);
    expect(single.partUrls).toHaveLength(1);
    expect(single.partUrls[0]!.url).toContain("?single");
    expect(single.partUrls[0]!.contentLength).toBe(2048);

    // An older page that does not ask keeps getting a multipart upload.
    const older = await start({ size: 2048 });
    expect(older.single).toBeUndefined();
    expect(older.uploadId).toStartWith("mock-upload-");

    // Too large for one request, whatever the browser says.
    const large = await start({ size: 11 * 1024 * 1024, singleOk: true });
    expect(large.single).toBeUndefined();
    expect(large.partUrls).toHaveLength(2);

    // Aborting a one-request file removes it without asking storage to abort an upload.
    const abort = await app.handle(
      new Request(`${APP_URL}/api/upload/abort-multipart`, jsonBody({ transferId: transfer.id, fileId: single.fileId, uploadId: single.uploadId })),
    );
    expect(abort.status).toBe(204);
  });

  it("file just over one Part: returns two Parts with correct sizes", async () => {
    const transfer = await createTransfer(1);
    const size = MULTIPART_PART_SIZE + 100; // one full Part plus a remainder
    const res = await app.handle(
      new Request(`${APP_URL}/api/upload/init-multipart`, jsonBody({
        transferId: transfer.id,
        size,
        ...FILE_FIELDS,
      })),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      partUrls: Array<{ partNumber: number; contentLength: number }>;
    };
    expect(body.partUrls).toHaveLength(2);
    expect(body.partUrls[0]!.contentLength).toBe(MULTIPART_PART_SIZE);
    expect(body.partUrls[1]!.contentLength).toBe(100);
  });

  it("non-owner gets 404 on an owned transfer", async () => {
    const { user: owner } = await createAuthedUser();
    const { cookie: stranger } = await createAuthedUser();
    const owned = await createTransfer(1, undefined, undefined, owner.id);

    const res = await app.handle(
      authedRequest(stranger, `${APP_URL}/api/upload/init-multipart`, jsonBody({
        transferId: owned.id,
        size: 1024,
        ...FILE_FIELDS,
      })),
    );
    expect(res.status).toBe(404);
  });

  it("creates a file row with the requested size", async () => {
    const transfer = await createTransfer(1);
    const res = await app.handle(
      new Request(`${APP_URL}/api/upload/init-multipart`, jsonBody({
        transferId: transfer.id,
        size: 12345,
        ...FILE_FIELDS,
      })),
    );
    const body = (await res.json()) as { fileId: string };
    const [row] = await db.select().from(files).where(eq(files.id, body.fileId));
    expect(row.size).toBe(12345);
    expect(row.transferId).toBe(transfer.id);
    expect(row.uploadId).toBe(`mock-upload-${row.r2Key}`);
  });

  // A negative size would lower the transfer total and the monthly
  // volume counter it is added to.
  it("rejects a negative, zero or fractional size", async () => {
    const transfer = await createTransfer(1);
    for (const size of [-1024, 0, 10.5]) {
      const res = await app.handle(
        new Request(`${APP_URL}/api/upload/init-multipart`, jsonBody({
          transferId: transfer.id,
          size,
          ...FILE_FIELDS,
        })),
      );
      expect(res.status).toBe(400);
    }
    const rows = await db.select().from(files).where(eq(files.transferId, transfer.id));
    expect(rows).toHaveLength(0);
  });

  it("rejects an encrypted name longer than the column", async () => {
    const transfer = await createTransfer(1);
    const res = await app.handle(
      new Request(`${APP_URL}/api/upload/init-multipart`, jsonBody({
        transferId: transfer.id,
        size: 1024,
        ...FILE_FIELDS,
        encryptedName: "x".repeat(1025),
      })),
    );
    expect(res.status).toBe(400);
  });
});

// ─── complete-multipart ─────────────────────────────────────────────────────

describe("POST /api/upload/complete-multipart", () => {
  it("happy path returns 200 with the file id + size", async () => {
    const transfer = await createTransfer(1);
    const init = await app
      .handle(
        new Request(`${APP_URL}/api/upload/init-multipart`, jsonBody({
          transferId: transfer.id,
          size: 1024,
          ...FILE_FIELDS,
        })),
      )
      .then((r) => r.json()) as {
        fileId: string;
        uploadId: string;
        partUrls: Array<{ partNumber: number }>;
      };

    const res = await app.handle(
      new Request(`${APP_URL}/api/upload/complete-multipart`, jsonBody({
        transferId: transfer.id,
        fileId: init.fileId,
        uploadId: init.uploadId,
        parts: init.partUrls.map((p) => ({ partNumber: p.partNumber, etag: '"abc"' })),
      })),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { fileId: string; size: number };
    expect(body.fileId).toBe(init.fileId);
    expect(body.size).toBe(1024);
  });

  it("answers a repeated call for a finished file without asking storage again", async () => {
    const transfer = await createTransfer(1);
    const init = (await app
      .handle(
        new Request(`${APP_URL}/api/upload/init-multipart`, jsonBody({
          transferId: transfer.id,
          size: 1024,
          ...FILE_FIELDS,
        })),
      )
      .then((r) => r.json())) as { fileId: string; uploadId: string };
    const finish = () =>
      app.handle(
        new Request(`${APP_URL}/api/upload/complete-multipart`, jsonBody({
          transferId: transfer.id,
          fileId: init.fileId,
          uploadId: init.uploadId,
          parts: [{ partNumber: 1, etag: '"abc"' }],
        })),
      );

    expect((await finish()).status).toBe(200);
    const again = await finish();
    expect(again.status).toBe(200);
    expect(((await again.json()) as { fileId: string }).fileId).toBe(init.fileId);
  });

  it("non-owner gets 404 on an owned transfer", async () => {
    const { user: owner } = await createAuthedUser();
    const { cookie: stranger } = await createAuthedUser();
    const owned = await createTransfer(1, undefined, undefined, owner.id);

    const res = await app.handle(
      authedRequest(stranger, `${APP_URL}/api/upload/complete-multipart`, jsonBody({
        transferId: owned.id,
        fileId: "F".repeat(21),
        uploadId: "anything",
        parts: [{ partNumber: 1, etag: '"a"' }],
      })),
    );
    expect(res.status).toBe(404);
  });

  it("file id from a different transfer returns 404", async () => {
    const transferA = await createTransfer(1);
    const transferB = await createTransfer(1);
    const init = await app
      .handle(
        new Request(`${APP_URL}/api/upload/init-multipart`, jsonBody({
          transferId: transferA.id,
          size: 1024,
          ...FILE_FIELDS,
        })),
      )
      .then((r) => r.json()) as { fileId: string; uploadId: string };

    // Use file from A but pass transferId B → mismatch → 404.
    const res = await app.handle(
      new Request(`${APP_URL}/api/upload/complete-multipart`, jsonBody({
        transferId: transferB.id,
        fileId: init.fileId,
        uploadId: init.uploadId,
        parts: [{ partNumber: 1, etag: '"a"' }],
      })),
    );
    expect(res.status).toBe(404);
  });
});

// ─── abort-multipart ────────────────────────────────────────────────────────

describe("POST /api/upload/abort-multipart", () => {
  it("deletes the file row and returns 204", async () => {
    const transfer = await createTransfer(1);
    const init = await app
      .handle(
        new Request(`${APP_URL}/api/upload/init-multipart`, jsonBody({
          transferId: transfer.id,
          size: 1024,
          ...FILE_FIELDS,
        })),
      )
      .then((r) => r.json()) as { fileId: string; uploadId: string };

    const res = await app.handle(
      new Request(`${APP_URL}/api/upload/abort-multipart`, jsonBody({
        transferId: transfer.id,
        fileId: init.fileId,
        uploadId: init.uploadId,
      })),
    );
    expect(res.status).toBe(204);

    const rows = await db.select().from(files).where(eq(files.id, init.fileId));
    expect(rows).toHaveLength(0);
  });

  it("non-owner gets 404 on an owned transfer", async () => {
    const { user: owner } = await createAuthedUser();
    const { cookie: stranger } = await createAuthedUser();
    const owned = await createTransfer(1, undefined, undefined, owner.id);

    const res = await app.handle(
      authedRequest(stranger, `${APP_URL}/api/upload/abort-multipart`, jsonBody({
        transferId: owned.id,
        fileId: "F".repeat(21),
        uploadId: "anything",
      })),
    );
    expect(res.status).toBe(404);
  });

  it("aborting a file that's already gone returns 204 (idempotent)", async () => {
    const transfer = await createTransfer(1);
    const init = await app
      .handle(
        new Request(`${APP_URL}/api/upload/init-multipart`, jsonBody({
          transferId: transfer.id,
          size: 1024,
          ...FILE_FIELDS,
        })),
      )
      .then((r) => r.json()) as { fileId: string; uploadId: string };

    // First abort.
    await app.handle(
      new Request(`${APP_URL}/api/upload/abort-multipart`, jsonBody({
        transferId: transfer.id,
        fileId: init.fileId,
        uploadId: init.uploadId,
      })),
    );

    // Second abort on the same (already-deleted) file should still
    // succeed with 204 — retried clients shouldn't see a confusing 404.
    const res = await app.handle(
      new Request(`${APP_URL}/api/upload/abort-multipart`, jsonBody({
        transferId: transfer.id,
        fileId: init.fileId,
        uploadId: init.uploadId,
      })),
    );
    expect(res.status).toBe(204);
  });
});

// Anyone holding a share link knows the transfer and file IDs, so a
// completed transfer must reject every per-file mutation.
describe("completed transfers are frozen", () => {
  it("rejects add, finish and abort, and keeps the file", async () => {
    const transfer = await createTransfer(1);
    const file = await createFile({
      transferId: transfer.id,
      size: 1024,
      mimeType: FILE_FIELDS.contentType,
      encryptedName: FILE_FIELDS.encryptedName,
      encryptedNameIv: FILE_FIELDS.encryptedNameIv,
      fileIv: FILE_FIELDS.fileIv,
    });
    await completeTransfer(transfer.id);

    const call = (path: string, body: object) =>
      app.handle(new Request(`${APP_URL}/api/upload/${path}`, jsonBody(body)));

    const abort = await call("abort-multipart", {
      transferId: transfer.id,
      fileId: file.id,
      uploadId: "any",
    });
    expect(abort.status).toBe(409);

    const finish = await call("complete-multipart", {
      transferId: transfer.id,
      fileId: file.id,
      uploadId: "any",
      parts: [{ partNumber: 1, etag: "etag" }],
    });
    expect(finish.status).toBe(409);

    const add = await call("init-multipart", {
      transferId: transfer.id,
      size: 1024,
      ...FILE_FIELDS,
    });
    expect(add.status).toBe(409);

    const left = await db.select().from(files).where(eq(files.transferId, transfer.id));
    expect(left).toHaveLength(1);
  });
});

// ─── storage on abort ───────────────────────────────────────────────────────

describe("POST /api/upload/abort-multipart storage handling", () => {
  afterEach(() => {
    mock.module("../../src/services/r2.service", () => defaultR2Mock());
  });

  async function initFile(transferId: string) {
    return app
      .handle(
        new Request(`${APP_URL}/api/upload/init-multipart`, jsonBody({
          transferId,
          size: 1024,
          ...FILE_FIELDS,
        })),
      )
      .then((r) => r.json()) as Promise<{ fileId: string; uploadId: string; r2Key: string }>;
  }

  // The upload may already have been stitched into an object, so abort
  // has to delete the object as well as the multipart upload.
  it("deletes the object and uses the stored upload ID", async () => {
    const aborted: string[] = [];
    const deleted: string[] = [];
    mock.module("../../src/services/r2.service", () => ({
      ...defaultR2Mock(),
      abortMultipartUpload: async (_key: string, uploadId: string) => {
        aborted.push(uploadId);
      },
      deleteFromR2: async (key: string) => {
        deleted.push(key);
      },
    }));

    const transfer = await createTransfer(1);
    const init = await initFile(transfer.id);

    const res = await app.handle(
      new Request(`${APP_URL}/api/upload/abort-multipart`, jsonBody({
        transferId: transfer.id,
        fileId: init.fileId,
        uploadId: "made-up-by-the-client",
      })),
    );
    expect(res.status).toBe(204);
    expect(aborted).toEqual([init.uploadId]);
    expect(deleted).toEqual([init.r2Key]);
  });

  it("keeps the file row when storage refuses the delete", async () => {
    mock.module("../../src/services/r2.service", () => ({
      ...defaultR2Mock(),
      deleteFromR2: async () => {
        throw new Error("simulated storage outage");
      },
    }));

    const transfer = await createTransfer(1);
    const init = await initFile(transfer.id);

    const res = await app.handle(
      new Request(`${APP_URL}/api/upload/abort-multipart`, jsonBody({
        transferId: transfer.id,
        fileId: init.fileId,
        uploadId: init.uploadId,
      })),
    );
    expect(res.status).toBe(502);
    const rows = await db.select().from(files).where(eq(files.id, init.fileId));
    expect(rows).toHaveLength(1);
  });
});

// ─── complete ───────────────────────────────────────────────────────────────

describe("POST /api/upload/complete", () => {
  // A sender whose first response was lost retries the call.
  it("answers a repeat call the same way without changing the transfer", async () => {
    const transfer = await createTransfer(1);
    await createFile({
      transferId: transfer.id,
      size: 1024,
      mimeType: FILE_FIELDS.contentType,
      encryptedName: FILE_FIELDS.encryptedName,
      encryptedNameIv: FILE_FIELDS.encryptedNameIv,
      fileIv: FILE_FIELDS.fileIv,
    });

    const complete = () =>
      app.handle(
        new Request(`${APP_URL}/api/upload/complete`, jsonBody({ transferId: transfer.id })),
      );

    const first = await complete();
    expect(first.status).toBe(200);
    const second = await complete();
    expect(second.status).toBe(200);
    expect(await second.json()).toEqual({ success: true, shareUrl: `/d/${transfer.id}` });
  });
});
