// Default in-process R2 mock used by `tests/setup.ts` and by individual tests
// that need to override + restore the stub. Extracted so the default headObject
// behaviour (pretend the upload succeeded with the size from the DB row) stays
// in sync across files — without this, an inline `mock.module` override in one
// test file would leak a degraded stub into every later test file that shares
// the same Bun process.

// Must match MULTIPART_PART_SIZE in src/services/r2.service.ts, or fixtures
// compute a different Part count than production. Was 16 MB here while prod
// ran 10 MB (ADR-0009 still documents 16 MB and is now stale).
const MULTIPART_PART_SIZE = 10 * 1024 * 1024;

export function defaultR2Mock() {
  return {
    getPresignedDownloadUrl: async (key: string, notAfter: Date) => ({
      url: `https://r2.test.invalid/${key}`,
      expiresAt: new Date(Math.min(Date.now() + 4 * 60 * 60_000, notAfter.getTime())),
    }),
    deleteFromR2: async () => undefined,
    headObject: async (key: string) => {
      const { db } = await import("../../src/db");
      const { files } = await import("../../src/db/schema");
      const { eq } = await import("drizzle-orm");
      const [row] = await db
        .select({ size: files.size })
        .from(files)
        .where(eq(files.r2Key, key))
        .limit(1);
      return row ? { size: row.size } : null;
    },
    // Multipart stubs (ADR-0009). The mocked uploadId is deterministic
    // so tests can assert against it without snapshotting random values.
    MULTIPART_PART_SIZE,
    UPLOAD_URL_EXPIRY: 4 * 60 * 60,
    initMultipartUpload: async (key: string, totalBytes: number) => {
      const partCount = Math.max(1, Math.ceil(totalBytes / MULTIPART_PART_SIZE));
      const partUrls = Array.from({ length: partCount }, (_, i) => {
        const partNumber = i + 1;
        const offset = i * MULTIPART_PART_SIZE;
        const isLast = i === partCount - 1;
        const contentLength = isLast ? totalBytes - offset : MULTIPART_PART_SIZE;
        return {
          partNumber,
          url: `https://r2.test.invalid/${key}?partNumber=${partNumber}`,
          contentLength,
        };
      });
      return { uploadId: `mock-upload-${key}`, key, partUrls };
    },
    completeMultipartUpload: async () => undefined,
    abortMultipartUpload: async () => undefined,
  };
}
