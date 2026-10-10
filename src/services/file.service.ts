import { eq, and, gt, lt, desc, sql } from 'drizzle-orm';
import { nanoid } from 'nanoid';
import { db } from '../db';
import { transfers, files, transferEvents, type NewTransfer, type NewFile, type Transfer, type File } from '../db/schema';

// Optional encrypted-title pair carried alongside transfer creation.
// Both fields are set together or not at all (server invariant — see
// docs/adr/0005-encrypted-transfer-title-scope.md). Caller validates
// the base64 / length shape; this layer only persists.
export interface TransferTitleInput {
  encryptedTitle: string;
  encryptedTitleIv: string;
}

// Transfer operations
export async function createTransfer(
  expiresInHours: number,
  password?: string,
  maxDownloads?: number,
  userId?: string | null,
  title?: TransferTitleInput | null,
  passId?: string | null
): Promise<Transfer> {
  const id = nanoid();
  const expiresAt = new Date();
  expiresAt.setTime(expiresAt.getTime() + expiresInHours * 60 * 60 * 1000);

  // Hash password if provided (Argon2id via Bun)
  const passwordHash = password ? await Bun.password.hash(password) : null;

  const [transfer] = await db.insert(transfers).values({
    id,
    expiresAt,
    passwordHash,
    maxDownloads: maxDownloads ?? null,
    isCompleted: false,
    userId: userId ?? null,
    encryptedTitle: title?.encryptedTitle ?? null,
    encryptedTitleIv: title?.encryptedTitleIv ?? null,
    passId: passId ?? null,
  }).returning();

  return transfer;
}

// Owner-scoped title update. Returns true on success, false when
// the transfer doesn't exist, isn't owned by `userId`, or is
// soft-deleted — the route layer collapses all three to a 404 to
// avoid an existence oracle.
//
// Pass `null` for both fields to clear the title. The
// both-or-neither invariant is enforced at the route layer before
// this is called.
export async function setOwnedTransferTitle(
  userId: string,
  transferId: string,
  encryptedTitle: string | null,
  encryptedTitleIv: string | null,
): Promise<boolean> {
  const updated = await db
    .update(transfers)
    .set({ encryptedTitle, encryptedTitleIv })
    .where(
      and(
        eq(transfers.id, transferId),
        eq(transfers.userId, userId),
        eq(transfers.isDeleted, false),
      ),
    )
    .returning({ id: transfers.id });

  return updated.length > 0;
}

// Marks the transfer live. Optional `vaultWrap` writes the per-transfer
// vault column in the same UPDATE — caller has already validated the
// blob layout (60 bytes). Anonymous and unvaulted callers leave it NULL.
// See docs/adr/0004-vault-redesign-password-and-recovery-phrase.md.
export async function completeTransfer(
  id: string,
  vaultWrap?: { wrappedKey: Uint8Array }
): Promise<void> {
  await db
    .update(transfers)
    .set({
      isCompleted: true,
      ...(vaultWrap ? { wrappedKey: vaultWrap.wrappedKey } : {}),
    })
    .where(eq(transfers.id, id));
}

export async function verifyTransferPassword(transferId: string, password: string): Promise<boolean> {
  const transfer = await getTransferById(transferId);
  if (!transfer || !transfer.passwordHash) return false;

  return Bun.password.verify(password, transfer.passwordHash);
}

export async function getTransferById(id: string): Promise<Transfer | null> {
  const [transfer] = await db
    .select()
    .from(transfers)
    .where(
      and(
        eq(transfers.id, id),
        eq(transfers.isDeleted, false)
      )
    )
    .limit(1);

  return transfer ?? null;
}

export async function getValidTransfer(id: string): Promise<Transfer | null> {
  const transfer = await getTransferById(id);

  if (!transfer) return null;

  // Check if expired
  if (new Date(transfer.expiresAt) < new Date()) {
    return null;
  }

  // Check download limit
  if (transfer.maxDownloads !== null && transfer.downloadCount >= transfer.maxDownloads) {
    return null;
  }

  return transfer;
}

export async function getCompletedValidTransfer(id: string): Promise<Transfer | null> {
  const transfer = await getValidTransfer(id);
  if (!transfer) return null;

  // Only expose completed transfers to downloaders
  if (!transfer.isCompleted) return null;

  return transfer;
}

// Atomic "may I download?" gate. Increments download_count by 1
// *only* when the transfer is still live, completed, not
// soft-deleted, and either has no download cap or is strictly
// below it — all in a single UPDATE so two concurrent calls cannot
// both pass a stale read of the count and overshoot
// `max_downloads`.
//
// Returns the new download_count on success, or null when the transfer is no
// longer downloadable for any of the reasons above. Callers cannot
// distinguish *why* the claim failed; that's by design — the
// (expired / deleted / cap-reached) states collapse into a single 404 at
// the route layer per doc 20 §4.
export async function claimDownloadSlot(transferId: string): Promise<number | null> {
  const updated = await db
    .update(transfers)
    .set({ downloadCount: sql`${transfers.downloadCount} + 1` })
    .where(
      and(
        eq(transfers.id, transferId),
        eq(transfers.isDeleted, false),
        eq(transfers.isCompleted, true),
        gt(transfers.expiresAt, new Date()),
        sql`(${transfers.maxDownloads} IS NULL OR ${transfers.downloadCount} < ${transfers.maxDownloads})`,
      ),
    )
    .returning({ downloadCount: transfers.downloadCount });

  return updated[0]?.downloadCount ?? null;
}

async function logTransferEvent(
  event: 'completed' | 'expired' | 'aborted',
  transfer: Transfer,
  fileCount: number,
  totalBytes: number
): Promise<void> {
  try {
    await db.insert(transferEvents).values({
      event,
      transferId: transfer.id,
      fileCount,
      totalBytes,
      downloadCount: transfer.downloadCount,
      hasPassword: transfer.passwordHash !== null,
      maxDownloads: transfer.maxDownloads ?? null,
    });
  } catch (err) {
    // Logging must never break the main flow
    console.error('[log] Failed to write transfer event:', err);
  }
}

async function hardDeleteTransfer(id: string): Promise<void> {
  await db.delete(files).where(eq(files.transferId, id));
  await db.delete(transfers).where(eq(transfers.id, id));
}

export async function abortTransfer(id: string): Promise<void> {
  const { deleteFromR2 } = await import('./r2.service');
  const transfer = await getTransferById(id);
  const transferFiles = await getFilesForTransfer(id);

  const totalBytes = transferFiles.reduce((sum, f) => sum + f.size, 0);

  for (const file of transferFiles) {
    try {
      await deleteFromR2(file.r2Key);
    } catch {
      // best-effort — DB cleanup proceeds regardless
    }
  }

  if (transfer) {
    await logTransferEvent('aborted', transfer, transferFiles.length, totalBytes);
  }

  await hardDeleteTransfer(id);
}

export async function deleteExpiredTransfer(transfer: Transfer): Promise<void> {
  const { deleteFromR2 } = await import('./r2.service');
  const transferFiles = await getFilesForTransfer(transfer.id);
  const totalBytes = transferFiles.reduce((sum, f) => sum + f.size, 0);

  for (const file of transferFiles) {
    try {
      await deleteFromR2(file.r2Key);
    } catch (err) {
      console.error(`[cleanup] Failed to delete R2 object ${file.r2Key}:`, err);
    }
  }

  await logTransferEvent('expired', transfer, transferFiles.length, totalBytes);
  await hardDeleteTransfer(transfer.id);
}

export async function logCompletedTransfer(transfer: Transfer): Promise<void> {
  const transferFiles = await getFilesForTransfer(transfer.id);
  const totalBytes = transferFiles.reduce((sum, f) => sum + f.size, 0);
  await logTransferEvent('completed', transfer, transferFiles.length, totalBytes);
}

export async function markTransferAsDeleted(id: string): Promise<void> {
  await db
    .update(transfers)
    .set({ isDeleted: true })
    .where(eq(transfers.id, id));
}

// Owner-scoped list with per-row file aggregates. Cursor is the
// createdAt of the last row from the previous page (ISO string).
// `wrappedKey` is base64url-encoded when present and NULL when the
// row is unvaulted.
export interface OwnedTransferSummary {
  id: string;
  createdAt: Date;
  expiresAt: Date;
  fileCount: number;
  totalBytes: number;
  downloadCount: number;
  isCompleted: boolean;
  hasPassword: boolean;
  wrappedKey: string | null;
  encryptedTitle: string | null;
  encryptedTitleIv: string | null;
}

function bytesToBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

export async function listTransfersForUser(
  userId: string,
  cursor: Date | null,
  limit: number
): Promise<OwnedTransferSummary[]> {
  const whereClauses = [
    eq(transfers.userId, userId),
    eq(transfers.isDeleted, false),
  ];
  if (cursor) {
    whereClauses.push(lt(transfers.createdAt, cursor));
  }

  const rows = await db
    .select({
      id: transfers.id,
      createdAt: transfers.createdAt,
      expiresAt: transfers.expiresAt,
      downloadCount: transfers.downloadCount,
      isCompleted: transfers.isCompleted,
      passwordHash: transfers.passwordHash,
      wrappedKey: transfers.wrappedKey,
      encryptedTitle: transfers.encryptedTitle,
      encryptedTitleIv: transfers.encryptedTitleIv,
      fileCount: sql<number>`coalesce(count(${files.id}) filter (where ${files.isDeleted} = false), 0)`,
      totalBytes: sql<number>`coalesce(sum(${files.size}) filter (where ${files.isDeleted} = false), 0)`,
    })
    .from(transfers)
    .leftJoin(files, eq(files.transferId, transfers.id))
    .where(and(...whereClauses))
    .groupBy(transfers.id)
    .orderBy(desc(transfers.createdAt))
    .limit(limit);

  return rows.map((r) => ({
    id: r.id,
    createdAt: r.createdAt,
    expiresAt: r.expiresAt,
    downloadCount: r.downloadCount,
    isCompleted: r.isCompleted,
    hasPassword: r.passwordHash !== null,
    wrappedKey: r.wrappedKey ? bytesToBase64Url(r.wrappedKey) : null,
    encryptedTitle: r.encryptedTitle,
    encryptedTitleIv: r.encryptedTitleIv,
    // postgres.js returns bigint aggregates as strings — coerce explicitly
    fileCount: Number(r.fileCount ?? 0),
    totalBytes: Number(r.totalBytes ?? 0),
  }));
}

// Per-file metadata for an owned transfer. Used by the dashboard
// to decrypt filenames after unwrapping K_transfer. Returns null
// when the transfer does not exist or is not owned by `userId`;
// the route layer collapses both to a 404.
export interface OwnedTransferFileMetadata {
  id: string;
  encryptedName: string;
  encryptedNameIv: string;
  size: number;
  mimeType: string | null;
}

export async function getFileMetadataForOwnedTransfer(
  userId: string,
  transferId: string
): Promise<OwnedTransferFileMetadata[] | null> {
  const [transfer] = await db
    .select({ id: transfers.id, userId: transfers.userId, isDeleted: transfers.isDeleted })
    .from(transfers)
    .where(eq(transfers.id, transferId))
    .limit(1);

  if (!transfer || transfer.isDeleted || transfer.userId !== userId) {
    return null;
  }

  const rows = await db
    .select({
      id: files.id,
      encryptedName: files.encryptedName,
      encryptedNameIv: files.encryptedNameIv,
      size: files.size,
      mimeType: files.mimeType,
    })
    .from(files)
    .where(and(eq(files.transferId, transferId), eq(files.isDeleted, false)));

  return rows.map((r) => ({
    id: r.id,
    encryptedName: r.encryptedName,
    encryptedNameIv: r.encryptedNameIv,
    size: Number(r.size),
    mimeType: r.mimeType,
  }));
}

// Returns true when a row was soft-deleted, false when not found
// or not owned (caller maps both to 404 to avoid an existence oracle).
export async function softDeleteOwnedTransfer(userId: string, transferId: string): Promise<boolean> {
  const updated = await db
    .update(transfers)
    .set({ isDeleted: true })
    .where(
      and(
        eq(transfers.id, transferId),
        eq(transfers.userId, userId),
        eq(transfers.isDeleted, false),
      )
    )
    .returning({ id: transfers.id });

  return updated.length > 0;
}

// Owner-soft-deleted rows awaiting storage cleanup + hard-delete by the
// background job. Distinct from expired/abandoned pickups.
export async function getSoftDeletedTransfers(): Promise<Transfer[]> {
  return db
    .select()
    .from(transfers)
    .where(eq(transfers.isDeleted, true));
}

// Storage cleanup + hard-delete for an owner-soft-deleted transfer. Logged
// to transfer_events as 'aborted' (user-initiated termination). User-attributed
// audit is logged separately to auth_events at the DELETE handler. See doc 20 §7.
export async function purgeOwnerDeletedTransfer(transfer: Transfer): Promise<void> {
  const { deleteFromR2 } = await import('./r2.service');
  const transferFiles = await getFilesForTransfer(transfer.id);
  const totalBytes = transferFiles.reduce((sum, f) => sum + f.size, 0);

  for (const file of transferFiles) {
    try {
      await deleteFromR2(file.r2Key);
    } catch (err) {
      console.error(`[cleanup] Failed to delete R2 object ${file.r2Key}:`, err);
    }
  }

  await logTransferEvent('aborted', transfer, transferFiles.length, totalBytes);
  await hardDeleteTransfer(transfer.id);
}

// File operations
export async function createFile(data: Omit<NewFile, 'id' | 'r2Key' | 'storageType'>): Promise<File> {
  const id = nanoid();
  const storageKey = `uploads/${data.transferId}/${id}`;

  const [file] = await db.insert(files).values({
    id,
    r2Key: storageKey,
    ...data
  }).returning();

  return file;
}

export async function getFilesByTransferId(transferId: string): Promise<File[]> {
  return db
    .select()
    .from(files)
    .where(
      and(
        eq(files.transferId, transferId),
        eq(files.isDeleted, false)
      )
    );
}

export async function getTransferTotalSize(transferId: string): Promise<number> {
  const [row] = await db
    .select({
      total: sql<number>`coalesce(sum(${files.size}), 0)`
    })
    .from(files)
    .where(
      and(
        eq(files.transferId, transferId),
        eq(files.isDeleted, false)
      )
    );

  // postgres.js returns bigint aggregate results as strings — coerce explicitly
  return Number(row?.total ?? 0);
}

export async function getFileById(id: string): Promise<File | null> {
  const [file] = await db
    .select()
    .from(files)
    .where(
      and(
        eq(files.id, id),
        eq(files.isDeleted, false)
      )
    )
    .limit(1);

  return file ?? null;
}

// Hard-delete a single file row by ID. Used by the multipart abort
// path — the file never completed so there's no risk of dangling
// transfer state, and the row should be gone (not soft-deleted) so
// it doesn't appear in any per-transfer queries.
export async function deleteFileById(id: string): Promise<void> {
  await db.delete(files).where(eq(files.id, id));
}

export async function markFileAsDeleted(id: string): Promise<void> {
  await db
    .update(files)
    .set({ isDeleted: true })
    .where(eq(files.id, id));
}

// Cleanup operations
export async function getExpiredTransfers(): Promise<Transfer[]> {
  return db
    .select()
    .from(transfers)
    .where(
      and(
        eq(transfers.isDeleted, false),
        lt(transfers.expiresAt, new Date())
      )
    );
}

// Incomplete transfers older than 30 minutes — upload was abandoned or failed
export async function getAbandonedTransfers(): Promise<Transfer[]> {
  const cutoff = new Date(Date.now() - 30 * 60 * 1000);
  return db
    .select()
    .from(transfers)
    .where(
      and(
        eq(transfers.isDeleted, false),
        eq(transfers.isCompleted, false),
        lt(transfers.createdAt, cutoff)
      )
    );
}

export async function getFilesForTransfer(transferId: string): Promise<File[]> {
  return db
    .select()
    .from(files)
    .where(eq(files.transferId, transferId));
}
