import { eq, and, or, gt, lt, desc, sql, notExists, inArray } from 'drizzle-orm';
import { nanoid } from 'nanoid';
import { db } from '../db';
import { transfers, files, portals, transferEvents, type NewTransfer, type NewFile, type Transfer, type File } from '../db/schema';

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
  passwordSalt?: string | null,
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
    passwordSalt: passwordHash ? (passwordSalt ?? null) : null,
    maxDownloads: maxDownloads ?? null,
    isCompleted: false,
    userId: userId ?? null,
    encryptedTitle: title?.encryptedTitle ?? null,
    encryptedTitleIv: title?.encryptedTitleIv ?? null,
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

// A deposit: a transfer uploaded through a portal. It has no owner, no
// password and no download limit, and is kept for the portal owner's
// retention period.
export async function createDeposit(
  portalId: string,
  retentionDays: number,
  title?: TransferTitleInput | null,
): Promise<Transfer> {
  const [transfer] = await db.insert(transfers).values({
    id: nanoid(),
    portalId,
    expiresAt: new Date(Date.now() + retentionDays * 24 * 60 * 60 * 1000),
    isCompleted: false,
    encryptedTitle: title?.encryptedTitle ?? null,
    encryptedTitleIv: title?.encryptedTitleIv ?? null,
  }).returning();
  return transfer;
}

// Marks the transfer live. Optional `vaultWrap` writes the per-transfer
// vault column in the same UPDATE — caller has already validated the
// blob layout (60 bytes). Anonymous and unvaulted callers leave it NULL.
// See docs/adr/0004-vault-redesign-password-and-recovery-phrase.md.
// Returns false when the transfer was already completed or its file
// set no longer matches `expectedFileCount` (the set the caller verified).
export async function completeTransfer(
  id: string,
  vaultWrap?: { wrappedKey?: Uint8Array; sealedKey?: Uint8Array },
  expectedFileCount?: number,
): Promise<boolean> {
  const updated = await db
    .update(transfers)
    .set({
      isCompleted: true,
      ...(vaultWrap?.wrappedKey ? { wrappedKey: vaultWrap.wrappedKey } : {}),
      ...(vaultWrap?.sealedKey ? { sealedKey: vaultWrap.sealedKey } : {}),
    })
    .where(
      and(
        eq(transfers.id, id),
        eq(transfers.isCompleted, false),
        expectedFileCount === undefined
          ? undefined
          : sql`(select count(*) from ${files} where ${files.transferId} = ${transfers.id} and ${files.isDeleted} = false) = ${expectedFileCount}`,
      ),
    )
    .returning({ id: transfers.id });
  return updated.length > 0;
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

// The public download path. A deposit is never served here: it has no
// share link, and only the portal's members may read it.
export async function getCompletedValidTransfer(id: string): Promise<Transfer | null> {
  const transfer = await getValidTransfer(id);
  if (!transfer || transfer.portalId !== null) return null;

  // Only expose completed transfers to downloaders
  if (!transfer.isCompleted) return null;

  return transfer;
}

// Atomic "may I download this file?" gate. `max_downloads` caps each
// file separately, so one recipient can fetch every file of a transfer
// on a single download. The transfer's download_count is the number of
// complete downloads: the lowest count across its files.
//
// The transfer row is locked first, so concurrent claims cannot both
// pass a stale read and overshoot the cap.
//
// Returns the transfer's download_count on success, or null when the
// file is no longer downloadable. Callers cannot distinguish why
// (expired / deleted / not completed / cap reached); the route layer
// collapses all of them into a single 404 per doc 20 §4.
export async function claimDownloadSlot(fileId: string): Promise<number | null> {
  return db.transaction(async (tx) => {
    const [row] = await tx
      .select({ id: transfers.id, maxDownloads: transfers.maxDownloads })
      .from(files)
      .innerJoin(transfers, eq(transfers.id, files.transferId))
      .where(
        and(
          eq(files.id, fileId),
          eq(files.isDeleted, false),
          eq(transfers.isDeleted, false),
          eq(transfers.isCompleted, true),
          gt(transfers.expiresAt, new Date()),
        ),
      )
      .for('update', { of: transfers });
    if (!row) return null;

    const claimed = await tx
      .update(files)
      .set({ downloadCount: sql`${files.downloadCount} + 1` })
      .where(
        and(
          eq(files.id, fileId),
          row.maxDownloads === null ? undefined : lt(files.downloadCount, row.maxDownloads),
        ),
      )
      .returning({ id: files.id });
    if (claimed.length === 0) return null;

    const [lowest] = await tx
      .select({ count: sql<number>`min(${files.downloadCount})` })
      .from(files)
      .where(and(eq(files.transferId, row.id), eq(files.isDeleted, false)));
    const downloadCount = Number(lowest?.count ?? 0);

    await tx.update(transfers).set({ downloadCount }).where(eq(transfers.id, row.id));
    return downloadCount;
  });
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

// Removes the stored bytes behind file rows: the open multipart upload,
// if any, and the object. Returns false when storage refused, in which
// case the caller must keep the rows: they are the only record of the
// keys, and deleting them would orphan the ciphertext for good.
export async function removeStoredFiles(
  rows: Pick<File, 'r2Key' | 'uploadId'>[],
): Promise<boolean> {
  const { abortMultipartUpload, deleteFromR2 } = await import('./r2.service');
  let allRemoved = true;
  for (const row of rows) {
    try {
      if (row.uploadId) await abortMultipartUpload(row.r2Key, row.uploadId);
      await deleteFromR2(row.r2Key);
    } catch (err) {
      allRemoved = false;
      console.error(`[storage] Failed to remove ${row.r2Key}:`, err);
    }
  }
  return allRemoved;
}

// Storage first, rows second. Returns false, leaving the rows for the
// next sweep, when storage could not be cleared.
async function removeTransfer(
  transfer: Transfer,
  event: 'expired' | 'aborted',
): Promise<boolean> {
  const transferFiles = await getFilesForTransfer(transfer.id);
  if (!(await removeStoredFiles(transferFiles))) return false;

  const totalBytes = transferFiles.reduce((sum, f) => sum + f.size, 0);
  await logTransferEvent(event, transfer, transferFiles.length, totalBytes);
  await hardDeleteTransfer(transfer.id);
  return true;
}

export async function abortTransfer(id: string): Promise<boolean> {
  const transfer = await getTransferById(id);
  if (!transfer) return true;
  return removeTransfer(transfer, 'aborted');
}

export async function deleteExpiredTransfer(transfer: Transfer): Promise<boolean> {
  return removeTransfer(transfer, 'expired');
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
export async function purgeOwnerDeletedTransfer(transfer: Transfer): Promise<boolean> {
  return removeTransfer(transfer, 'aborted');
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

// Bytes an account has stored right now: every file of every transfer it
// owns, and of every deposit in a portal it owns, that has not been
// deleted. Uploads in progress are included. Computed from the rows, so
// there is no separate counter to drift.
type Queryable = Pick<typeof db, 'select'>;

export async function getStoredBytes(userId: string, executor: Queryable = db): Promise<number> {
  const [row] = await executor
    .select({ total: sql<number>`coalesce(sum(${files.size}), 0)` })
    .from(files)
    .innerJoin(transfers, eq(transfers.id, files.transferId))
    .leftJoin(portals, eq(portals.id, transfers.portalId))
    .where(
      and(
        or(eq(transfers.userId, userId), eq(portals.ownerId, userId)),
        eq(transfers.isDeleted, false),
        eq(files.isDeleted, false),
      ),
    );
  return Number(row?.total ?? 0);
}

// Creates the file row only if it fits in the account's storage quota.
// The per-account lock makes check and insert one step, so parallel
// uploads cannot each see room for themselves. Returns null when full.
//
// `pending` applies to deposits: unfinished deposits in one portal may
// hold at most `maxBytes` between them. Space is reserved when an upload
// starts, so without this an outsider with the link could reserve the
// owner's whole quota without sending a byte.
export async function createFileWithinQuota(
  userId: string,
  quotaBytes: number,
  data: Omit<NewFile, 'id' | 'r2Key' | 'storageType'>,
  pending?: { portalId: string; maxBytes: number },
): Promise<File | null> {
  return db.transaction(async (tx) => {
    await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${`storage:${userId}`}, 0))`);
    const used = await getStoredBytes(userId, tx);
    if (used + data.size > quotaBytes) return null;

    if (pending) {
      const [row] = await tx
        .select({ total: sql<number>`coalesce(sum(${files.size}), 0)` })
        .from(files)
        .innerJoin(transfers, eq(transfers.id, files.transferId))
        .where(
          and(
            eq(transfers.portalId, pending.portalId),
            eq(transfers.isCompleted, false),
            eq(transfers.isDeleted, false),
            eq(files.isDeleted, false),
          ),
        );
      if (Number(row?.total ?? 0) + data.size > pending.maxBytes) return null;
    }

    const id = nanoid();
    const [file] = await tx
      .insert(files)
      .values({ id, r2Key: `uploads/${data.transferId}/${id}`, ...data })
      .returning();
    return file;
  });
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

export async function setFileUploadId(id: string, uploadId: string | null): Promise<void> {
  await db.update(files).set({ uploadId }).where(eq(files.id, id));
}

// Hard-delete a single file row by ID. Used by the multipart abort
// path — the file never completed so there's no risk of dangling
// transfer state, and the row should be gone (not soft-deleted) so
// it doesn't appear in any per-transfer queries.
// Returns whether this call removed the row, so a caller refunding
// something for the file does so exactly once however many requests race.
export async function deleteFileById(id: string): Promise<boolean> {
  const deleted = await db.delete(files).where(eq(files.id, id)).returning({ id: files.id });
  return deleted.length > 0;
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

// Incomplete transfers nobody is uploading to any more. A transfer is
// left alone while any of its files could still be receiving parts,
// which is for as long as that file's upload URLs are valid.
const ABANDONED_GRACE_MS = 30 * 60 * 1000;

export async function getAbandonedTransfers(): Promise<Transfer[]> {
  const { UPLOAD_URL_EXPIRY } = await import('./r2.service');
  const idleCutoff = new Date(Date.now() - ABANDONED_GRACE_MS);
  const uploadCutoff = new Date(Date.now() - UPLOAD_URL_EXPIRY * 1000 - ABANDONED_GRACE_MS);
  return db
    .select()
    .from(transfers)
    .where(
      and(
        eq(transfers.isDeleted, false),
        eq(transfers.isCompleted, false),
        lt(transfers.createdAt, idleCutoff),
        notExists(
          db
            .select({ id: files.id })
            .from(files)
            .where(and(eq(files.transferId, transfers.id), gt(files.createdAt, uploadCutoff))),
        ),
      )
    );
}

export async function getFilesForTransfer(transferId: string): Promise<File[]> {
  return db
    .select()
    .from(files)
    .where(eq(files.transferId, transferId));
}

// ─── deposits, as a portal member sees them ─────────────────────────────────

export interface DepositSummary {
  id: string;
  createdAt: Date;
  expiresAt: Date;
  sealedKey: Uint8Array;
  encryptedTitle: string | null;
  encryptedTitleIv: string | null;
  files: {
    id: string;
    encryptedName: string;
    encryptedNameIv: string;
    fileIv: string;
    size: number;
    mimeType: string | null;
  }[];
}

/** Completed, unexpired deposits of a portal, newest first. */
export async function listDeposits(
  portalId: string,
  cursor: Date | null,
  limit: number,
): Promise<DepositSummary[]> {
  const rows = await db
    .select()
    .from(transfers)
    .where(
      and(
        eq(transfers.portalId, portalId),
        eq(transfers.isDeleted, false),
        eq(transfers.isCompleted, true),
        gt(transfers.expiresAt, new Date()),
        cursor ? lt(transfers.createdAt, cursor) : undefined,
      ),
    )
    .orderBy(desc(transfers.createdAt))
    .limit(limit);

  const result: DepositSummary[] = [];
  for (const row of rows) {
    if (!row.sealedKey) continue;
    const depositFiles = await getFilesByTransferId(row.id);
    result.push({
      id: row.id,
      createdAt: row.createdAt,
      expiresAt: row.expiresAt,
      sealedKey: row.sealedKey,
      encryptedTitle: row.encryptedTitle,
      encryptedTitleIv: row.encryptedTitleIv,
      files: depositFiles.map((f) => ({
        id: f.id,
        encryptedName: f.encryptedName,
        encryptedNameIv: f.encryptedNameIv,
        fileIv: f.fileIv,
        size: Number(f.size),
        mimeType: f.mimeType,
      })),
    });
  }
  return result;
}

/** A file of a live deposit in this portal, with the deposit's expiry; null otherwise. */
export async function getDepositFile(
  portalId: string,
  fileId: string,
): Promise<{ r2Key: string; size: number; expiresAt: Date } | null> {
  const [row] = await db
    .select({ r2Key: files.r2Key, size: files.size, expiresAt: transfers.expiresAt })
    .from(files)
    .innerJoin(transfers, eq(transfers.id, files.transferId))
    .where(
      and(
        eq(files.id, fileId),
        eq(files.isDeleted, false),
        eq(transfers.portalId, portalId),
        eq(transfers.isDeleted, false),
        eq(transfers.isCompleted, true),
        gt(transfers.expiresAt, new Date()),
      ),
    )
    .limit(1);
  return row ? { r2Key: row.r2Key, size: Number(row.size), expiresAt: row.expiresAt } : null;
}

/** Marks a deposit deleted; the sweep removes its storage. False when not in this portal. */
export async function softDeleteDeposit(portalId: string, transferId: string): Promise<boolean> {
  const updated = await db
    .update(transfers)
    .set({ isDeleted: true })
    .where(
      and(
        eq(transfers.id, transferId),
        eq(transfers.portalId, portalId),
        eq(transfers.isDeleted, false),
      ),
    )
    .returning({ id: transfers.id });
  return updated.length > 0;
}

/**
 * Marks deleted every deposit whose portal no longer exists. Deleting a
 * portal marks its deposits itself; this catches one that was started in
 * the same instant, so nothing depends on winning that race.
 */
export async function markOrphanedDepositsDeleted(): Promise<number> {
  const updated = await db
    .update(transfers)
    .set({ isDeleted: true })
    .where(
      and(
        sql`${transfers.portalId} IS NOT NULL`,
        eq(transfers.isDeleted, false),
        notExists(db.select({ id: portals.id }).from(portals).where(eq(portals.id, transfers.portalId))),
      ),
    )
    .returning({ id: transfers.id });
  return updated.length;
}

/** Marks every deposit of a portal deleted, before the portal row goes. */
export async function softDeleteDepositsOf(
  portalIds: string[],
  executor: Pick<typeof db, 'update'> = db,
): Promise<void> {
  if (portalIds.length === 0) return;
  await executor
    .update(transfers)
    .set({ isDeleted: true })
    .where(inArray(transfers.portalId, portalIds));
}
