import { Elysia, t } from 'elysia';
import { createTransfer, completeTransfer, abortTransfer, logCompletedTransfer, createFile, createFileWithinQuota, deleteFileById, getFileById, getTransferTotalSize, getValidTransfer, getTransferById, getFilesByTransferId, removeStoredFiles, setFileUploadId } from '../services/file.service';
import {
  completeMultipartUpload,
  headObject,
  initMultipartUpload,
} from '../services/r2.service';
import {
  checkAuthedOrIpRateLimit,
  checkAuthedOrIpVolumeLimit,
  rateLimiters,
  releaseAuthedOrIpVolumeLimit,
} from '../services/ratelimit.service';
import { resolveCaps } from '../config/tiers';
import { findUserById } from '../auth/users';
import { getPortal } from '../services/portal.service';
import type { User } from '../db/schema';
import { exceedsTotalLimit } from '../utils/limits';
import { authPlugin } from '../auth/middleware';
import { ipContextPlugin } from '../auth/ipContextPlugin';
import {
  ENCRYPTED_TITLE_IV_LENGTH,
  ENCRYPTED_TITLE_MAX_LENGTH,
  validateEncryptedTitle,
} from '../utils/encryptedTitle';

// nanoid validation pattern (21 chars, URL-safe alphabet)
const NANOID_PATTERN = /^[A-Za-z0-9_-]{21}$/;
function isValidNanoId(id: string): boolean {
  return NANOID_PATTERN.test(id);
}

const MIN_PASSWORD_LENGTH = 8;

// Vault wrap blob is `wrap_iv(12) || ciphertext(32) || tag(16)`.
// Exact byte count enforced server-side so the column stays normalised.
const WRAPPED_KEY_BYTES = 60;
const PASSWORD_SALT_BYTES = 16;
// mode(1) + encapsulated key(65) + key(32) + tag(16).
const SEALED_KEY_BYTES = 114;

// The account a deposit is stored for, or null when the portal is gone,
// switched off, or its owner is no longer on a plan with portals.
async function depositTarget(portalId: string): Promise<{ owner: User } | null> {
  const portal = await getPortal(portalId);
  if (!portal || portal.isDisabled) return null;
  const owner = await findUserById(portal.ownerId);
  if (!owner || owner.deletedAt || resolveCaps(owner).maxPortals === 0) return null;
  return { owner };
}

function decodeBase64Url(input: string): Uint8Array | null {
  // base64url uses '-_' and no padding; strict regex stops malformed payloads
  // from being silently coerced by Buffer's lenient decoder.
  if (!/^[A-Za-z0-9_-]+$/.test(input)) return null;
  try {
    return new Uint8Array(Buffer.from(input, 'base64url'));
  } catch {
    return null;
  }
}

export const uploadRoutes = new Elysia({ prefix: '/api/upload' })
  .use(authPlugin)
  .use(ipContextPlugin)

  // Create a new transfer (group of files). If a session is present,
  // the transfer is owned by that user; otherwise it's anonymous
  // (user_id NULL). Ownership is set at creation and never re-assigned.
  .post('/create-transfer', async ({ body, ipContext, me, set }) => {
    const caps = resolveCaps(me);

    // Per-minute smoothing rate (not tier-aware — applies the same to
    // every tier). Per-user when authed, per-IP otherwise.
    const rateLimit = await checkAuthedOrIpRateLimit(me?.id, ipContext, rateLimiters.upload);
    if (!rateLimit.allowed) {
      set.status = 429;
      set.headers['Retry-After'] = String(rateLimit.resetIn);
      return { error: 'Rate limit exceeded. Try again later.' };
    }

    // Daily transfer limit — tier-aware cap, per-user when authed.
    const dailyConfig = { ...rateLimiters.dailyTransfers, maxRequests: caps.dailyTransferCount };
    const dailyLimit = await checkAuthedOrIpRateLimit(me?.id, ipContext, dailyConfig);
    if (!dailyLimit.allowed) {
      set.status = 429;
      set.headers['Retry-After'] = String(dailyLimit.resetIn);
      return {
        error: `Daily limit reached. You can create ${caps.dailyTransferCount} transfers per day.`,
        code: 'daily_transfer_limit_exceeded',
        upgradeUrl: '/pricing',
      };
    }

    const { expiresInHours, password, passwordSalt, maxDownloads, encryptedTitle, encryptedTitleIv } = body;

    // Validate expiration against the tier's allowed list.
    if (!caps.allowedExpiryHours.includes(expiresInHours)) {
      set.status = 400;
      return {
        error: `Invalid expiration. Allowed values: ${caps.allowedExpiryHours.join(', ')} hours.`,
        code: 'expiry_not_allowed_for_tier',
        upgradeUrl: '/pricing',
      };
    }

    // Validate password if provided (minimum 8 characters for security)
    if (password !== undefined && password.length < MIN_PASSWORD_LENGTH) {
      set.status = 400;
      return { error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters.` };
    }

    // With a salt, `password` is a verifier the browser derived from the
    // real password, which then never reaches us.
    if (passwordSalt !== undefined) {
      const saltBytes = decodeBase64Url(passwordSalt);
      if (password === undefined || !saltBytes || saltBytes.length !== PASSWORD_SALT_BYTES) {
        set.status = 400;
        return { error: 'passwordSalt must be 16 bytes (base64url) and come with a password.' };
      }
    }

    // Validate maxDownloads if provided
    if (maxDownloads !== undefined && (maxDownloads < 1 || maxDownloads > 100)) {
      set.status = 400;
      return { error: 'maxDownloads must be between 1 and 100.' };
    }

    // Title is optional but both-or-neither — a missing title just
    // means "no title".
    const titleResult = validateEncryptedTitle(encryptedTitle, encryptedTitleIv);
    if (!titleResult.ok) {
      set.status = 400;
      return { error: titleResult.error };
    }

    const transfer = await createTransfer(
      expiresInHours,
      password,
      maxDownloads,
      me?.id ?? null,
      titleResult.value,
      passwordSalt,
    );

    return {
      transferId: transfer.id,
      expiresAt: transfer.expiresAt
    };
  }, {
    body: t.Object({
      expiresInHours: t.Number(),
      password: t.Optional(t.String({ maxLength: 256 })),
      passwordSalt: t.Optional(t.String({ maxLength: 32 })),
      maxDownloads: t.Optional(t.Number({ minimum: 1, maximum: 100 })),
      encryptedTitle: t.Optional(t.String({ maxLength: ENCRYPTED_TITLE_MAX_LENGTH })),
      encryptedTitleIv: t.Optional(t.String({ maxLength: ENCRYPTED_TITLE_IV_LENGTH })),
    })
  })

  // Begin a multipart upload for one file. Returns all Part URLs in
  // one batch so the browser can upload Parts in parallel without
  // per-Part round-trips. Monthly volume is charged here;
  // /abort-multipart releases it.
  .post('/init-multipart', async ({ body, ipContext, me, set }) => {
    const rateLimit = await checkAuthedOrIpRateLimit(me?.id, ipContext, rateLimiters.upload);
    if (!rateLimit.allowed) {
      set.status = 429;
      set.headers['Retry-After'] = String(rateLimit.resetIn);
      return { error: 'Rate limit exceeded. Try again later.' };
    }

    const { transferId, contentType, encryptedName, encryptedNameIv, fileIv, size } = body;

    if (!isValidNanoId(transferId)) {
      set.status = 400;
      return { error: 'Invalid transfer ID' };
    }

    const transfer = await getValidTransfer(transferId);
    if (!transfer) {
      set.status = 404;
      return { error: 'Transfer not found or has expired' };
    }

    // Owner-only on owned transfers; non-owner collapses to 404 to
    // avoid leaking existence.
    if (transfer.userId !== null && transfer.userId !== me?.id) {
      set.status = 404;
      return { error: 'Transfer not found or has expired' };
    }
    if (transfer.isCompleted) {
      set.status = 409;
      return { error: 'Transfer is already completed' };
    }

    // Limits follow whoever the bytes are stored for, not whoever is
    // calling. A deposit counts against its portal's owner; an ownerless
    // transfer gets anonymous limits even when a paying user is signed in,
    // or paid size caps would apply to bytes no storage quota accounts for.
    const deposit = transfer.portalId ? await depositTarget(transfer.portalId) : null;
    if (transfer.portalId && !deposit) {
      set.status = 403;
      return { error: 'This portal is not accepting files right now.', code: 'portal_not_accepting' };
    }
    const owner = deposit ? deposit.owner : transfer.userId === null ? null : me;
    const caps = resolveCaps(owner);

    // Tier-aware file size cap.
    if (size > caps.maxFileSize) {
      set.status = 400;
      return {
        error: `File too large. Maximum size is ${caps.maxFileSize / (1024 * 1024)}MB`,
        code: 'file_too_large',
        upgradeUrl: '/pricing',
      };
    }

    // Tier-aware total-transfer cap.
    const currentTotal = await getTransferTotalSize(transferId);
    if (exceedsTotalLimit(currentTotal, size, caps.maxTransferSize)) {
      set.status = 400;
      return {
        error: `Transfer too large. Maximum total size is ${caps.maxTransferSize / (1024 * 1024)}MB`,
        code: 'transfer_too_large',
        upgradeUrl: '/pricing',
      };
    }

    // Monthly upload volume — tier-aware cap, per-user when authed.
    // Charged here; released on /abort-multipart.
    const volumeConfig = {
      ...rateLimiters.monthlyUploadVolume,
      maxBytes: caps.monthlyVolumeBytes,
      increment: size,
    };
    // A depositor is an outsider: their upload is bounded by the portal
    // owner's storage and the deposit rate limits, not by a monthly
    // allowance of their own or the owner's.
    const volumeLimit = deposit
      ? { allowed: true, remaining: 0, resetIn: 0 }
      : await checkAuthedOrIpVolumeLimit(owner?.id, ipContext, volumeConfig);
    if (!volumeLimit.allowed) {
      set.status = 429;
      set.headers['Retry-After'] = String(volumeLimit.resetIn);
      return {
        error: 'Monthly upload limit reached. Please try again later.',
        code: 'monthly_volume_exceeded',
        upgradeUrl: '/pricing',
      };
    }

    // Persist the file row before talking to R2 so we can clean it up
    // if the multipart init fails. On a plan with a storage quota the
    // row is only created if the file fits.
    const fileData = {
      transferId,
      encryptedName,
      encryptedNameIv,
      fileIv,
      size,
      mimeType: contentType || 'application/octet-stream',
    };
    const file =
      owner && caps.storageBytes !== null
        ? await createFileWithinQuota(owner.id, caps.storageBytes, fileData)
        : await createFile(fileData);
    if (!file) {
      if (!deposit) await releaseAuthedOrIpVolumeLimit(owner?.id, ipContext, volumeConfig, size);
      set.status = 413;
      return deposit
        ? { error: 'This portal is full and cannot accept files right now.', code: 'portal_full' }
        : {
            error: 'Your storage is full. Delete a transfer or wait for one to expire.',
            code: 'storage_quota_exceeded',
            upgradeUrl: '/pricing',
          };
    }

    try {
      const { uploadId, partUrls } = await initMultipartUpload(file.r2Key, size);
      await setFileUploadId(file.id, uploadId);
      return {
        fileId: file.id,
        r2Key: file.r2Key,
        uploadId,
        partUrls,
      };
    } catch (err) {
      // Roll back the file row + volume reservation if R2 rejects.
      // (Caller would otherwise have nothing to abort against.)
      console.error('[upload] initMultipartUpload failed:', err);
      await deleteFileById(file.id);
      if (!deposit) await releaseAuthedOrIpVolumeLimit(owner?.id, ipContext, volumeConfig, size);
      set.status = 502;
      return { error: 'Storage initialisation failed. Please try again.' };
    }
  }, {
    body: t.Object({
      transferId: t.String({ minLength: 21, maxLength: 21 }),
      contentType: t.String({ maxLength: 127 }),
      encryptedName: t.String({ minLength: 1, maxLength: 1024 }),
      encryptedNameIv: t.String({ minLength: 1, maxLength: 32 }),
      fileIv: t.String({ minLength: 1, maxLength: 32 }),
      // A negative or fractional size would lower the totals it is added to.
      size: t.Integer({ minimum: 1 }),
    }),
  })

  // Stitch the uploaded Parts into the final R2 object. Called once
  // per file after every Part's PUT has succeeded. No volume-cap
  // interaction — that was charged at /init-multipart.
  .post('/complete-multipart', async ({ body, ipContext, me, set }) => {
    const { transferId, fileId, uploadId, parts } = body;

    if (!isValidNanoId(transferId) || !isValidNanoId(fileId)) {
      set.status = 400;
      return { error: 'Invalid transfer or file ID' };
    }

    const transfer = await getValidTransfer(transferId);
    if (!transfer) {
      set.status = 404;
      return { error: 'Transfer not found or has expired' };
    }
    if (transfer.userId !== null && transfer.userId !== me?.id) {
      set.status = 404;
      return { error: 'Transfer not found or has expired' };
    }
    if (transfer.isCompleted) {
      set.status = 409;
      return { error: 'Transfer is already completed' };
    }

    const file = await getFileById(fileId);
    if (!file || file.transferId !== transferId) {
      set.status = 404;
      return { error: 'File not found' };
    }

    if (parts.length === 0) {
      set.status = 400;
      return { error: 'At least one part is required.' };
    }

    try {
      await completeMultipartUpload(file.r2Key, file.uploadId ?? uploadId, parts);
      await setFileUploadId(file.id, null);
      return { fileId: file.id, size: file.size };
    } catch (err) {
      console.error('[upload] completeMultipartUpload failed:', err);
      set.status = 502;
      return { error: 'Failed to finalise upload. You can retry.' };
    }
  }, {
    body: t.Object({
      transferId: t.String({ minLength: 21, maxLength: 21 }),
      fileId: t.String({ minLength: 21, maxLength: 21 }),
      uploadId: t.String({ minLength: 1, maxLength: 2048 }),
      parts: t.Array(
        t.Object({
          partNumber: t.Number({ minimum: 1, maximum: 10000 }),
          etag: t.String({ minLength: 1, maxLength: 256 }),
        }),
        { minItems: 1 },
      ),
    }),
  })

  // Abort a single file's upload. Tears down the multipart upload and
  // any object it already produced, releases the monthly volume
  // reservation, and deletes the file row. Idempotent.
  .post('/abort-multipart', async ({ body, ipContext, me, set }) => {
    const { transferId, fileId, uploadId } = body;

    if (!isValidNanoId(transferId) || !isValidNanoId(fileId)) {
      set.status = 400;
      return { error: 'Invalid transfer or file ID' };
    }

    const transfer = await getValidTransfer(transferId);
    if (!transfer) {
      set.status = 404;
      return { error: 'Transfer not found or has expired' };
    }
    if (transfer.userId !== null && transfer.userId !== me?.id) {
      set.status = 404;
      return { error: 'Transfer not found or has expired' };
    }
    if (transfer.isCompleted) {
      set.status = 409;
      return { error: 'Transfer is already completed' };
    }

    const file = await getFileById(fileId);
    if (!file || file.transferId !== transferId) {
      // Already cleaned up — treat as success so retried aborts
      // don't surface confusing 404s to the client.
      set.status = 204;
      return null;
    }

    // The row is the only record of the storage key. Keep it, and the
    // volume reservation, until storage confirms the bytes are gone;
    // the abandoned sweep retries whatever is left.
    const removed = await removeStoredFiles([{ ...file, uploadId: file.uploadId ?? uploadId }]);
    if (!removed) {
      set.status = 502;
      return { error: 'Could not remove the upload. It will be cleaned up automatically.' };
    }

    // Release the monthly volume reservation made at init.
    const volumeConfig = {
      ...rateLimiters.monthlyUploadVolume,
      maxBytes: 0, // unused on release
      increment: 0,
    };
    if (!transfer.portalId) {
      await releaseAuthedOrIpVolumeLimit(
        transfer.userId === null ? undefined : me?.id,
        ipContext,
        volumeConfig,
        file.size,
      );
    }

    await deleteFileById(file.id);

    set.status = 204;
    return null;
  }, {
    body: t.Object({
      transferId: t.String({ minLength: 21, maxLength: 21 }),
      fileId: t.String({ minLength: 21, maxLength: 21 }),
      uploadId: t.String({ minLength: 1, maxLength: 2048 }),
    }),
  })

  // Complete the transfer (called after all files are uploaded)
  .post('/complete', async ({ body, me, set }) => {
    const { transferId, wrappedKey, sealedKey } = body;

    // Validate transferId format
    if (!isValidNanoId(transferId)) {
      set.status = 400;
      return { error: 'Invalid transfer ID' };
    }

    const transfer = await getValidTransfer(transferId);
    if (!transfer) {
      set.status = 404;
      return { error: 'Transfer not found or has expired' };
    }

    // Owner-only on owned transfers; non-owner collapses to 404.
    if (transfer.userId !== null && transfer.userId !== me?.id) {
      set.status = 404;
      return { error: 'Transfer not found or has expired' };
    }

    // A sender whose first response was lost retries; answer the same
    // way without touching the transfer again.
    if (transfer.isCompleted) {
      return { success: true, shareUrl: `/d/${transferId}` };
    }

    // Vault wrap: K_transfer wrapped under the user's K_vault.
    // Anonymous transfers cannot vault; signed-in owners may. The wrap
    // blob is opaque to the server — only its byte count is validated.
    let vaultWrap: { wrappedKey?: Uint8Array; sealedKey?: Uint8Array } | undefined;

    // A deposit carries its key sealed to the portal's public key, and
    // nothing else can. Without it no member could ever open the files.
    const hasSealedKey = typeof sealedKey === 'string' && sealedKey.length > 0;
    if (hasSealedKey !== (transfer.portalId !== null)) {
      set.status = 400;
      return { error: 'sealedKey is required for a deposit and not allowed otherwise.' };
    }
    if (hasSealedKey) {
      const sealedKeyBytes = decodeBase64Url(sealedKey!);
      if (!sealedKeyBytes || sealedKeyBytes.length !== SEALED_KEY_BYTES) {
        set.status = 400;
        return { error: 'sealedKey must be 114 bytes (base64url).' };
      }
      vaultWrap = { sealedKey: sealedKeyBytes };
    }

    if (typeof wrappedKey === 'string' && wrappedKey.length > 0) {
      if (!me || transfer.userId !== me.id) {
        set.status = 400;
        return { error: 'Vault wrap requires an owned signed-in transfer.' };
      }
      const wrappedKeyBytes = decodeBase64Url(wrappedKey);
      if (!wrappedKeyBytes || wrappedKeyBytes.length !== WRAPPED_KEY_BYTES) {
        set.status = 400;
        return { error: 'wrappedKey must be 60 bytes (base64url).' };
      }
      vaultWrap = { wrappedKey: wrappedKeyBytes };
    }

    // Verify every declared file is actually in storage at the expected
    // size before marking the transfer live. Without this, a client
    // could /complete after a partial or skipped upload and leave
    // recipients with broken downloads.
    const transferFiles = await getFilesByTransferId(transferId);
    if (transferFiles.length === 0) {
      set.status = 409;
      return { error: 'Transfer has no files to complete.' };
    }
    for (const file of transferFiles) {
      const head = await headObject(file.r2Key);
      if (!head) {
        set.status = 409;
        return { error: 'Upload incomplete — one or more files are missing.' };
      }
      if (head.size !== file.size) {
        set.status = 409;
        return { error: 'Upload incomplete — file size mismatch.' };
      }
    }

    // Conditional on the file set checked above, so a file added while
    // the checks ran cannot ride into a live transfer unverified.
    const completed = await completeTransfer(transferId, vaultWrap, transferFiles.length);
    if (!completed) {
      set.status = 409;
      return { error: 'Transfer changed while completing. Please retry.' };
    }
    logCompletedTransfer(transfer).catch(() => {}); // fire-and-forget, never blocks response

    return {
      success: true,
      shareUrl: `/d/${transferId}`
    };
  }, {
    body: t.Object({
      transferId: t.String({ minLength: 21, maxLength: 21 }),
      wrappedKey: t.Optional(t.String({ maxLength: 128 })),
      sealedKey: t.Optional(t.String({ maxLength: 256 })),
    })
  })

  // Abort an in-progress transfer — deletes any already-uploaded files from R2
  .post('/abort', async ({ body, me, set }) => {
    const { transferId } = body;

    if (!isValidNanoId(transferId)) {
      set.status = 400;
      return { error: 'Invalid transfer ID' };
    }

    // Only allow aborting incomplete transfers (completed ones are live)
    const transfer = await getTransferById(transferId);
    if (!transfer || transfer.isDeleted) {
      set.status = 404;
      return { error: 'Transfer not found' };
    }

    // Owner-only on owned transfers; non-owner collapses to 404.
    if (transfer.userId !== null && transfer.userId !== me?.id) {
      set.status = 404;
      return { error: 'Transfer not found' };
    }

    if (transfer.isCompleted) {
      set.status = 409;
      return { error: 'Transfer is already completed' };
    }

    if (!(await abortTransfer(transferId))) {
      set.status = 502;
      return { error: 'Could not remove the upload. It will be cleaned up automatically.' };
    }
    return { success: true };
  }, {
    body: t.Object({
      transferId: t.String({ minLength: 21, maxLength: 21 })
    })
  });
