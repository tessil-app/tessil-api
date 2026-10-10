import { Elysia, t } from 'elysia';
import { createTransfer, completeTransfer, abortTransfer, logCompletedTransfer, createFile, deleteFileById, getFileById, getTransferTotalSize, getValidTransfer, getTransferById, getFilesByTransferId } from '../services/file.service';
import {
  abortMultipartUpload,
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
import { env } from '../config/env';
import { resolveTransferCaps } from '../config/tiers';
import {
  completeTransferWithPass,
  hasOpenTransferSlot,
  isPassUsable,
  PassAlreadyUsedError,
  resolvePass,
} from '../services/pass.service';
import type { Transfer } from '../db/schema';
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

// The paywall has to hold on every route that moves or publishes bytes,
// not only on create-transfer. A transfer stays paid for while its pass
// is unspent, or while its owner is still subscribed.
async function isUploadPaidFor(
  transfer: Transfer,
  me: { id: string; tier: string } | null | undefined,
): Promise<boolean> {
  if (!env.PAYWALL_ENABLED) return true;
  if (transfer.passId) return isPassUsable(transfer.passId);
  return me?.tier === 'pro' && transfer.userId === me.id;
}

const PAYMENT_REQUIRED = {
  error: 'Sending needs a pass or a subscription.',
  code: 'payment_required',
  upgradeUrl: '/pricing',
} as const;

export const uploadRoutes = new Elysia({ prefix: '/api/upload' })
  .use(authPlugin)
  .use(ipContextPlugin)

  // Create a new transfer (group of files). If a session is present,
  // the transfer is owned by that user; otherwise it's anonymous
  // (user_id NULL). Ownership is set at creation and never re-assigned.
  .post('/create-transfer', async ({ body, ipContext, me, set }) => {
    // Pay-to-send: a transfer needs an active subscription or a paid,
    // unused pass. The pass is only spent when the transfer completes.
    let passId: string | null = null;
    if (env.PAYWALL_ENABLED && me?.tier !== 'pro') {
      const paymentRequired = (code: string, error: string) => {
        set.status = 402;
        return { error, code, upgradeUrl: '/pricing' };
      };
      if (!body.passToken) {
        return paymentRequired('payment_required', 'Sending needs a pass or a subscription.');
      }
      let resolved: Awaited<ReturnType<typeof resolvePass>>;
      try {
        resolved = await resolvePass(body.passToken);
      } catch (err) {
        console.error('[upload] pass verification failed:', err);
        set.status = 502;
        return { error: 'Could not confirm the payment. Please try again.' };
      }
      if (resolved.state === 'used') {
        return paymentRequired('pass_already_used', 'This pass has already been used.');
      }
      if (resolved.state !== 'paid' || !resolved.pass) {
        return paymentRequired('payment_required', 'This pass has not been paid for.');
      }
      if (!(await hasOpenTransferSlot(resolved.pass.id))) {
        set.status = 429;
        return { error: 'Too many unfinished transfers on this pass. Try again in a few minutes.' };
      }
      passId = resolved.pass.id;
    }

    const caps = resolveTransferCaps(me, passId !== null);

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

    const { expiresInHours, password, maxDownloads, encryptedTitle, encryptedTitleIv } = body;

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
      passId,
    );

    return {
      transferId: transfer.id,
      expiresAt: transfer.expiresAt
    };
  }, {
    body: t.Object({
      expiresInHours: t.Number(),
      password: t.Optional(t.String({ maxLength: 256 })),
      maxDownloads: t.Optional(t.Number({ minimum: 1, maximum: 100 })),
      encryptedTitle: t.Optional(t.String({ maxLength: ENCRYPTED_TITLE_MAX_LENGTH })),
      encryptedTitleIv: t.Optional(t.String({ maxLength: ENCRYPTED_TITLE_IV_LENGTH })),
      passToken: t.Optional(t.String({ minLength: 16, maxLength: 64 })),
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

    // A live transfer is frozen. Without this, anyone holding the ID of
    // a completed anonymous transfer could keep adding files to it.
    if (transfer.isCompleted) {
      set.status = 409;
      return { error: 'Transfer is already completed' };
    }

    if (!(await isUploadPaidFor(transfer, me))) {
      set.status = 402;
      return PAYMENT_REQUIRED;
    }

    const caps = resolveTransferCaps(me, transfer.passId !== null);

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
    const volumeLimit = await checkAuthedOrIpVolumeLimit(me?.id, ipContext, volumeConfig);
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
    // if the multipart init fails.
    const file = await createFile({
      transferId,
      encryptedName,
      encryptedNameIv,
      fileIv,
      size,
      mimeType: contentType || 'application/octet-stream',
    });

    try {
      const { uploadId, partUrls } = await initMultipartUpload(file.r2Key, size);
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
      await releaseAuthedOrIpVolumeLimit(me?.id, ipContext, volumeConfig, size);
      set.status = 502;
      return { error: 'Storage initialisation failed. Please try again.' };
    }
  }, {
    body: t.Object({
      transferId: t.String({ minLength: 21, maxLength: 21 }),
      contentType: t.String(),
      encryptedName: t.String(),
      encryptedNameIv: t.String(),
      fileIv: t.String(),
      size: t.Number(),
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
      await completeMultipartUpload(file.r2Key, uploadId, parts);
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

  // Abort a single file's in-flight multipart upload. Tears down the
  // R2 multipart upload (if it still exists), releases the monthly
  // volume reservation, and deletes the file row. Idempotent —
  // duplicate aborts and aborts of already-completed uploads no-op.
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

    // Best-effort R2 abort. If it fails the lifecycle rule will catch
    // the orphaned upload within 7 days (per the runbook); meanwhile
    // we proceed with the DB + volume cleanup so the user's state is
    // consistent.
    try {
      await abortMultipartUpload(file.r2Key, uploadId);
    } catch (err) {
      console.error('[upload] abortMultipartUpload failed (will rely on lifecycle rule):', err);
    }

    // Release the monthly volume reservation made at init.
    const volumeConfig = {
      ...rateLimiters.monthlyUploadVolume,
      maxBytes: 0, // unused on release
      increment: 0,
    };
    await releaseAuthedOrIpVolumeLimit(me?.id, ipContext, volumeConfig, file.size);

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
    const { transferId, wrappedKey } = body;

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

    // Vault wrap: K_transfer wrapped under the user's K_vault.
    // Anonymous transfers cannot vault; signed-in owners may. The wrap
    // blob is opaque to the server — only its byte count is validated.
    let vaultWrap: { wrappedKey: Uint8Array } | undefined;
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

    if (transfer.isCompleted) {
      set.status = 409;
      return { error: 'Transfer is already completed' };
    }

    if (!transfer.passId && !(await isUploadPaidFor(transfer, me))) {
      set.status = 402;
      return PAYMENT_REQUIRED;
    }

    if (transfer.passId) {
      try {
        await completeTransferWithPass(transferId, transfer.passId, vaultWrap);
      } catch (err) {
        if (err instanceof PassAlreadyUsedError) {
          set.status = 402;
          return {
            error: 'This pass has already been used for another transfer.',
            code: 'pass_already_used',
            upgradeUrl: '/pricing',
          };
        }
        throw err;
      }
    } else {
      await completeTransfer(transferId, vaultWrap);
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

    await abortTransfer(transferId);
    return { success: true };
  }, {
    body: t.Object({
      transferId: t.String({ minLength: 21, maxLength: 21 })
    })
  });
