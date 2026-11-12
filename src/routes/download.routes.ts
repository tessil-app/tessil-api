import { Elysia, t } from 'elysia';
import { getCompletedValidTransfer, getTransferById, getFilesByTransferId, getFileById, claimDownloadSlot, verifyTransferPassword } from '../services/file.service';
import { getPresignedDownloadUrl } from '../services/r2.service';
import { checkIpRateLimit, rateLimiters } from '../services/ratelimit.service';
import { ipContextPlugin } from '../auth/ipContextPlugin';
import { issueDownloadToken, verifyDownloadToken } from '../auth/downloadTokens';

// nanoid validation pattern (21 chars, URL-safe alphabet)
const NANOID_PATTERN = /^[A-Za-z0-9_-]{21}$/;
function isValidNanoId(id: string): boolean {
  return NANOID_PATTERN.test(id);
}

export const downloadRoutes = new Elysia({ prefix: '/api/download' })
  .use(ipContextPlugin)
  // Get transfer metadata with all files
  .get('/transfer/:id', async ({ params, ipContext, set }) => {
    // Validate ID format first (prevents path traversal)
    if (!isValidNanoId(params.id)) {
      set.status = 404;
      return { error: 'Transfer not found or has expired' };
    }

    const rateLimit = await checkIpRateLimit(ipContext, rateLimiters.download);
    if (!rateLimit.allowed) {
      set.status = 429;
      set.headers['Retry-After'] = String(rateLimit.resetIn);
      return { error: 'Rate limit exceeded. Try again later.' };
    }

    const transfer = await getCompletedValidTransfer(params.id);

    if (!transfer) {
      set.status = 404;
      return { error: 'Transfer not found or has expired' };
    }

    // Get all files for this transfer
    const files = await getFilesByTransferId(transfer.id);

    // If password protected, return limited metadata. The encrypted
    // title is safe to return pre-verify: the ciphertext is keyed
    // under the (still-wrapped) fragment key, so the recipient
    // can't decrypt it until they've entered the password and the
    // fragment key has been unwrapped.
    if (transfer.passwordHash) {
      return {
        id: transfer.id,
        expiresAt: transfer.expiresAt,
        passwordRequired: true,
        // NULL on older transfers: the client then sends the password itself.
        passwordSalt: transfer.passwordSalt,
        fileCount: files.length,
        encryptedTitle: transfer.encryptedTitle,
        encryptedTitleIv: transfer.encryptedTitleIv,
      };
    }

    return {
      id: transfer.id,
      expiresAt: transfer.expiresAt,
      passwordRequired: false,
      encryptedTitle: transfer.encryptedTitle,
      encryptedTitleIv: transfer.encryptedTitleIv,
      files: files.map(file => ({
        id: file.id,
        encryptedName: file.encryptedName,
        encryptedNameIv: file.encryptedNameIv,
        fileIv: file.fileIv,
        size: file.size,
        mimeType: file.mimeType
      }))
    };
  }, {
    params: t.Object({
      id: t.String()
    })
  })

  // Verify password and get full metadata
  .post('/transfer/:id/verify', async ({ params, body, ipContext, set }) => {
    // Validate ID format first
    if (!isValidNanoId(params.id)) {
      set.status = 404;
      return { error: 'Transfer not found or has expired' };
    }

    const rateLimit = await checkIpRateLimit(ipContext, rateLimiters.password);
    if (!rateLimit.allowed) {
      set.status = 429;
      set.headers['Retry-After'] = String(rateLimit.resetIn);
      return { error: 'Too many password attempts. Try again later.' };
    }

    const transfer = await getCompletedValidTransfer(params.id);

    if (!transfer) {
      set.status = 404;
      return { error: 'Transfer not found or has expired' };
    }

    if (!transfer.passwordHash) {
      set.status = 400;
      return { error: 'Transfer is not password protected' };
    }

    const isValid = await verifyTransferPassword(params.id, body.password);

    if (!isValid) {
      set.status = 401;
      return { error: 'Incorrect password' };
    }

    // Get all files for this transfer
    const files = await getFilesByTransferId(transfer.id);

    // Issue a short-lived "password OK" token so subsequent
    // /file/:id/url calls under this transfer don't need to
    // re-verify the password. The token binds transferId + expiry
    // under DOWNLOAD_TOKEN_SECRET.
    const accessToken = await issueDownloadToken(transfer.id);

    return {
      id: transfer.id,
      expiresAt: transfer.expiresAt,
      passwordRequired: false,
      accessToken: accessToken.token,
      accessTokenExpiresAt: accessToken.expiresAt.toISOString(),
      encryptedTitle: transfer.encryptedTitle,
      encryptedTitleIv: transfer.encryptedTitleIv,
      files: files.map(file => ({
        id: file.id,
        encryptedName: file.encryptedName,
        encryptedNameIv: file.encryptedNameIv,
        fileIv: file.fileIv,
        size: file.size,
        mimeType: file.mimeType
      }))
    };
  }, {
    params: t.Object({
      id: t.String({ minLength: 21, maxLength: 21 })
    }),
    body: t.Object({
      password: t.String({ maxLength: 256 })
    })
  })

  // Get presigned download URL for a file
  .get('/file/:id/url', async ({ params, ipContext, request, set }) => {
    // Validate ID format first
    if (!isValidNanoId(params.id)) {
      set.status = 404;
      return { error: 'File not found' };
    }

    // Per-minute rate limit
    const rateLimit = await checkIpRateLimit(ipContext, rateLimiters.download);
    if (!rateLimit.allowed) {
      set.status = 429;
      set.headers['Retry-After'] = String(rateLimit.resetIn);
      return { error: 'Rate limit exceeded. Try again later.' };
    }

    // Daily download limit
    const dailyLimit = await checkIpRateLimit(ipContext, rateLimiters.dailyDownloads);
    if (!dailyLimit.allowed) {
      set.status = 429;
      set.headers['Retry-After'] = String(dailyLimit.resetIn);
      return { error: `Daily download limit reached. You can download ${rateLimiters.dailyDownloads.maxRequests} files per day.` };
    }

    const file = await getFileById(params.id);

    if (!file) {
      set.status = 404;
      return { error: 'File not found' };
    }

    // Password gate. Only enforced for *live* transfers, so an
    // expired/deleted/not-yet-completed transfer always 404s
    // instead of leaking "this transfer was once
    // password-protected" via a 401. The token binds transferId
    // under DOWNLOAD_TOKEN_SECRET, so it cannot be replayed across
    // transfers.
    const transferRow = await getTransferById(file.transferId);
    // A deposit has no public download path, whoever knows its IDs.
    if (!transferRow || transferRow.portalId !== null) {
      set.status = 404;
      return { error: 'Transfer has expired' };
    }
    const isLiveProtected =
      transferRow.isCompleted &&
      new Date(transferRow.expiresAt) > new Date() &&
      transferRow.passwordHash !== null;
    if (isLiveProtected) {
      const headerToken = request.headers.get('x-transfer-token');
      if (!headerToken || !(await verifyDownloadToken(headerToken, file.transferId))) {
        set.status = 401;
        return { error: 'Password verification required' };
      }
    }

    // Atomic claim: gate-check + increment in one UPDATE so a
    // burst of concurrent downloads on a transfer at
    // (max_downloads - 1) can't all pass a stale read and overshoot
    // the cap. A null return collapses "expired / deleted / not
    // completed / cap exhausted" into the same 404 — existence
    // oracle policy.
    const claimed = await claimDownloadSlot(file.id);
    if (claimed === null) {
      set.status = 404;
      return { error: 'Transfer has expired' };
    }

    const presigned = await getPresignedDownloadUrl(file.r2Key, transferRow.expiresAt);

    return {
      downloadUrl: presigned.url,
      expiresAt: presigned.expiresAt.toISOString(),
      size: file.size
    };
  }, {
    params: t.Object({
      id: t.String()
    })
  });
