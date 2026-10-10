import { lt, or, and, isNotNull } from 'drizzle-orm';
import { getExpiredTransfers, getAbandonedTransfers, getSoftDeletedTransfers, deleteExpiredTransfer, abortTransfer, purgeOwnerDeletedTransfer } from './file.service';
import { db } from '../db';
import { authEvents, magicLinkTokens, sessions } from '../db/schema';
import { rotateSalts } from './saltService';
import { cleanupUnpaidPasses } from './pass.service';

export async function cleanupExpiredTransfers(): Promise<number> {
  const expiredTransfers = await getExpiredTransfers();
  let count = 0;

  for (const transfer of expiredTransfers) {
    try {
      await deleteExpiredTransfer(transfer);
      count++;
    } catch (error) {
      console.error(`[cleanup] Failed to delete expired transfer ${transfer.id}:`, error);
    }
  }

  return count;
}

export async function cleanupAbandonedTransfers(): Promise<number> {
  const abandoned = await getAbandonedTransfers();
  let count = 0;

  for (const transfer of abandoned) {
    try {
      await abortTransfer(transfer.id);
      count++;
    } catch (error) {
      console.error(`[cleanup] Failed to delete abandoned transfer ${transfer.id}:`, error);
    }
  }

  return count;
}

// Owner-soft-deleted transfers (DELETE /api/me/transfers/:id). Reuse the
// expired-deletion path: removes R2 objects and hard-deletes the row.
export async function cleanupSoftDeletedTransfers(): Promise<number> {
  const rows = await getSoftDeletedTransfers();
  let count = 0;

  for (const transfer of rows) {
    try {
      await purgeOwnerDeletedTransfer(transfer);
      count++;
    } catch (error) {
      console.error(`[cleanup] Failed to delete soft-deleted transfer ${transfer.id}:`, error);
    }
  }

  return count;
}

// Auth-related purges.
export async function cleanupAuthArtefacts(): Promise<{ tokens: number; sessions: number; events: number }> {
  const now = new Date();
  // Magic-link tokens: drop rows that expired or were consumed > 1h ago.
  const tokenCutoff = new Date(now.getTime() - 60 * 60 * 1000);
  const tokens = await db
    .delete(magicLinkTokens)
    .where(
      or(
        lt(magicLinkTokens.expiresAt, tokenCutoff),
        and(isNotNull(magicLinkTokens.consumedAt), lt(magicLinkTokens.consumedAt, tokenCutoff)),
      ),
    )
    .returning({ id: magicLinkTokens.id });

  // Sessions: drop rows past absolute expiry, or revoked > 7 days ago.
  const revokeCutoff = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  const sess = await db
    .delete(sessions)
    .where(
      or(
        lt(sessions.absoluteExpiresAt, now),
        and(isNotNull(sessions.revokedAt), lt(sessions.revokedAt, revokeCutoff)),
      ),
    )
    .returning({ id: sessions.id });

  // Auth events: 30-day retention.
  const eventCutoff = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  const events = await db
    .delete(authEvents)
    .where(lt(authEvents.createdAt, eventCutoff))
    .returning({ id: authEvents.id });

  return { tokens: tokens.length, sessions: sess.length, events: events.length };
}

export function startCleanupJob(): void {
  const INTERVAL_MS = 15 * 60 * 1000; // 15 minutes
  // Re-entrancy guard: a sweep slower than the interval would otherwise stack.
  let running = false;

  const runCleanup = async () => {
    if (running) {
      console.warn('[cleanup] Previous run still in progress, skipping this tick');
      return;
    }
    running = true;
    try {
      await runCleanupOnce();
    } finally {
      running = false;
    }
  };

  const runCleanupOnce = async () => {
    // Each stage is isolated so one failure cannot skip the stages after it.
    try {
      const expired = await cleanupExpiredTransfers();
      const abandoned = await cleanupAbandonedTransfers();
      const softDeleted = await cleanupSoftDeletedTransfers();
      if (expired + abandoned + softDeleted > 0) {
        console.log(`[cleanup] Deleted ${expired} expired, ${abandoned} abandoned, ${softDeleted} soft-deleted transfers`);
      }
    } catch (err) {
      console.error('[cleanup] Transfer sweep failed:', err);
    }
    try {
      const auth = await cleanupAuthArtefacts();
      if (auth.tokens + auth.sessions + auth.events > 0) {
        console.log(
          `[cleanup] Auth: ${auth.tokens} tokens, ${auth.sessions} sessions, ${auth.events} events purged`,
        );
      }
    } catch (err) {
      console.error('[cleanup] Auth purge failed:', err);
    }
    try {
      const passes = await cleanupUnpaidPasses();
      if (passes > 0) console.log(`[cleanup] Dropped ${passes} unpaid passes`);
    } catch (err) {
      console.error('[cleanup] Pass sweep failed:', err);
    }
    try {
      const salt = await rotateSalts();
      if (salt.rotated.length > 0 || salt.purged > 0) {
        console.log(
          `[cleanup] Salts: rotated [${salt.rotated.join(',')}], purged ${salt.purged}`,
        );
      }
    } catch (err) {
      console.error('[cleanup] Salt rotation failed:', err);
    }
  };

  runCleanup();
  setInterval(runCleanup, INTERVAL_MS);
}
