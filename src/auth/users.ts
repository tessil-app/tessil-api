// User lookup + silent auto-create for the magic-link flow.
//
// Also implements the GDPR account erasure (Article 17) and account
// export (Article 20) flows for the authenticated user.

import { and, asc, eq, inArray } from "drizzle-orm";
import { nanoid } from "nanoid";
import { db } from "../db";
import {
  authEvents,
  files,
  magicLinkTokens,
  sessions,
  subscriptions,
  transfers,
  users,
  type User,
} from "../db/schema";
import { normaliseEmail } from "./tokens";
import { purgeOwnerDeletedTransfer } from "../services/file.service";
import { getActiveSalt } from "../services/saltService";
import type { IpContext } from "../utils/ipContext";

export async function findUserByEmail(email: string): Promise<User | null> {
  const normalised = normaliseEmail(email);
  const [user] = await db.select().from(users).where(eq(users.email, normalised)).limit(1);
  return user ?? null;
}

export async function findOrCreateUserByEmail(email: string): Promise<User> {
  const normalised = normaliseEmail(email);
  const existing = await findUserByEmail(normalised);
  if (existing) return existing;

  // Race-safe: rely on the unique index. If two requests race, one will
  // conflict and we re-read.
  try {
    const [created] = await db
      .insert(users)
      .values({ id: nanoid(), email: normalised })
      .returning();
    if (created) return created;
  } catch {
    // Likely a unique-violation race; fall through to re-read.
  }

  const recheck = await findUserByEmail(normalised);
  if (recheck) return recheck;
  throw new Error("Failed to create or load user");
}

export async function findUserById(id: string): Promise<User | null> {
  const [user] = await db.select().from(users).where(eq(users.id, id)).limit(1);
  return user ?? null;
}

interface EraseAccountInput {
  user: User;
  ipContext: IpContext;
  userAgent: string | null;
  // Overridable so tests need no payment-processor client.
  cancelSubscription?: (polarSubscriptionId: string) => Promise<void>;
}

async function cancelAtProcessor(polarSubscriptionId: string): Promise<void> {
  const { cancelSubscriptionImmediately } = await import("../services/polar.service");
  await cancelSubscriptionImmediately(polarSubscriptionId);
}

// Permanent account erasure. Billing is stopped first, then owned
// transfers + R2 objects are purged (best-effort, outside the DB
// transaction); then a single DB transaction handles all row-level
// operations atomically.
export async function eraseAccount({
  user,
  ipContext,
  userAgent,
  cancelSubscription = cancelAtProcessor,
}: EraseAccountInput): Promise<void> {
  // Step 1: stop billing. Runs before anything is destroyed, so a
  // processor failure aborts the erasure with the account intact
  // instead of leaving a deleted user who is still charged.
  const live = await db
    .select({ polarSubscriptionId: subscriptions.polarSubscriptionId })
    .from(subscriptions)
    .where(
      and(
        eq(subscriptions.userId, user.id),
        inArray(subscriptions.status, ["active", "past_due", "trialing"]),
      ),
    );
  for (const subscription of live) {
    await cancelSubscription(subscription.polarSubscriptionId);
  }

  // Step 2: purge every owned transfer, soft-deleted ones included.
  const owned = await db.select().from(transfers).where(eq(transfers.userId, user.id));

  for (const transfer of owned) {
    try {
      await purgeOwnerDeletedTransfer(transfer);
    } catch (err) {
      console.error(`[erasure] purgeOwnerDeletedTransfer failed for ${transfer.id}:`, err);
    }
  }

  // Steps 3–9: DB-only cascade in a single transaction.
  await db.transaction(async (tx) => {
    // Step 3: a transfer whose storage could not be cleared survives
    // step 2. Detach it from the user and strip what the user wrote,
    // so the account can go now and the sweep finishes the storage.
    await tx
      .update(transfers)
      .set({
        userId: null,
        isDeleted: true,
        wrappedKey: null,
        encryptedTitle: null,
        encryptedTitleIv: null,
        passwordHash: null,
      })
      .where(eq(transfers.userId, user.id));

    // Step 4: hard-delete magic-link tokens for this email (any purpose).
    await tx.delete(magicLinkTokens).where(eq(magicLinkTokens.email, user.email));

    // Step 5: hard-delete all sessions for the user.
    await tx.delete(sessions).where(eq(sessions.userId, user.id));

    // Step 6: scrub email column on historical auth_events rows for this user.
    await tx
      .update(authEvents)
      .set({ email: null })
      .where(eq(authEvents.userId, user.id));

    // Step 7: write account_deleted audit row inside the same
    // transaction. No raw IP — only country/ASN and an HMAC
    // correlator keyed under the active auth_events salt.
    const salt = await getActiveSalt("auth_events");
    const correlator = ipContext.hmac(salt.secret);
    await tx.insert(authEvents).values({
      eventType: "account_deleted",
      userId: user.id,
      email: null,
      country: ipContext.country === "unknown" ? null : ipContext.country.toUpperCase().slice(0, 2),
      asn: ipContext.asn,
      ipCorrelator: correlator,
      saltId: salt.id,
      userAgent: userAgent ?? null,
    });

    // Step 8: hard-delete the user row. Safe now: child rows are gone.
    await tx.delete(users).where(eq(users.id, user.id));
  });
}

// GDPR Article 20 export bundle. Positive-list scope: no token
// hashes, no password hashes, no storage keys. Encrypted filename
// material is included so the user can reconstruct filenames with
// the key from their share link.
//
// Raw IPs are never stored, so they don't appear here. Sessions
// carry the country + ASN derived at create time; magic-link rows
// carry no network signal at all; auth_events carry country + ASN
// (the HMAC correlator is internal-only and never surfaced).
export interface AccountExport {
  exportFormatVersion: 1;
  exportedAt: string;
  account: {
    id: string;
    email: string;
    tier: string;
    createdAt: string;
  };
  sessions: Array<{
    createdAt: string;
    lastSeenAt: string;
    expiresAt: string;
    absoluteExpiresAt: string;
    revokedAt: string | null;
    country: string | null;
    asn: number | null;
    userAgent: string | null;
  }>;
  magicLinkRequests: Array<{
    createdAt: string;
    expiresAt: string;
    consumedAt: string | null;
    userAgent: string | null;
  }>;
  authEvents: Array<{
    eventType: string;
    createdAt: string;
    country: string | null;
    asn: number | null;
    userAgent: string | null;
  }>;
  transfers: Array<{
    id: string;
    createdAt: string;
    expiresAt: string;
    downloadCount: number;
    maxDownloads: number | null;
    isCompleted: boolean;
    isDeleted: boolean;
    hasPassword: boolean;
    files: Array<{
      encryptedName: string;
      encryptedNameIv: string;
      fileIv: string;
      size: number;
      mimeType: string | null;
      createdAt: string;
    }>;
  }>;
}

export async function buildAccountExport(user: User): Promise<AccountExport> {
  const [sessionRows, magicLinkRows, eventRows, transferRows] = await Promise.all([
    db
      .select()
      .from(sessions)
      .where(eq(sessions.userId, user.id))
      .orderBy(asc(sessions.createdAt)),
    db
      .select()
      .from(magicLinkTokens)
      .where(eq(magicLinkTokens.email, user.email))
      .orderBy(asc(magicLinkTokens.createdAt)),
    db
      .select()
      .from(authEvents)
      .where(eq(authEvents.userId, user.id))
      .orderBy(asc(authEvents.createdAt)),
    db
      .select()
      .from(transfers)
      .where(eq(transfers.userId, user.id))
      .orderBy(asc(transfers.createdAt)),
  ]);

  const transferIds = transferRows.map((t) => t.id);
  const fileRows = transferIds.length
    ? await db
        .select()
        .from(files)
        .where(inArray(files.transferId, transferIds))
        .orderBy(asc(files.createdAt))
    : [];

  const filesByTransfer = new Map<string, typeof fileRows>();
  for (const row of fileRows) {
    const list = filesByTransfer.get(row.transferId) ?? [];
    list.push(row);
    filesByTransfer.set(row.transferId, list);
  }

  return {
    exportFormatVersion: 1,
    exportedAt: new Date().toISOString(),
    account: {
      id: user.id,
      email: user.email,
      tier: user.tier,
      createdAt: user.createdAt.toISOString(),
    },
    sessions: sessionRows.map((s) => ({
      createdAt: s.createdAt.toISOString(),
      lastSeenAt: s.lastSeenAt.toISOString(),
      expiresAt: s.expiresAt.toISOString(),
      absoluteExpiresAt: s.absoluteExpiresAt.toISOString(),
      revokedAt: s.revokedAt ? s.revokedAt.toISOString() : null,
      country: s.country ?? null,
      asn: s.asn ?? null,
      userAgent: s.userAgent ?? null,
    })),
    magicLinkRequests: magicLinkRows.map((m) => ({
      createdAt: m.createdAt.toISOString(),
      expiresAt: m.expiresAt.toISOString(),
      consumedAt: m.consumedAt ? m.consumedAt.toISOString() : null,
      userAgent: m.userAgent ?? null,
    })),
    authEvents: eventRows.map((e) => ({
      eventType: e.eventType,
      createdAt: e.createdAt.toISOString(),
      country: e.country ?? null,
      asn: e.asn ?? null,
      userAgent: e.userAgent ?? null,
    })),
    transfers: transferRows.map((t) => ({
      id: t.id,
      createdAt: t.createdAt.toISOString(),
      expiresAt: t.expiresAt.toISOString(),
      downloadCount: t.downloadCount,
      maxDownloads: t.maxDownloads,
      isCompleted: t.isCompleted,
      isDeleted: t.isDeleted,
      hasPassword: t.passwordHash !== null,
      files: (filesByTransfer.get(t.id) ?? []).map((f) => ({
        encryptedName: f.encryptedName,
        encryptedNameIv: f.encryptedNameIv,
        fileIv: f.fileIv,
        size: f.size,
        mimeType: f.mimeType ?? null,
        createdAt: f.createdAt.toISOString(),
      })),
    })),
  };
}

