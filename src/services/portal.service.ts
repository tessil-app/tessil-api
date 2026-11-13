// Portals. The server stores opaque blobs and membership; all keys are
// made and used in the browser. See docs/adr/0014-portal-keys-and-vault-items.md.

import { createHash, timingSafeEqual } from "node:crypto";
import { and, count, eq, sql } from "drizzle-orm";
import { db } from "../db";
import { portalMembers, portals, type Portal } from "../db/schema";
import { softDeleteDepositsOf } from "./file.service";

// nonce(12) + public key(65) + a short title + tag(16) at the least. The
// bundle also carries what the owner asks visitors for (a list of up to
// twenty labelled items), so the ceiling leaves room for that.
export const PUBLIC_BUNDLE_MIN_BYTES = 12 + 65 + 16;
export const PUBLIC_BUNDLE_MAX_BYTES = 8192;
// version(1) + encapsulated key(65) + link key(32) + PKCS#8 key + tag(16).
export const SEALED_KEYS_MIN_BYTES = 1 + 65 + 32 + 16;
export const SEALED_KEYS_MAX_BYTES = 1024;

export const DEPOSIT_TOKEN_BYTES = 32;

function hashDepositToken(token: Uint8Array): string {
  return createHash("sha256").update(token).digest("hex");
}

/** True when `token` is the one this portal was created with. */
export function depositTokenMatches(portal: Portal, token: Uint8Array): boolean {
  const expected = Buffer.from(portal.depositTokenHash, "hex");
  const actual = Buffer.from(hashDepositToken(token), "hex");
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

export interface PortalForMember {
  id: string;
  role: string;
  publicBundle: Uint8Array;
  sealedKeys: Uint8Array;
  keyVersion: number;
  isDisabled: boolean;
  createdAt: Date;
}

export async function countOwnedPortals(userId: string): Promise<number> {
  const [row] = await db.select({ n: count() }).from(portals).where(eq(portals.ownerId, userId));
  return Number(row?.n ?? 0);
}

/**
 * Creates a portal with its owner as the first member. The ID is chosen by
 * the browser, because the portal's keys are bound to it before the server
 * ever sees them. The count and the insert share a transaction and a
 * per-owner lock so parallel creates cannot overshoot the plan's limit.
 */
export async function createPortal(
  ownerId: string,
  maxPortals: number,
  blobs: { id: string; publicBundle: Uint8Array; sealedKeys: Uint8Array; depositToken: Uint8Array },
): Promise<{ ok: true; portal: Portal } | { ok: false; reason: "limit_reached" | "id_taken" }> {
  return db.transaction(async (tx) => {
    await tx.execute(
      sql`select pg_advisory_xact_lock(hashtextextended(${`portals:${ownerId}`}, 0))`,
    );
    const [owned] = await tx.select({ n: count() }).from(portals).where(eq(portals.ownerId, ownerId));
    if (Number(owned?.n ?? 0) >= maxPortals) return { ok: false as const, reason: "limit_reached" as const };

    const [portal] = await tx
      .insert(portals)
      .values({
        id: blobs.id,
        ownerId,
        publicBundle: blobs.publicBundle,
        depositTokenHash: hashDepositToken(blobs.depositToken),
      })
      .onConflictDoNothing({ target: portals.id })
      .returning();
    if (!portal) return { ok: false as const, reason: "id_taken" as const };
    await tx.insert(portalMembers).values({
      portalId: portal.id,
      userId: ownerId,
      role: "owner",
      keyVersion: portal.keyVersion,
      sealedKeys: blobs.sealedKeys,
    });
    return { ok: true as const, portal };
  });
}

/** Every portal the user is a member of, newest first. */
export async function listPortalsForMember(userId: string): Promise<PortalForMember[]> {
  const rows = await db
    .select({
      id: portals.id,
      role: portalMembers.role,
      publicBundle: portals.publicBundle,
      sealedKeys: portalMembers.sealedKeys,
      keyVersion: portals.keyVersion,
      isDisabled: portals.isDisabled,
      createdAt: portals.createdAt,
    })
    .from(portalMembers)
    .innerJoin(portals, eq(portals.id, portalMembers.portalId))
    .where(eq(portalMembers.userId, userId));
  return rows.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
}

export async function getPortal(id: string): Promise<Portal | null> {
  const [row] = await db.select().from(portals).where(eq(portals.id, id)).limit(1);
  return row ?? null;
}

/** Owner-scoped update. False when the portal does not exist or is not theirs. */
export async function updateOwnedPortal(
  ownerId: string,
  portalId: string,
  changes: { isDisabled?: boolean; publicBundle?: Uint8Array },
): Promise<boolean> {
  const updated = await db
    .update(portals)
    .set(changes)
    .where(and(eq(portals.id, portalId), eq(portals.ownerId, ownerId)))
    .returning({ id: portals.id });
  return updated.length > 0;
}

/**
 * Owner-scoped delete; members go with it. Deposits are marked deleted in
 * the same transaction so the sweep removes their storage; without that
 * they would live on, unreadable, until they expired. False when not found
 * or not theirs.
 */
export async function deleteOwnedPortal(ownerId: string, portalId: string): Promise<boolean> {
  return db.transaction(async (tx) => {
    const [owned] = await tx
      .select({ id: portals.id })
      .from(portals)
      .where(and(eq(portals.id, portalId), eq(portals.ownerId, ownerId)))
      .for("update");
    if (!owned) return false;
    await softDeleteDepositsOf([portalId], tx);
    await tx.delete(portals).where(eq(portals.id, portalId));
    return true;
  });
}

/** The user's role in a portal, or null when they are not a member. */
export async function getMemberRole(portalId: string, userId: string): Promise<string | null> {
  const [row] = await db
    .select({ role: portalMembers.role })
    .from(portalMembers)
    .where(and(eq(portalMembers.portalId, portalId), eq(portalMembers.userId, userId)))
    .limit(1);
  return row?.role ?? null;
}

export async function listOwnedPortalIds(ownerId: string): Promise<string[]> {
  const rows = await db.select({ id: portals.id }).from(portals).where(eq(portals.ownerId, ownerId));
  return rows.map((r) => r.id);
}
