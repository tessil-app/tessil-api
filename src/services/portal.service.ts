// Portals. The server stores opaque blobs and membership; all keys are
// made and used in the browser. See docs/adr/0014-portal-keys-and-vault-items.md.

import { and, count, eq, sql } from "drizzle-orm";
import { nanoid } from "nanoid";
import { db } from "../db";
import { portalMembers, portals, type Portal } from "../db/schema";

// nonce(12) + public key(65) + a short title + tag(16), with headroom.
export const PUBLIC_BUNDLE_MIN_BYTES = 12 + 65 + 16;
export const PUBLIC_BUNDLE_MAX_BYTES = 2048;
// version(1) + encapsulated key(65) + link key(32) + PKCS#8 key + tag(16).
export const SEALED_KEYS_MIN_BYTES = 1 + 65 + 32 + 16;
export const SEALED_KEYS_MAX_BYTES = 1024;

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
 * Creates a portal with its owner as the first member. Returns null when
 * the owner already has `maxPortals`; the count and the insert share a
 * transaction and a per-owner lock so parallel creates cannot overshoot.
 */
export async function createPortal(
  ownerId: string,
  maxPortals: number,
  blobs: { publicBundle: Uint8Array; sealedKeys: Uint8Array },
): Promise<Portal | null> {
  return db.transaction(async (tx) => {
    await tx.execute(
      sql`select pg_advisory_xact_lock(hashtextextended(${`portals:${ownerId}`}, 0))`,
    );
    const [owned] = await tx.select({ n: count() }).from(portals).where(eq(portals.ownerId, ownerId));
    if (Number(owned?.n ?? 0) >= maxPortals) return null;

    const [portal] = await tx
      .insert(portals)
      .values({ id: nanoid(), ownerId, publicBundle: blobs.publicBundle })
      .returning();
    await tx.insert(portalMembers).values({
      portalId: portal.id,
      userId: ownerId,
      role: "owner",
      keyVersion: portal.keyVersion,
      sealedKeys: blobs.sealedKeys,
    });
    return portal;
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

/** Owner-scoped delete; members go with it. False when not found or not theirs. */
export async function deleteOwnedPortal(ownerId: string, portalId: string): Promise<boolean> {
  const deleted = await db
    .delete(portals)
    .where(and(eq(portals.id, portalId), eq(portals.ownerId, ownerId)))
    .returning({ id: portals.id });
  return deleted.length > 0;
}
