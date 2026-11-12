// Portals. The server stores opaque blobs and membership; all keys are
// made and used in the browser. See docs/adr/0014-portal-keys-and-vault-items.md.

import { createHash, timingSafeEqual } from "node:crypto";
import { and, count, eq, sql } from "drizzle-orm";
import { nanoid } from "nanoid";
import { db } from "../db";
import { portalInvites, portalMembers, portals, users, type Portal } from "../db/schema";
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
  /** The owner: who a guest received the keys from. */
  owner: { userId: string; email: string; publicKey: Uint8Array | null };
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
      ownerId: portals.ownerId,
      ownerEmail: users.email,
      ownerPublicKey: users.publicKey,
    })
    .from(portalMembers)
    .innerJoin(portals, eq(portals.id, portalMembers.portalId))
    .innerJoin(users, eq(users.id, portals.ownerId))
    .where(eq(portalMembers.userId, userId));
  return rows
    .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
    .map(({ ownerId, ownerEmail, ownerPublicKey, ...row }) => ({
      ...row,
      owner: { userId: ownerId, email: ownerEmail, publicKey: ownerPublicKey },
    }));
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

// ─── sharing a portal ───────────────────────────────────────────────────────

export interface PortalGuest {
  userId: string;
  email: string;
  /** Needed by the owner's browser to check who they are sharing with. */
  publicKey: Uint8Array | null;
}

export interface PortalInviteView {
  id: string;
  email: string;
  createdAt: Date;
  /**
   * The invitee's account, once they have one with a keypair. Until then
   * the owner cannot hand over the keys and the invite just waits.
   */
  ready: { userId: string; publicKey: Uint8Array } | null;
}

export interface PortalSharing {
  guests: PortalGuest[];
  invites: PortalInviteView[];
}

export async function getPortalSharing(portalId: string): Promise<PortalSharing> {
  const guests = await db
    .select({ userId: users.id, email: users.email, publicKey: users.publicKey })
    .from(portalMembers)
    .innerJoin(users, eq(users.id, portalMembers.userId))
    .where(and(eq(portalMembers.portalId, portalId), eq(portalMembers.role, "member")));

  const invites = await db
    .select({
      id: portalInvites.id,
      email: portalInvites.email,
      createdAt: portalInvites.createdAt,
      userId: users.id,
      publicKey: users.publicKey,
      deletedAt: users.deletedAt,
    })
    .from(portalInvites)
    .leftJoin(users, eq(users.email, portalInvites.email))
    .where(eq(portalInvites.portalId, portalId));

  return {
    guests,
    invites: invites.map((i) => ({
      id: i.id,
      email: i.email,
      createdAt: i.createdAt,
      ready: i.userId && i.publicKey && !i.deletedAt ? { userId: i.userId, publicKey: i.publicKey } : null,
    })),
  };
}

export type InviteResult =
  | { ok: true; inviteId: string }
  | { ok: false; reason: "not_owner" | "own_email" | "full" | "already_invited" | "already_member" };

/** Records that the owner wants to share with `email`. Locks the portal so the guest limit holds. */
export async function createPortalInvite(
  ownerId: string,
  ownerEmail: string,
  portalId: string,
  email: string,
  maxGuests: number,
): Promise<InviteResult> {
  if (email === ownerEmail) return { ok: false, reason: "own_email" };
  return db.transaction(async (tx) => {
    const [portal] = await tx
      .select({ id: portals.id })
      .from(portals)
      .where(and(eq(portals.id, portalId), eq(portals.ownerId, ownerId)))
      .for("update");
    if (!portal) return { ok: false as const, reason: "not_owner" as const };

    const guests = await tx
      .select({ email: users.email })
      .from(portalMembers)
      .innerJoin(users, eq(users.id, portalMembers.userId))
      .where(and(eq(portalMembers.portalId, portalId), eq(portalMembers.role, "member")));
    if (guests.some((g) => g.email === email)) return { ok: false as const, reason: "already_member" as const };

    const pending = await tx
      .select({ email: portalInvites.email })
      .from(portalInvites)
      .where(eq(portalInvites.portalId, portalId));
    if (pending.some((p) => p.email === email)) return { ok: false as const, reason: "already_invited" as const };
    if (guests.length + pending.length >= maxGuests) return { ok: false as const, reason: "full" as const };

    const id = nanoid();
    await tx.insert(portalInvites).values({ id, portalId, email });
    return { ok: true as const, inviteId: id };
  });
}

/** Owner-scoped. False when there is no such invite on a portal they own. */
export async function deletePortalInvite(ownerId: string, portalId: string, inviteId: string): Promise<boolean> {
  const owned = await db
    .select({ id: portals.id })
    .from(portals)
    .where(and(eq(portals.id, portalId), eq(portals.ownerId, ownerId)))
    .limit(1);
  if (owned.length === 0) return false;
  const deleted = await db
    .delete(portalInvites)
    .where(and(eq(portalInvites.id, inviteId), eq(portalInvites.portalId, portalId)))
    .returning({ id: portalInvites.id });
  return deleted.length > 0;
}

export type AdmitResult =
  | { ok: true; userId: string }
  | { ok: false; reason: "not_owner" | "no_invite" | "not_ready" | "key_changed" };

/**
 * Turns an invite into a membership: the owner's browser has sealed the
 * portal's keys to the invitee's public key and hands them over here.
 * `sealedTo` is the public key the owner sealed to; if the invitee's key
 * is no longer that one, the handover would be unopenable, so it is
 * refused and the owner's browser tries again with the current key.
 */
export async function admitInvitee(
  ownerId: string,
  portalId: string,
  inviteId: string,
  sealedKeys: Uint8Array,
  sealedTo: Uint8Array,
): Promise<AdmitResult> {
  return db.transaction(async (tx) => {
    const [portal] = await tx
      .select({ id: portals.id, keyVersion: portals.keyVersion })
      .from(portals)
      .where(and(eq(portals.id, portalId), eq(portals.ownerId, ownerId)))
      .for("update");
    if (!portal) return { ok: false as const, reason: "not_owner" as const };

    const [invite] = await tx
      .select({ id: portalInvites.id, email: portalInvites.email })
      .from(portalInvites)
      .where(and(eq(portalInvites.id, inviteId), eq(portalInvites.portalId, portalId)));
    if (!invite) return { ok: false as const, reason: "no_invite" as const };

    const [invitee] = await tx
      .select({ id: users.id, publicKey: users.publicKey, deletedAt: users.deletedAt })
      .from(users)
      .where(eq(users.email, invite.email));
    if (!invitee || invitee.deletedAt || !invitee.publicKey) {
      return { ok: false as const, reason: "not_ready" as const };
    }
    if (Buffer.compare(Buffer.from(invitee.publicKey), Buffer.from(sealedTo)) !== 0) {
      return { ok: false as const, reason: "key_changed" as const };
    }

    await tx
      .insert(portalMembers)
      .values({
        portalId,
        userId: invitee.id,
        role: "member",
        keyVersion: portal.keyVersion,
        sealedKeys,
      })
      .onConflictDoNothing({ target: [portalMembers.portalId, portalMembers.userId] });
    await tx.delete(portalInvites).where(eq(portalInvites.id, invite.id));
    return { ok: true as const, userId: invitee.id };
  });
}

/** A member replaces their own copy of the keys, e.g. with one kept under their vault. */
export async function replaceOwnMemberKeys(
  portalId: string,
  userId: string,
  sealedKeys: Uint8Array,
): Promise<boolean> {
  const updated = await db
    .update(portalMembers)
    .set({ sealedKeys })
    .where(and(eq(portalMembers.portalId, portalId), eq(portalMembers.userId, userId)))
    .returning({ userId: portalMembers.userId });
  return updated.length > 0;
}

/**
 * Removes a guest. The owner can remove anyone but themselves; a guest can
 * remove themselves. The owner's own membership only goes with the portal.
 */
export async function removeGuest(
  actorId: string,
  portalId: string,
  targetUserId: string,
): Promise<boolean> {
  const [portal] = await db
    .select({ ownerId: portals.ownerId })
    .from(portals)
    .where(eq(portals.id, portalId))
    .limit(1);
  if (!portal || targetUserId === portal.ownerId) return false;
  if (actorId !== portal.ownerId && actorId !== targetUserId) return false;
  const deleted = await db
    .delete(portalMembers)
    .where(
      and(
        eq(portalMembers.portalId, portalId),
        eq(portalMembers.userId, targetUserId),
        eq(portalMembers.role, "member"),
      ),
    )
    .returning({ userId: portalMembers.userId });
  return deleted.length > 0;
}
