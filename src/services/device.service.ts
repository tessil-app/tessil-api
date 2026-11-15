// Access keys. See docs/adr/0015-access-keys-cli-and-mcp.md.
//
// The server's part is small on purpose: it knows a device's public key
// and the hash of its token, which permissions a person gave it, and when
// it stops working. It never holds anything a device could decrypt with.

import { createHash } from "node:crypto";
import { and, desc, eq, gt, isNotNull, isNull, lt, or, sql } from "drizzle-orm";
import { nanoid } from "nanoid";
import { db } from "../db";
import { devicePortalKeys, devices, portalMembers, portals, sessions, type Device } from "../db/schema";

export const DEVICE_PERMISSIONS = [
  "transfers:send",
  "transfers:read",
  "transfers:delete",
  "portals:read",
  "portals:manage",
  "portals:send-back",
] as const;
export type DevicePermission = (typeof DEVICE_PERMISSIONS)[number];

/** What an account without portals may hand out. */
export const TRANSFER_PERMISSIONS: readonly DevicePermission[] = [
  "transfers:send",
  "transfers:read",
  "transfers:delete",
];

export const DEVICE_PUBLIC_KEY_BYTES = 65;
export const DEVICE_TOKEN_PREFIX = "tsl_";
export const DEVICE_LIFETIME_DAYS = 90;
const PAIRING_MINUTES = 10;
// No 0/O or 1/I/L: the code is read off one screen and typed into another.
const PAIRING_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
const PAIRING_LENGTH = 8;
// Stamping every request would be a write per request.
const LAST_USED_RESOLUTION_MS = 5 * 60 * 1000;

const sha256 = (value: string) => createHash("sha256").update(value).digest("hex");

export function hashDeviceToken(token: string): string {
  return sha256(token);
}

/** "ABCD-EFGH", however it was typed. Null when it is not a code. */
export function canonicalisePairingCode(input: string): string | null {
  const code = input.toUpperCase().replace(/[^A-Z0-9]/g, "");
  if (code.length !== PAIRING_LENGTH) return null;
  for (const ch of code) if (!PAIRING_ALPHABET.includes(ch)) return null;
  return code;
}

function newPairingCode(): string {
  let code = "";
  while (code.length < PAIRING_LENGTH) {
    const [b] = crypto.getRandomValues(new Uint8Array(1));
    // Reject the tail so every letter is equally likely.
    if (b < 256 - (256 % PAIRING_ALPHABET.length)) code += PAIRING_ALPHABET[b % PAIRING_ALPHABET.length];
  }
  return code;
}

export function cleanPermissions(input: readonly string[]): DevicePermission[] {
  return DEVICE_PERMISSIONS.filter((p) => input.includes(p));
}

/** Usable right now: approved, not revoked, not past its date. */
export function isActive(device: Device, now = new Date()): boolean {
  return (
    device.userId !== null &&
    device.approvedAt !== null &&
    device.revokedAt === null &&
    device.expiresAt !== null &&
    device.expiresAt.getTime() > now.getTime()
  );
}

/**
 * A program announces itself. The row belongs to nobody until a signed-in
 * person approves it by the pairing code, which the program shows them.
 */
export async function registerPendingDevice(input: {
  name: string;
  publicKey: Uint8Array;
  tokenHash: string;
}): Promise<{ id: string; pairingCode: string; pairingExpiresAt: Date } | null> {
  const pairingCode = newPairingCode();
  const pairingExpiresAt = new Date(Date.now() + PAIRING_MINUTES * 60 * 1000);
  const [row] = await db
    .insert(devices)
    .values({
      id: nanoid(),
      name: input.name,
      publicKey: input.publicKey,
      tokenHash: input.tokenHash,
      pairingHash: sha256(pairingCode),
      pairingExpiresAt,
    })
    .onConflictDoNothing({ target: devices.tokenHash })
    .returning({ id: devices.id });
  // A token hash seen before: refused, so one token cannot be re-registered.
  if (!row) return null;
  return { id: row.id, pairingCode, pairingExpiresAt };
}

/** The pending device a pairing code belongs to, if it is still waiting. */
export async function findPendingByCode(code: string): Promise<Device | null> {
  const [row] = await db
    .select()
    .from(devices)
    .where(
      and(
        eq(devices.pairingHash, sha256(code)),
        isNull(devices.userId),
        isNull(devices.revokedAt),
        gt(devices.pairingExpiresAt, new Date()),
      ),
    )
    .limit(1);
  return row ?? null;
}

/**
 * Gives a pending device to `userId`. The count and the update share a
 * transaction and a per-account lock, so parallel approvals cannot go past
 * the plan's number of keys.
 *
 * The approving session is looked at again under that lock. "Sign out
 * everywhere" revokes sessions first and keys second, under the same lock,
 * so an approval already on its way either finishes before the keys are
 * revoked, and is caught, or finds its session revoked and stops here.
 */
export async function approveDevice(
  userId: string,
  sessionId: string,
  code: string,
  maxDevices: number,
  permissions: DevicePermission[],
  name?: string,
): Promise<{ ok: true; device: Device } | { ok: false; reason: "not_found" | "limit_reached" | "signed_out" }> {
  return db.transaction(async (tx) => {
    await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${`devices:${userId}`}, 0))`);
    const [session] = await tx
      .select({ id: sessions.id })
      .from(sessions)
      .where(and(eq(sessions.id, sessionId), eq(sessions.userId, userId), isNull(sessions.revokedAt)))
      .limit(1);
    if (!session) return { ok: false as const, reason: "signed_out" as const };

    const [active] = await tx
      .select({ n: sql<number>`count(*)` })
      .from(devices)
      .where(and(eq(devices.userId, userId), isNull(devices.revokedAt), gt(devices.expiresAt, new Date())));
    if (Number(active?.n ?? 0) >= maxDevices) return { ok: false as const, reason: "limit_reached" as const };

    const now = new Date();
    const [device] = await tx
      .update(devices)
      .set({
        userId,
        permissions,
        approvedAt: now,
        expiresAt: new Date(now.getTime() + DEVICE_LIFETIME_DAYS * 86_400_000),
        pairingHash: null,
        pairingExpiresAt: null,
        ...(name ? { name } : {}),
      })
      .where(
        and(
          eq(devices.pairingHash, sha256(code)),
          isNull(devices.userId),
          isNull(devices.revokedAt),
          gt(devices.pairingExpiresAt, now),
        ),
      )
      .returning();
    return device ? { ok: true as const, device } : { ok: false as const, reason: "not_found" as const };
  });
}

/** A person's keys, newest first, including revoked and lapsed ones still on record. */
export async function listDevices(userId: string): Promise<Device[]> {
  return db.select().from(devices).where(eq(devices.userId, userId)).orderBy(desc(devices.createdAt));
}

/**
 * Owner-scoped change. Renewing a lapsed key puts it back among the active
 * ones, so that is checked against the plan under the same per-account
 * lock as an approval: two renewals at once cannot both slip through.
 */
export async function updateOwnedDevice(
  userId: string,
  deviceId: string,
  maxDevices: number,
  changes: { name?: string; permissions?: DevicePermission[]; renew?: boolean },
): Promise<{ ok: true; device: Device } | { ok: false; reason: "not_found" | "limit_reached" }> {
  return db.transaction(async (tx) => {
    await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${`devices:${userId}`}, 0))`);
    const [current] = await tx
      .select()
      .from(devices)
      .where(and(eq(devices.id, deviceId), eq(devices.userId, userId), isNull(devices.revokedAt)))
      .limit(1);
    if (!current) return { ok: false as const, reason: "not_found" as const };

    if (changes.renew && !isActive(current)) {
      const [active] = await tx
        .select({ n: sql<number>`count(*)` })
        .from(devices)
        .where(and(eq(devices.userId, userId), isNull(devices.revokedAt), gt(devices.expiresAt, new Date())));
      if (Number(active?.n ?? 0) >= maxDevices) return { ok: false as const, reason: "limit_reached" as const };
    }

    const [device] = await tx
      .update(devices)
      .set({
        ...(changes.name !== undefined ? { name: changes.name } : {}),
        ...(changes.permissions !== undefined ? { permissions: changes.permissions } : {}),
        ...(changes.renew ? { expiresAt: new Date(Date.now() + DEVICE_LIFETIME_DAYS * 86_400_000) } : {}),
      })
      .where(eq(devices.id, deviceId))
      .returning();
    return { ok: true as const, device };
  });
}

/**
 * Stops every key of an account. Part of "sign out everywhere": whoever
 * got into the account may have approved a key of their own, and a key
 * outlives the session that approved it.
 *
 * Call it after the sessions are revoked. It waits for the account's lock,
 * so an approval in flight has either committed, and is revoked here, or
 * has yet to check its session, and will find it gone.
 */
export async function revokeAllDevicesForUser(userId: string): Promise<number> {
  return db.transaction(async (tx) => {
    await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${`devices:${userId}`}, 0))`);
    const updated = await tx
      .update(devices)
      .set({ revokedAt: new Date() })
      .where(and(eq(devices.userId, userId), isNull(devices.revokedAt)))
      .returning({ id: devices.id });
    return updated.length;
  });
}

/** Stops a key at once. False when it is not theirs or was already stopped. */
export async function revokeOwnedDevice(userId: string, deviceId: string): Promise<boolean> {
  const updated = await db
    .update(devices)
    .set({ revokedAt: new Date() })
    .where(and(eq(devices.id, deviceId), eq(devices.userId, userId), isNull(devices.revokedAt)))
    .returning({ id: devices.id });
  return updated.length > 0;
}

/** The device a token belongs to, in whatever state it is. */
export async function findDeviceByToken(token: string): Promise<Device | null> {
  const [row] = await db.select().from(devices).where(eq(devices.tokenHash, hashDeviceToken(token))).limit(1);
  return row ?? null;
}

/** Notes that a key was used, at most once per few minutes. */
export async function touchDevice(device: Device): Promise<void> {
  const now = Date.now();
  if (device.lastUsedAt && now - device.lastUsedAt.getTime() < LAST_USED_RESOLUTION_MS) return;
  await db.update(devices).set({ lastUsedAt: new Date(now) }).where(eq(devices.id, device.id));
}

/**
 * Removes pending rows nobody approved and keys that stopped working long
 * ago. Run from the cleanup job.
 */
export async function purgeDeadDevices(): Promise<number> {
  const longAgo = new Date(Date.now() - 30 * 86_400_000);
  const removed = await db
    .delete(devices)
    .where(
      or(
        and(isNull(devices.userId), lt(devices.pairingExpiresAt, new Date())),
        and(isNotNull(devices.revokedAt), lt(devices.revokedAt, longAgo)),
        and(isNotNull(devices.expiresAt), lt(devices.expiresAt, longAgo)),
      ),
    )
    .returning({ id: devices.id });
  return removed.length;
}

// ─── portals a key may open ─────────────────────────────────────────────────

/** Which portals a key of this account has been handed. Null when the key is not theirs. */
export async function listGrantsOfOwnedDevice(
  userId: string,
  deviceId: string,
): Promise<{ portalId: string; keyVersion: number }[] | null> {
  const [device] = await db
    .select({ id: devices.id })
    .from(devices)
    .where(and(eq(devices.id, deviceId), eq(devices.userId, userId), isNull(devices.revokedAt)))
    .limit(1);
  if (!device) return null;
  return db
    .select({ portalId: devicePortalKeys.portalId, keyVersion: devicePortalKeys.keyVersion })
    .from(devicePortalKeys)
    .where(eq(devicePortalKeys.deviceId, deviceId));
}

/**
 * Stores a portal's keys for one of the account's own keys. Refused unless
 * the key is theirs and usable and they are a member of the portal: one
 * can only hand on what one holds. The version must be the portal's
 * current one, so a grant cannot be made for keys that were rotated away.
 */
export async function grantPortalToDevice(
  userId: string,
  deviceId: string,
  portalId: string,
  keyVersion: number,
  sealedKeys: Uint8Array,
): Promise<"ok" | "not_found" | "stale_version"> {
  const [row] = await db
    .select({ portalVersion: portals.keyVersion })
    .from(devices)
    .innerJoin(portalMembers, and(eq(portalMembers.userId, devices.userId), eq(portalMembers.portalId, portalId)))
    .innerJoin(portals, eq(portals.id, portalMembers.portalId))
    .where(and(eq(devices.id, deviceId), eq(devices.userId, userId), isNull(devices.revokedAt)))
    .limit(1);
  if (!row) return "not_found";
  if (row.portalVersion !== keyVersion) return "stale_version";
  await db
    .insert(devicePortalKeys)
    .values({ deviceId, portalId, keyVersion, sealedKeys })
    .onConflictDoUpdate({
      target: [devicePortalKeys.deviceId, devicePortalKeys.portalId],
      set: { keyVersion, sealedKeys, createdAt: new Date() },
    });
  return "ok";
}

export async function revokePortalFromDevice(userId: string, deviceId: string, portalId: string): Promise<boolean> {
  const removed = await db
    .delete(devicePortalKeys)
    .where(
      and(
        eq(devicePortalKeys.deviceId, deviceId),
        eq(devicePortalKeys.portalId, portalId),
        sql`exists (select 1 from ${devices} where ${devices.id} = ${deviceId} and ${devices.userId} = ${userId})`,
      ),
    )
    .returning({ portalId: devicePortalKeys.portalId });
  return removed.length > 0;
}

export interface GrantedPortal {
  id: string;
  role: string;
  publicBundle: Uint8Array;
  /** The portal's keys as handed to this device. */
  sealedKeys: Uint8Array;
  keyVersion: number;
  isDisabled: boolean;
  closesAt: Date | null;
  createdAt: Date;
}

/**
 * The portals a key can open right now: handed to it, and its account is
 * still a member. Leaving a portal, or being removed from it, takes it
 * away from the account's keys without anyone having to remember them.
 */
export async function listPortalsForDevice(device: Device): Promise<GrantedPortal[]> {
  if (!device.userId) return [];
  return db
    .select({
      id: portals.id,
      role: portalMembers.role,
      publicBundle: portals.publicBundle,
      sealedKeys: devicePortalKeys.sealedKeys,
      keyVersion: devicePortalKeys.keyVersion,
      isDisabled: portals.isDisabled,
      closesAt: portals.closesAt,
      createdAt: portals.createdAt,
    })
    .from(devicePortalKeys)
    .innerJoin(portals, eq(portals.id, devicePortalKeys.portalId))
    .innerJoin(portalMembers, and(eq(portalMembers.portalId, portals.id), eq(portalMembers.userId, device.userId)))
    .where(eq(devicePortalKeys.deviceId, device.id))
    .orderBy(desc(portals.createdAt));
}

/** True when this key may open this portal right now. */
export async function deviceMayOpenPortal(device: Device, portalId: string): Promise<boolean> {
  if (!device.userId) return false;
  const [row] = await db
    .select({ portalId: devicePortalKeys.portalId })
    .from(devicePortalKeys)
    .innerJoin(
      portalMembers,
      and(eq(portalMembers.portalId, devicePortalKeys.portalId), eq(portalMembers.userId, device.userId)),
    )
    .where(and(eq(devicePortalKeys.deviceId, device.id), eq(devicePortalKeys.portalId, portalId)))
    .limit(1);
  return row !== undefined;
}
