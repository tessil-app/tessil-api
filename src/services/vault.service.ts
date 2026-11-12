// Per-user vault — stores opaque crypto blobs the server cannot read.
//
// The vault holds a random per-user `K_vault` wrapped twice: once under a
// password-derived KEK and once under a recovery-phrase-derived KEK.
// All KDF work happens client-side; the server only persists salts and
// wrap blobs. See docs/adr/0004-vault-redesign-password-and-recovery-phrase.md.
//
// Wrap blob layout is AES-GCM-256 over a 32-byte K_vault:
//   iv(12) || ciphertext(32) || tag(16)  = 60 bytes
//
// Salts are 16 bytes (Argon2id RFC 9106 minimum).

import { and, eq, isNull } from "drizzle-orm";
import { db } from "../db";
import { nanoid } from "nanoid";
import { authenticators, users, userVaults, vaultItems, vaultPasskeyWraps, type UserVault } from "../db/schema";

export const WRAP_BYTES = 60;
export const SALT_BYTES = 16;
export const CURRENT_KDF_VERSION = 1;

export interface VaultBlobs {
  /** Absent for a vault without a password; then `passkey` is required. */
  saltPassword?: Uint8Array;
  wrapPassword?: Uint8Array;
  saltPhrase: Uint8Array;
  wrapPhrase: Uint8Array;
  kdfVersion: number;
  /** A passkey that unlocks the vault from the start. */
  passkey?: { authenticatorId: string; prfSalt: Uint8Array; wrap: Uint8Array };
}

/** Fetch the vault row for a user, or null if setup has not happened. */
export async function getUserVault(userId: string): Promise<UserVault | null> {
  const [row] = await db
    .select()
    .from(userVaults)
    .where(eq(userVaults.userId, userId))
    .limit(1);
  return row ?? null;
}

/**
 * One-shot vault setup. Inserts the row and stamps
 * `users.vault_setup_completed_at` in a single transaction. The user-row
 * stamp is the source of truth for the setup-guard middleware (cheap to
 * read on every request), and the vault row holds the blobs.
 *
 * Returns `{ ok: true }` on first-time setup, `{ ok: false, reason: 'already_setup' }`
 * if the row already exists. Idempotent under racing concurrent calls — the
 * unique PK on `user_id` collapses the second insert.
 */
export async function createUserVault(
  userId: string,
  blobs: VaultBlobs,
): Promise<{ ok: true } | { ok: false; reason: "already_setup" | "not_your_passkey" }> {
  const existing = await getUserVault(userId);
  if (existing) return { ok: false, reason: "already_setup" };

  if (blobs.passkey) {
    const [owned] = await db
      .select({ id: authenticators.id })
      .from(authenticators)
      .where(
        and(eq(authenticators.id, blobs.passkey.authenticatorId), eq(authenticators.userId, userId)),
      )
      .limit(1);
    if (!owned) return { ok: false, reason: "not_your_passkey" };
  }

  return db.transaction(async (tx) => {
    const inserted = await tx
      .insert(userVaults)
      .values({
        userId,
        saltPassword: blobs.saltPassword ?? null,
        saltPhrase: blobs.saltPhrase,
        wrapPassword: blobs.wrapPassword ?? null,
        wrapPhrase: blobs.wrapPhrase,
        kdfVersion: blobs.kdfVersion,
      })
      .onConflictDoNothing({ target: userVaults.userId })
      .returning({ userId: userVaults.userId });

    if (inserted.length === 0) {
      return { ok: false, reason: "already_setup" } as const;
    }

    // Same transaction as the vault: a vault without a password must
    // never exist without the passkey wrap that opens it.
    if (blobs.passkey) {
      await tx.insert(vaultPasskeyWraps).values({
        authenticatorId: blobs.passkey.authenticatorId,
        userId,
        prfSalt: blobs.passkey.prfSalt,
        wrap: blobs.passkey.wrap,
      });
    }

    await tx
      .update(users)
      .set({ vaultSetupCompletedAt: new Date() })
      .where(and(eq(users.id, userId), isNull(users.vaultSetupCompletedAt)));

    return { ok: true } as const;
  });
}

/**
 * Rewrap K_vault under a new password-derived KEK. Caller has already
 * unwrapped K_vault client-side (either with the old password or the
 * recovery phrase) and re-wrapped it under the new password. The wrap
 * under the recovery phrase is untouched, so phrase recovery still
 * works after a password change.
 */
export async function updateVaultPasswordWrap(
  userId: string,
  saltPassword: Uint8Array,
  wrapPassword: Uint8Array,
  kdfVersion: number,
): Promise<boolean> {
  const result = await db
    .update(userVaults)
    .set({
      saltPassword,
      wrapPassword,
      kdfVersion,
      passwordChangedAt: new Date(),
    })
    .where(eq(userVaults.userId, userId))
    .returning({ userId: userVaults.userId });
  return result.length > 0;
}

/**
 * Rewrap K_vault under a freshly generated recovery phrase. Caller has
 * unwrapped K_vault with their password and re-wrapped under the new
 * phrase. The password wrap is untouched.
 */
export async function updateVaultPhraseWrap(
  userId: string,
  saltPhrase: Uint8Array,
  wrapPhrase: Uint8Array,
  kdfVersion: number,
): Promise<boolean> {
  const result = await db
    .update(userVaults)
    .set({
      saltPhrase,
      wrapPhrase,
      kdfVersion,
      phraseRegeneratedAt: new Date(),
    })
    .where(eq(userVaults.userId, userId))
    .returning({ userId: userVaults.userId });
  return result.length > 0;
}

// ─── user keypair ───────────────────────────────────────────────────────────

export const PUBLIC_KEY_BYTES = 65; // uncompressed P-256 point
export const USER_PRIVATE_KEY_KIND = "user_private_key";
// version(1) + iv(12) + PKCS#8 P-256 key + tag(16) is about 170 bytes.
export const WRAPPED_PRIVATE_KEY_MIN_BYTES = 64;
export const WRAPPED_PRIVATE_KEY_MAX_BYTES = 512;

/** True when the bytes are a point on P-256, not just the right length. */
export async function isValidPublicKey(bytes: Uint8Array): Promise<boolean> {
  if (bytes.length !== PUBLIC_KEY_BYTES || bytes[0] !== 0x04) return false;
  try {
    await crypto.subtle.importKey(
      "raw",
      bytes as unknown as ArrayBuffer,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      [],
    );
    return true;
  } catch {
    return false;
  }
}

export interface UserKeypair {
  publicKey: Uint8Array;
  wrappedPrivateKey: Uint8Array;
}

export async function getUserKeypair(userId: string): Promise<UserKeypair | null> {
  const [row] = await db
    .select({ publicKey: users.publicKey, wrappedPrivateKey: vaultItems.ciphertext })
    .from(users)
    .innerJoin(
      vaultItems,
      and(eq(vaultItems.userId, users.id), eq(vaultItems.kind, USER_PRIVATE_KEY_KIND)),
    )
    .where(eq(users.id, userId))
    .limit(1);
  if (!row || !row.publicKey) return null;
  return { publicKey: row.publicKey, wrappedPrivateKey: row.wrappedPrivateKey };
}

/**
 * Stores a user's keypair once. Both halves land in one transaction, so a
 * public key never exists without the private key that answers to it.
 * Anything already encrypted to the key depends on it, so there is no
 * overwrite: replacing a keypair will be an explicit rotation.
 */
export async function createUserKeypair(
  userId: string,
  keypair: UserKeypair,
): Promise<{ ok: true } | { ok: false; reason: "no_vault" | "already_exists" }> {
  if (!(await getUserVault(userId))) return { ok: false, reason: "no_vault" };

  return db.transaction(async (tx) => {
    const inserted = await tx
      .insert(vaultItems)
      .values({
        id: nanoid(),
        userId,
        kind: USER_PRIVATE_KEY_KIND,
        ciphertext: keypair.wrappedPrivateKey,
      })
      .onConflictDoNothing({ target: [vaultItems.userId, vaultItems.kind] })
      .returning({ id: vaultItems.id });
    if (inserted.length === 0) return { ok: false as const, reason: "already_exists" as const };

    await tx
      .update(users)
      .set({ publicKey: keypair.publicKey })
      .where(and(eq(users.id, userId), isNull(users.publicKey)));
    return { ok: true as const };
  });
}

// ─── passkey unlock ─────────────────────────────────────────────────────────

export const PRF_SALT_BYTES = 32;

export interface PasskeyWrap {
  authenticatorId: string;
  /** The WebAuthn credential ID, so the browser can ask for this passkey. */
  credentialId: Uint8Array;
  prfSalt: Uint8Array;
  wrap: Uint8Array;
}

export async function listPasskeyWraps(userId: string): Promise<PasskeyWrap[]> {
  return db
    .select({
      authenticatorId: vaultPasskeyWraps.authenticatorId,
      credentialId: authenticators.credentialId,
      prfSalt: vaultPasskeyWraps.prfSalt,
      wrap: vaultPasskeyWraps.wrap,
    })
    .from(vaultPasskeyWraps)
    .innerJoin(authenticators, eq(authenticators.id, vaultPasskeyWraps.authenticatorId))
    .where(eq(vaultPasskeyWraps.userId, userId));
}

/**
 * Stores (or replaces) the vault wrap for one of the user's passkeys.
 * Refused when the vault does not exist or the passkey is not theirs.
 */
export async function setPasskeyWrap(
  userId: string,
  input: { authenticatorId: string; prfSalt: Uint8Array; wrap: Uint8Array },
): Promise<{ ok: true } | { ok: false; reason: "no_vault" | "not_your_passkey" }> {
  if (!(await getUserVault(userId))) return { ok: false, reason: "no_vault" };
  const [owned] = await db
    .select({ id: authenticators.id })
    .from(authenticators)
    .where(and(eq(authenticators.id, input.authenticatorId), eq(authenticators.userId, userId)))
    .limit(1);
  if (!owned) return { ok: false, reason: "not_your_passkey" };

  await db
    .insert(vaultPasskeyWraps)
    .values({ authenticatorId: input.authenticatorId, userId, prfSalt: input.prfSalt, wrap: input.wrap })
    .onConflictDoUpdate({
      target: vaultPasskeyWraps.authenticatorId,
      set: { prfSalt: input.prfSalt, wrap: input.wrap, createdAt: new Date() },
    });
  return { ok: true };
}

/**
 * Whether taking this passkey away would leave the vault with nothing but
 * its recovery phrase: no password, and no other passkey that unlocks it.
 * Run inside `tx` with the vault row locked, so two removals at once
 * cannot each believe the other passkey is still there.
 */
async function isLastWayIn(
  tx: Parameters<Parameters<typeof db.transaction>[0]>[0],
  userId: string,
  authenticatorId: string,
): Promise<boolean> {
  const [vault] = await tx
    .select({ wrapPassword: userVaults.wrapPassword })
    .from(userVaults)
    .where(eq(userVaults.userId, userId))
    .for("update");
  if (!vault || vault.wrapPassword !== null) return false;
  const wraps = await tx
    .select({ authenticatorId: vaultPasskeyWraps.authenticatorId })
    .from(vaultPasskeyWraps)
    .where(eq(vaultPasskeyWraps.userId, userId));
  return wraps.length === 1 && wraps[0].authenticatorId === authenticatorId;
}

export type RemoveResult = { ok: true } | { ok: false; reason: "not_found" | "last_way_in" };

/** Stops a passkey from unlocking the vault. */
export async function deletePasskeyWrap(userId: string, authenticatorId: string): Promise<RemoveResult> {
  return db.transaction(async (tx) => {
    if (await isLastWayIn(tx, userId, authenticatorId)) {
      return { ok: false as const, reason: "last_way_in" as const };
    }
    const deleted = await tx
      .delete(vaultPasskeyWraps)
      .where(
        and(
          eq(vaultPasskeyWraps.authenticatorId, authenticatorId),
          eq(vaultPasskeyWraps.userId, userId),
        ),
      )
      .returning({ id: vaultPasskeyWraps.authenticatorId });
    return deleted.length > 0
      ? { ok: true as const }
      : { ok: false as const, reason: "not_found" as const };
  });
}

/**
 * Deletes one of the user's passkeys, unless it is the last thing besides
 * the recovery phrase that opens their vault. Deleting a passkey takes its
 * vault wrap with it, so the same rule applies as for removing the wrap.
 */
export async function deletePasskeyKeepingVaultOpen(
  userId: string,
  authenticatorId: string,
): Promise<RemoveResult> {
  return db.transaction(async (tx) => {
    if (await isLastWayIn(tx, userId, authenticatorId)) {
      return { ok: false as const, reason: "last_way_in" as const };
    }
    const deleted = await tx
      .delete(authenticators)
      .where(and(eq(authenticators.id, authenticatorId), eq(authenticators.userId, userId)))
      .returning({ id: authenticators.id });
    return deleted.length > 0
      ? { ok: true as const }
      : { ok: false as const, reason: "not_found" as const };
  });
}
