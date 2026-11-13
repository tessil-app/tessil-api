// Vault endpoints. The server stores opaque crypto blobs only — all KDF
// work and (un)wrapping happens client-side. See
// docs/adr/0004-vault-redesign-password-and-recovery-phrase.md.
//
// Surface:
//   GET  /api/me/vault                (auth — read salts + wraps + setup flag)
//   POST /api/me/vault/setup          (auth — one-shot first-time setup)
//   POST /api/me/vault/password       (auth — rewrap K_vault under new password)
//   POST /api/me/vault/phrase         (auth — rewrap K_vault under new phrase)
//   POST /api/me/vault/keypair        (auth, one-shot: public key + wrapped private key)
//   PUT    /api/me/vault/passkeys/:authenticatorId  (auth, let a passkey unlock the vault)
//   DELETE /api/me/vault/passkeys/:authenticatorId  (auth, stop that)

import { sendPortalNotice } from "../services/email.service";
import { listInvitesForEmail } from "../services/portal.service";
import { Elysia, t } from "elysia";
import { authPlugin } from "../auth/middleware";
import { ipContextPlugin } from "../auth/ipContextPlugin";
import { logAuthEvent } from "../auth/events";
import { checkRateLimit, rateLimiters } from "../services/ratelimit.service";
import {
  CURRENT_KDF_VERSION,
  SALT_BYTES,
  WRAP_BYTES,
  PUBLIC_KEY_BYTES,
  WRAPPED_PRIVATE_KEY_MAX_BYTES,
  WRAPPED_PRIVATE_KEY_MIN_BYTES,
  PRF_SALT_BYTES,
  createUserKeypair,
  deletePasskeyWrap,
  listPasskeyWraps,
  setPasskeyWrap,
  createUserVault,
  getUserKeypair,
  getUserVault,
  isValidPublicKey,
  updateVaultPasswordWrap,
  updateVaultPhraseWrap,
} from "../services/vault.service";

export const LAST_WAY_IN_MESSAGE =
  "This is the only thing besides your recovery phrase that opens your vault. Add a vault password or another passkey first.";

function decodeBase64Url(input: string): Uint8Array | null {
  // Strict base64url — '-_' alphabet, no padding. Buffer's decoder is lenient
  // about garbage; we reject it up front so a malformed payload cannot reach
  // the bytea column.
  if (!/^[A-Za-z0-9_-]+$/.test(input)) return null;
  try {
    return new Uint8Array(Buffer.from(input, "base64url"));
  } catch {
    return null;
  }
}

function bytesToBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function decodeFixedLength(input: string, byteLength: number): Uint8Array | null {
  const bytes = decodeBase64Url(input);
  if (!bytes || bytes.length !== byteLength) return null;
  return bytes;
}

function validateKdfVersion(version: number): boolean {
  // Only the current version is accepted. When parameters bump we widen
  // the accept-list and migrate readers/writers separately.
  return Number.isInteger(version) && version === CURRENT_KDF_VERSION;
}

export const vaultRoutes = new Elysia({ prefix: "/api/me/vault" })
  .use(authPlugin)
  .use(ipContextPlugin)

  .get("/", async ({ me, set }) => {
    if (!me) {
      set.status = 401;
      return { error: "Not authenticated" };
    }
    const row = await getUserVault(me.id);
    if (!row) {
      // Tells the browser this API can create a vault without a password.
      return { isSetup: false as const, passkeyOnlySetup: true as const };
    }
    const [keypair, passkeyWraps] = await Promise.all([
      getUserKeypair(me.id),
      listPasskeyWraps(me.id),
    ]);
    return {
      isSetup: true as const,
      // Passkeys that can unlock this vault, each with what the browser
      // needs to ask the passkey for its key.
      passkeyWraps: passkeyWraps.map((w) => ({
        authenticatorId: w.authenticatorId,
        credentialId: bytesToBase64Url(w.credentialId),
        prfSalt: bytesToBase64Url(w.prfSalt),
        wrap: bytesToBase64Url(w.wrap),
      })),
      publicKey: keypair ? bytesToBase64Url(keypair.publicKey) : null,
      wrappedPrivateKey: keypair ? bytesToBase64Url(keypair.wrappedPrivateKey) : null,
      kdfVersion: row.kdfVersion,
      // Both null for a vault opened by passkey and recovery phrase only.
      saltPassword: row.saltPassword ? bytesToBase64Url(row.saltPassword) : null,
      saltPhrase: bytesToBase64Url(row.saltPhrase),
      wrapPassword: row.wrapPassword ? bytesToBase64Url(row.wrapPassword) : null,
      wrapPhrase: bytesToBase64Url(row.wrapPhrase),
      passwordChangedAt: row.passwordChangedAt?.toISOString() ?? null,
      phraseRegeneratedAt: row.phraseRegeneratedAt?.toISOString() ?? null,
    };
  })

  .post(
    "/setup",
    async ({ body, me, ipContext, originRejected, request, set }) => {
      if (originRejected) {
        set.status = 403;
        return { error: "Forbidden" };
      }
      if (!me) {
        set.status = 401;
        return { error: "Not authenticated" };
      }

      const limit = await checkRateLimit(me.id, rateLimiters.vaultSetup);
      if (!limit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(limit.resetIn);
        return { error: "Rate limit exceeded. Try again later." };
      }

      if (!validateKdfVersion(body.kdfVersion)) {
        set.status = 400;
        return { error: "Unsupported kdfVersion." };
      }

      const saltPhrase = decodeFixedLength(body.saltPhrase, SALT_BYTES);
      const wrapPhrase = decodeFixedLength(body.wrapPhrase, WRAP_BYTES);
      if (!saltPhrase || !wrapPhrase) {
        set.status = 400;
        return { error: "Malformed vault payload." };
      }

      // The recovery phrase is always there. Besides it, a vault needs a
      // password, a passkey, or both: with neither, every unlock would
      // mean typing twelve words.
      const hasPassword = body.saltPassword !== undefined || body.wrapPassword !== undefined;
      const saltPassword = hasPassword ? decodeFixedLength(body.saltPassword ?? "", SALT_BYTES) : null;
      const wrapPassword = hasPassword ? decodeFixedLength(body.wrapPassword ?? "", WRAP_BYTES) : null;
      if (hasPassword && (!saltPassword || !wrapPassword)) {
        set.status = 400;
        return { error: "Malformed vault payload." };
      }

      let passkey: { authenticatorId: string; prfSalt: Uint8Array; wrap: Uint8Array } | undefined;
      if (body.passkey) {
        const prfSalt = decodeFixedLength(body.passkey.prfSalt, PRF_SALT_BYTES);
        const wrap = decodeFixedLength(body.passkey.wrap, WRAP_BYTES);
        if (!prfSalt || !wrap || !/^[A-Za-z0-9_-]{21}$/.test(body.passkey.authenticatorId)) {
          set.status = 400;
          return { error: "Malformed vault payload." };
        }
        passkey = { authenticatorId: body.passkey.authenticatorId, prfSalt, wrap };
      }
      if (!hasPassword && !passkey) {
        set.status = 400;
        return { error: "A vault needs a password or a passkey." };
      }

      const result = await createUserVault(me.id, {
        ...(saltPassword && wrapPassword ? { saltPassword, wrapPassword } : {}),
        saltPhrase,
        wrapPhrase,
        kdfVersion: body.kdfVersion,
        passkey,
      });
      if (!result.ok && result.reason === "not_your_passkey") {
        set.status = 404;
        return { error: "Passkey not found." };
      }
      if (!result.ok) {
        // Setup is one-shot. Subsequent attempts must go through change-password
        // or regenerate-phrase. 409 is the honest status here.
        set.status = 409;
        return { error: "Vault is already set up." };
      }

      await logAuthEvent({
        eventType: "vault_setup_completed",
        userId: me.id,
        email: me.email,
        ipContext,
        userAgent: request.headers.get("user-agent"),
      });

      return { ok: true as const };
    },
    {
      body: t.Object({
        kdfVersion: t.Integer({ minimum: 1, maximum: 1000 }),
        saltPassword: t.Optional(t.String({ maxLength: 64 })),
        saltPhrase: t.String({ maxLength: 64 }),
        wrapPassword: t.Optional(t.String({ maxLength: 128 })),
        wrapPhrase: t.String({ maxLength: 128 }),
        passkey: t.Optional(
          t.Object({
            authenticatorId: t.String({ maxLength: 21 }),
            prfSalt: t.String({ maxLength: 64 }),
            wrap: t.String({ maxLength: 128 }),
          }),
        ),
      }),
    },
  )

  .post(
    "/keypair",
    async ({ body, me, ipContext, originRejected, request, set }) => {
      if (originRejected) {
        set.status = 403;
        return { error: "Forbidden" };
      }
      if (!me) {
        set.status = 401;
        return { error: "Not authenticated" };
      }

      const limit = await checkRateLimit(me.id, rateLimiters.vaultKeypair);
      if (!limit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(limit.resetIn);
        return { error: "Rate limit exceeded. Try again later." };
      }

      const publicKey = decodeFixedLength(body.publicKey, PUBLIC_KEY_BYTES);
      const wrappedPrivateKey = decodeBase64Url(body.wrappedPrivateKey);
      if (
        !publicKey ||
        !(await isValidPublicKey(publicKey)) ||
        !wrappedPrivateKey ||
        wrappedPrivateKey.length < WRAPPED_PRIVATE_KEY_MIN_BYTES ||
        wrappedPrivateKey.length > WRAPPED_PRIVATE_KEY_MAX_BYTES
      ) {
        set.status = 400;
        return { error: "Malformed keypair payload." };
      }

      const result = await createUserKeypair(me.id, { publicKey, wrappedPrivateKey });
      if (!result.ok) {
        set.status = 409;
        return {
          error:
            result.reason === "no_vault"
              ? "Set up the vault first."
              : "A keypair already exists.",
        };
      }

      await logAuthEvent({
        eventType: "vault_keypair_created",
        userId: me.id,
        email: me.email,
        ipContext,
        userAgent: request.headers.get("user-agent"),
      });

      // Anyone who invited this address to a portal can now give access.
      void listInvitesForEmail(me.email)
        .then((invites) =>
          Promise.all(
            invites.map((i) =>
              sendPortalNotice({
                kind: "invitee_ready",
                to: i.ownerEmail,
                inviteeEmail: me.email,
                portalId: i.portalId,
              }),
            ),
          ),
        )
        .catch((err) => console.error("[vault] could not notify portal owners:", err));

      set.status = 201;
      return { ok: true as const };
    },
    {
      body: t.Object({
        publicKey: t.String({ maxLength: 128 }),
        wrappedPrivateKey: t.String({ maxLength: 1024 }),
      }),
    },
  )

  .put(
    "/passkeys/:authenticatorId",
    async ({ params, body, me, ipContext, originRejected, request, set }) => {
      if (originRejected) {
        set.status = 403;
        return { error: "Forbidden" };
      }
      if (!me) {
        set.status = 401;
        return { error: "Not authenticated" };
      }
      const limit = await checkRateLimit(me.id, rateLimiters.vaultPasswordChange);
      if (!limit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(limit.resetIn);
        return { error: "Rate limit exceeded. Try again later." };
      }

      const prfSalt = decodeFixedLength(body.prfSalt, PRF_SALT_BYTES);
      const wrap = decodeFixedLength(body.wrap, WRAP_BYTES);
      if (!prfSalt || !wrap || !/^[A-Za-z0-9_-]{21}$/.test(params.authenticatorId)) {
        set.status = 400;
        return { error: "Malformed passkey wrap." };
      }

      const result = await setPasskeyWrap(me.id, {
        authenticatorId: params.authenticatorId,
        prfSalt,
        wrap,
      });
      if (!result.ok) {
        // Someone else's passkey and no such passkey look the same.
        set.status = result.reason === "no_vault" ? 409 : 404;
        return {
          error: result.reason === "no_vault" ? "Set up the vault first." : "Passkey not found.",
        };
      }

      await logAuthEvent({
        eventType: "vault_passkey_unlock_enabled",
        userId: me.id,
        email: me.email,
        ipContext,
        userAgent: request.headers.get("user-agent"),
      });
      return { ok: true as const };
    },
    {
      params: t.Object({ authenticatorId: t.String() }),
      body: t.Object({
        prfSalt: t.String({ maxLength: 64 }),
        wrap: t.String({ maxLength: 128 }),
      }),
    },
  )

  .delete(
    "/passkeys/:authenticatorId",
    async ({ params, me, ipContext, originRejected, request, set }) => {
      if (originRejected) {
        set.status = 403;
        return { error: "Forbidden" };
      }
      if (!me) {
        set.status = 401;
        return { error: "Not authenticated" };
      }
      const removed = /^[A-Za-z0-9_-]{21}$/.test(params.authenticatorId)
        ? await deletePasskeyWrap(me.id, params.authenticatorId)
        : ({ ok: false, reason: "not_found" } as const);
      if (!removed.ok && removed.reason === "last_way_in") {
        set.status = 409;
        return { error: LAST_WAY_IN_MESSAGE, code: "last_way_into_vault" };
      }
      if (!removed.ok) {
        set.status = 404;
        return { error: "Passkey not found." };
      }
      await logAuthEvent({
        eventType: "vault_passkey_unlock_disabled",
        userId: me.id,
        email: me.email,
        ipContext,
        userAgent: request.headers.get("user-agent"),
      });
      return { ok: true as const };
    },
    { params: t.Object({ authenticatorId: t.String() }) },
  )

  .post(
    "/password",
    async ({ body, me, ipContext, originRejected, request, set }) => {
      if (originRejected) {
        set.status = 403;
        return { error: "Forbidden" };
      }
      if (!me) {
        set.status = 401;
        return { error: "Not authenticated" };
      }

      const limit = await checkRateLimit(me.id, rateLimiters.vaultPasswordChange);
      if (!limit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(limit.resetIn);
        return { error: "Rate limit exceeded. Try again later." };
      }

      if (!validateKdfVersion(body.kdfVersion)) {
        set.status = 400;
        return { error: "Unsupported kdfVersion." };
      }

      const saltPassword = decodeFixedLength(body.saltPassword, SALT_BYTES);
      const wrapPassword = decodeFixedLength(body.wrapPassword, WRAP_BYTES);
      if (!saltPassword || !wrapPassword) {
        set.status = 400;
        return { error: "Malformed vault payload." };
      }

      const updated = await updateVaultPasswordWrap(
        me.id,
        saltPassword,
        wrapPassword,
        body.kdfVersion,
      );
      if (!updated) {
        // No vault row to update — caller must run /setup first.
        set.status = 409;
        return { error: "Vault is not set up." };
      }

      await logAuthEvent({
        eventType: "vault_password_changed",
        userId: me.id,
        email: me.email,
        ipContext,
        userAgent: request.headers.get("user-agent"),
      });

      return { ok: true as const };
    },
    {
      body: t.Object({
        kdfVersion: t.Integer({ minimum: 1, maximum: 1000 }),
        saltPassword: t.String({ maxLength: 64 }),
        wrapPassword: t.String({ maxLength: 128 }),
      }),
    },
  )

  .post(
    "/phrase",
    async ({ body, me, ipContext, originRejected, request, set }) => {
      if (originRejected) {
        set.status = 403;
        return { error: "Forbidden" };
      }
      if (!me) {
        set.status = 401;
        return { error: "Not authenticated" };
      }

      const limit = await checkRateLimit(me.id, rateLimiters.vaultPhraseRegenerate);
      if (!limit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(limit.resetIn);
        return { error: "Rate limit exceeded. Try again later." };
      }

      if (!validateKdfVersion(body.kdfVersion)) {
        set.status = 400;
        return { error: "Unsupported kdfVersion." };
      }

      const saltPhrase = decodeFixedLength(body.saltPhrase, SALT_BYTES);
      const wrapPhrase = decodeFixedLength(body.wrapPhrase, WRAP_BYTES);
      if (!saltPhrase || !wrapPhrase) {
        set.status = 400;
        return { error: "Malformed vault payload." };
      }

      const updated = await updateVaultPhraseWrap(
        me.id,
        saltPhrase,
        wrapPhrase,
        body.kdfVersion,
      );
      if (!updated) {
        set.status = 409;
        return { error: "Vault is not set up." };
      }

      await logAuthEvent({
        eventType: "vault_phrase_regenerated",
        userId: me.id,
        email: me.email,
        ipContext,
        userAgent: request.headers.get("user-agent"),
      });

      return { ok: true as const };
    },
    {
      body: t.Object({
        kdfVersion: t.Integer({ minimum: 1, maximum: 1000 }),
        saltPhrase: t.String({ maxLength: 64 }),
        wrapPhrase: t.String({ maxLength: 128 }),
      }),
    },
  );
