// WebAuthn / passkey endpoints. Passkeys are a login factor only;
// they don't participate in vault key derivation.
//
// Surface:
//   POST   /api/auth/passkey/register/begin      (auth required)
//   POST   /api/auth/passkey/register/finish     (auth required)
//   POST   /api/auth/passkey/login/begin         (public)
//   POST   /api/auth/passkey/login/finish        (public — mints session)
//   GET    /api/auth/passkeys                    (auth required — list)
//   PATCH  /api/auth/passkey/:id                 (auth required — rename)
//   DELETE /api/auth/passkey/:id                 (auth required)
//
// Sessions are minted only on login/finish; register/finish does not
// re-mint anything (the user is already signed in via the existing session).

import { Elysia, t } from "elysia";
import { authPlugin } from "../auth/middleware";
import { ipContextPlugin } from "../auth/ipContextPlugin";
import { logAuthEvent } from "../auth/events";
import { eq } from "drizzle-orm";
import { db } from "../db";
import { users } from "../db/schema";
import {
  createSession,
  SESSION_ABSOLUTE_MS,
  SESSION_COOKIE_NAME,
  SESSION_COOKIE_OPTIONS,
} from "../auth/sessions";
import {
  beginAuthentication,
  beginRegistration,
  deleteAuthenticator,
  finishAuthentication,
  finishRegistration,
  listAuthenticatorsForUser,
  renameAuthenticator,
} from "../auth/webauthn";
import { checkIpRateLimit, rateLimiters } from "../services/ratelimit.service";

const NANOID_PATTERN = /^[A-Za-z0-9_-]{21}$/;

function authenticatorToDto(a: {
  id: string;
  nickname: string | null;
  deviceType: string;
  backedUp: boolean;
  transports: string[];
  createdAt: Date;
  lastUsedAt: Date | null;
  credentialId: Uint8Array;
}) {
  return {
    id: a.id,
    // Public by design; the browser needs it to ask for this passkey.
    credentialId: Buffer.from(a.credentialId).toString("base64url"),
    nickname: a.nickname,
    deviceType: a.deviceType,
    backedUp: a.backedUp,
    transports: a.transports,
    createdAt: a.createdAt.toISOString(),
    lastUsedAt: a.lastUsedAt?.toISOString() ?? null,
  };
}

export const passkeyRoutes = new Elysia({ prefix: "/api/auth" })
  .use(authPlugin)
  .use(ipContextPlugin)

  // ─── Registration ──────────────────────────────────────────────────────

  .post(
    "/passkey/register/begin",
    async ({ me, originRejected, set }) => {
      if (originRejected) {
        set.status = 403;
        return { error: "Forbidden" };
      }
      if (!me) {
        set.status = 401;
        return { error: "Not authenticated" };
      }

      const existing = await listAuthenticatorsForUser(me.id);
      const { options, challengeRowId } = await beginRegistration({
        userId: me.id,
        userEmail: me.email,
        existingCredentialIds: existing.map((a) => a.credentialId),
      });

      return { options, challengeId: challengeRowId };
    },
  )

  .post(
    "/passkey/register/finish",
    async ({ body, me, ipContext, originRejected, request, set }) => {
      if (originRejected) {
        set.status = 403;
        return { error: "Forbidden" };
      }
      if (!me) {
        set.status = 401;
        return { error: "Not authenticated" };
      }

      const result = await finishRegistration({
        challengeRowId: body.challengeId,
        userId: me.id,
        // The body.response shape mirrors RegistrationResponseJSON from the
        // browser. Trust simplewebauthn to validate fields downstream.
        response: body.response as Parameters<typeof finishRegistration>[0]["response"],
        nickname: body.nickname ?? null,
      });

      if (!result.ok) {
        set.status = result.reason === "challenge_invalid" ? 410 : 400;
        return { error: failureMessage(result.reason) };
      }

      await logAuthEvent({
        eventType: "passkey_registered",
        userId: me.id,
        email: me.email,
        ipContext,
        userAgent: request.headers.get("user-agent"),
      });

      return { authenticator: authenticatorToDto(result.authenticator) };
    },
    {
      body: t.Object({
        challengeId: t.String({ minLength: 21, maxLength: 21 }),
        response: t.Any(),
        nickname: t.Optional(t.Union([t.String({ maxLength: 64 }), t.Null()])),
      }),
    },
  )

  // ─── Authentication ────────────────────────────────────────────────────

  .post(
    "/passkey/login/begin",
    async ({ ipContext, originRejected, set }) => {
      if (originRejected) {
        set.status = 403;
        return { error: "Forbidden" };
      }

      // Reuse the existing verify-side rate limiter — a passkey assertion is
      // the same shape of "claim auth" attempt the magic-link verify is.
      const limit = await checkIpRateLimit(ipContext, rateLimiters.authVerifyPerIp);
      if (!limit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(limit.resetIn);
        return { error: "Too many requests. Try again later." };
      }

      const { options, challengeRowId } = await beginAuthentication();
      return { options, challengeId: challengeRowId };
    },
  )

  .post(
    "/passkey/login/finish",
    async ({ body, ipContext, originRejected, cookie, request, set }) => {
      if (originRejected) {
        set.status = 403;
        return { error: "Forbidden" };
      }

      const limit = await checkIpRateLimit(ipContext, rateLimiters.authVerifyPerIp);
      if (!limit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(limit.resetIn);
        return { error: "Too many requests. Try again later." };
      }

      const userAgent = request.headers.get("user-agent");

      const result = await finishAuthentication({
        challengeRowId: body.challengeId,
        response: body.response as Parameters<typeof finishAuthentication>[0]["response"],
      });

      if (!result.ok) {
        // Distinct statuses for distinct failures, but the user-visible
        // copy is uniform — caller does not branch on the specific reason.
        set.status = result.reason === "challenge_invalid" ? 410 : 401;
        return { error: failureMessage(result.reason) };
      }

      const [user] = await db
        .select()
        .from(users)
        .where(eq(users.id, result.authenticator.userId))
        .limit(1);
      if (!user || user.deletedAt) {
        // Orphaned credential — log and reject. Don't leak account state.
        set.status = 401;
        return { error: failureMessage("verification_failed") };
      }

      const { session, token: sessionToken } = await createSession({
        userId: user.id,
        ipContext,
        userAgent,
        authenticatorId: result.authenticator.id,
      });

      cookie[SESSION_COOKIE_NAME].set({
        value: sessionToken,
        ...SESSION_COOKIE_OPTIONS,
        maxAge: Math.floor(SESSION_ABSOLUTE_MS / 1000),
        expires: session.absoluteExpiresAt,
      });

      await logAuthEvent({
        eventType: "passkey_login_success",
        userId: user.id,
        email: user.email,
        ipContext,
        userAgent,
      });

      return { ok: true as const };
    },
    {
      body: t.Object({
        challengeId: t.String({ minLength: 21, maxLength: 21 }),
        response: t.Any(),
      }),
    },
  )

  // ─── List / rename / delete ────────────────────────────────────────────

  .get("/passkeys", async ({ me, set }) => {
    if (!me) {
      set.status = 401;
      return { error: "Not authenticated" };
    }
    const rows = await listAuthenticatorsForUser(me.id);
    return {
      authenticators: rows
        .slice()
        .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
        .map(authenticatorToDto),
    };
  })

  .patch(
    "/passkey/:id",
    async ({ params, body, me, originRejected, set }) => {
      if (originRejected) {
        set.status = 403;
        return { error: "Forbidden" };
      }
      if (!me) {
        set.status = 401;
        return { error: "Not authenticated" };
      }
      if (!NANOID_PATTERN.test(params.id)) {
        set.status = 404;
        return { error: "Not found" };
      }

      const trimmed = body.nickname?.trim();
      const nickname =
        trimmed && trimmed.length > 0 ? trimmed.slice(0, 64) : null;

      const row = await renameAuthenticator({
        authenticatorId: params.id,
        userId: me.id,
        nickname,
      });
      if (!row) {
        set.status = 404;
        return { error: "Not found" };
      }
      return { authenticator: authenticatorToDto(row) };
    },
    {
      body: t.Object({
        nickname: t.Optional(t.Union([t.String({ maxLength: 64 }), t.Null()])),
      }),
      params: t.Object({ id: t.String({ minLength: 21, maxLength: 21 }) }),
    },
  )

  .delete(
    "/passkey/:id",
    async ({ params, me, ipContext, originRejected, request, set }) => {
      if (originRejected) {
        set.status = 403;
        return { error: "Forbidden" };
      }
      if (!me) {
        set.status = 401;
        return { error: "Not authenticated" };
      }
      if (!NANOID_PATTERN.test(params.id)) {
        set.status = 404;
        return { error: "Not found" };
      }

      const removed = await deleteAuthenticator({
        authenticatorId: params.id,
        userId: me.id,
      });
      if (!removed) {
        set.status = 404;
        return { error: "Not found" };
      }

      await logAuthEvent({
        eventType: "passkey_deleted",
        userId: me.id,
        email: me.email,
        ipContext,
        userAgent: request.headers.get("user-agent"),
      });

      return { ok: true as const };
    },
    {
      params: t.Object({ id: t.String({ minLength: 21, maxLength: 21 }) }),
    },
  );

function failureMessage(
  reason:
    | "challenge_invalid"
    | "verification_failed"
    | "duplicate"
    | "credential_unknown"
    | "counter_replay",
): string {
  switch (reason) {
    case "challenge_invalid":
      return "Sign-in challenge expired. Try again.";
    case "duplicate":
      return "That sign-in key is already registered.";
    default:
      // Uniform copy for the rest — don't leak which failure mode hit.
      return "Couldn't verify your sign-in key. Try again.";
  }
}
