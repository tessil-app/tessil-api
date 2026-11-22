import { Elysia, redirect, t } from "elysia";
import { revokeAllDevicesForUser } from "../services/device.service";
import { env } from "../config/env";
import { authPlugin } from "../auth/middleware";
import { ipContextPlugin } from "../auth/ipContextPlugin";
import { logAuthEvent } from "../auth/events";
import {
  issueMagicLink,
  claimMagicLinkOrIssueCode,
  consumeMagicLinkByCode,
  MAGIC_LINK_TTL_MS,
} from "../auth/magicLinks";
import {
  createSession,
  revokeAllSessionsForUser,
  revokeSession,
  SESSION_ABSOLUTE_MS,
  SESSION_COOKIE_NAME,
  SESSION_COOKIE_OPTIONS,
} from "../auth/sessions";
import { findOrCreateUserByEmail } from "../auth/users";
import { canonicaliseCode, isLikelyEmail, normaliseEmail } from "../auth/tokens";
import { sendMagicLink } from "../services/email.service";
import { checkIpRateLimit, checkRateLimit, rateLimiters } from "../services/ratelimit.service";

// Cross-device pending-login cookie. Holds the opaque pending_session_id that
// /verify-code uses to look up the magic-link row. `__Host-` prefix mandates
// Secure + Path=/ + no Domain (RFC 6265bis §4.1.3.2). Audit doc 21 §3.
const PENDING_LOGIN_COOKIE_NAME = "__Host-pending-login";
const PENDING_LOGIN_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: true,
  sameSite: "lax" as const,
  path: "/",
} as const;
const PENDING_LOGIN_MAX_AGE_S = Math.floor(MAGIC_LINK_TTL_MS / 1000);

const VERIFY_CODE_TIMING_FLOOR_MS = 250;

const ENUMERATION_RESPONSE = {
  ok: true as const,
  message: "If that email is registered, we sent a sign-in link.",
};

// Minimum constant-time floor for the request endpoint — closes the
// timing side-channel on the existing-vs-non-existing-email path.
const REQUEST_TIMING_FLOOR_MS = 250;

async function constantTimeRespond<T>(start: number, response: T): Promise<T> {
  const elapsed = Date.now() - start;
  const wait = REQUEST_TIMING_FLOOR_MS - elapsed;
  if (wait > 0) {
    await new Promise((resolve) => setTimeout(resolve, wait));
  }
  return response;
}

// Generic uniform failure for the code path. Hides hit/miss timing
// and avoids branching user-visible behaviour on the specific
// failure mode (missing cookie, wrong code, burned row, expired
// row, etc.).
async function constantTimeVerifyCodeFailure(
  start: number,
): Promise<{ error: string }> {
  const elapsed = Date.now() - start;
  const wait = VERIFY_CODE_TIMING_FLOOR_MS - elapsed;
  if (wait > 0) {
    await new Promise((resolve) => setTimeout(resolve, wait));
  }
  return { error: "That code didn't match. Request a new sign-in link if it stopped working." };
}

export const authRoutes = new Elysia({ prefix: "/api/auth" })
  .use(authPlugin)
  .use(ipContextPlugin)

  // Request a magic-link email. Always returns the same shape
  // regardless of whether the email exists. Silent auto-create: a
  // new account is created for unknown emails on verify. Also emits
  // a 6-digit code for the cross-device path and binds it to a
  // pending-login cookie set on the response.
  .post(
    "/request-magic-link",
    async ({ body, request, cookie, ipContext, set }) => {
      const start = Date.now();
      const userAgent = request.headers.get("user-agent");

      // Per-IP throttle (cheap to evaluate before email shape check).
      const ipLimit = await checkIpRateLimit(ipContext, rateLimiters.authRequestPerIp);
      if (!ipLimit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(ipLimit.resetIn);
        return constantTimeRespond(start, { error: "Too many requests. Try again later." });
      }

      const rawEmail = typeof body.email === "string" ? body.email : "";
      const email = normaliseEmail(rawEmail);

      if (!isLikelyEmail(email)) {
        // Don't leak shape info — same response, just shorter path. The
        // constant-time floor still kicks in.
        return constantTimeRespond(start, ENUMERATION_RESPONSE);
      }

      // Per-email throttle.
      const emailLimit = await checkRateLimit(email, rateLimiters.authRequestPerEmail);
      if (!emailLimit.allowed) {
        // Still uniform response — don't tell the requester they hit the
        // per-email cap, only the per-IP cap is surfaced as 429.
        return constantTimeRespond(start, ENUMERATION_RESPONSE);
      }

      try {
        // Silent auto-create. The account exists either way after this call.
        await findOrCreateUserByEmail(email);

        const { token, pendingSessionId, expiresAt } = await issueMagicLink({
          email,
          userAgent,
        });
        // Token rides in the fragment, not the query string, so it is never
        // sent to the server (or the CDN edge) by the click itself. The SPA
        // reads it and POSTs to /api/auth/verify. This also stops link-scanning
        // bots from consuming the token by prefetching the URL.
        const link = `${env.APP_URL}/signin/verify#token=${encodeURIComponent(token)}`;

        await sendMagicLink({ to: email, link, expiresAt, ipContext, userAgent });

        // Bind the code path to this device via a host-only pending
        // cookie. Without this cookie the 6-digit code is useless —
        // restores the effective entropy.
        cookie[PENDING_LOGIN_COOKIE_NAME].set({
          value: pendingSessionId,
          ...PENDING_LOGIN_COOKIE_OPTIONS,
          maxAge: PENDING_LOGIN_MAX_AGE_S,
          expires: expiresAt,
        });

        await logAuthEvent({
          eventType: "magic_link_requested",
          email,
          ipContext,
          userAgent,
        });
      } catch (err) {
        // Internal failure (DB, email vendor) — do not leak to caller. Log,
        // and still return the uniform response so timing/shape stay constant.
        console.error("[auth/request-magic-link] internal error:", err);
      }

      return constantTimeRespond(start, ENUMERATION_RESPONSE);
    },
    {
      body: t.Object({
        email: t.String({ maxLength: 320 }),
      }),
    },
  )

  // Cross-device sign-in via a 6-digit code typed on the originating
  // device. Code is bound to the pending-login cookie set by
  // /request-magic-link; code alone (or cookie alone) is
  // insufficient. The per-row attempt counter burns the row after
  // CODE_MAX_ATTEMPTS wrong tries.
  .post(
    "/verify-code",
    async ({ body, cookie, ipContext, originRejected, request, set }) => {
      if (originRejected) {
        set.status = 403;
        return { error: "Forbidden" };
      }
      const start = Date.now();

      const userAgent = request.headers.get("user-agent");

      // Existing IP-keyed verify limiter applies to the code path too —
      // defence in depth alongside the per-row attempt counter.
      const verifyLimit = await checkIpRateLimit(ipContext, rateLimiters.authVerifyPerIp);
      if (!verifyLimit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(verifyLimit.resetIn);
        return { error: "Too many verification attempts. Try again later." };
      }

      const pendingSessionId = cookie[PENDING_LOGIN_COOKIE_NAME]?.value;
      const candidate = canonicaliseCode(typeof body.code === "string" ? body.code : "");

      // Missing cookie or malformed code: same generic-failure path as a
      // wrong code. Don't distinguish — the user cannot recover this
      // particular code anyway and we don't want to leak which factor
      // failed.
      if (!pendingSessionId || typeof pendingSessionId !== "string" || !candidate) {
        set.status = 401;
        return constantTimeVerifyCodeFailure(start);
      }

      const result = await consumeMagicLinkByCode(candidate, pendingSessionId);

      if (!result.ok) {
        if (result.reason === "burned") {
          // Tip-over case: clear the pending cookie so the UI can move on.
          cookie[PENDING_LOGIN_COOKIE_NAME].remove();
        }
        set.status = 401;
        return constantTimeVerifyCodeFailure(start);
      }

      const user = await findOrCreateUserByEmail(result.row.email);
      const { session, token: sessionToken } = await createSession({
        userId: user.id,
        ipContext,
        userAgent,
      });

      cookie[SESSION_COOKIE_NAME].set({
        value: sessionToken,
        ...SESSION_COOKIE_OPTIONS,
        maxAge: Math.floor(SESSION_ABSOLUTE_MS / 1000),
        expires: session.absoluteExpiresAt,
      });
      cookie[PENDING_LOGIN_COOKIE_NAME].remove();

      await logAuthEvent({
        eventType: "magic_link_consumed",
        userId: user.id,
        email: user.email,
        ipContext,
        userAgent,
      });
      await logAuthEvent({
        eventType: "login_success",
        userId: user.id,
        email: user.email,
        ipContext,
        userAgent,
      });

      return constantTimeRespond(start, { ok: true as const });
    },
    {
      body: t.Object({
        code: t.String({ maxLength: 16 }),
      }),
    },
  )

  // Verify a magic-link token with same-device vs cross-device
  // detection:
  //  - Same device as the requester (matching pending-login cookie): sign in
  //    here, set __Host-session, redirect to /dashboard.
  //  - Different device: don't sign in here. Mint a 6-digit code, store its
  //    hash, redirect to /signin/code with the plaintext code in the URL
  //    *fragment* (never sent to the server, never logged). The user types
  //    the code back on the originating device via /verify-code.
  .get(
    "/verify",
    async ({ query, request, cookie, ipContext, set }) => {
      const userAgent = request.headers.get("user-agent");

      const verifyLimit = await checkIpRateLimit(ipContext, rateLimiters.authVerifyPerIp);
      if (!verifyLimit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(verifyLimit.resetIn);
        return { error: "Too many verification attempts. Try again later." };
      }

      const token = typeof query.token === "string" ? query.token : "";
      const pendingCookieValue = cookie[PENDING_LOGIN_COOKIE_NAME]?.value;
      const requestingPendingSessionId =
        typeof pendingCookieValue === "string" && pendingCookieValue.length > 0
          ? pendingCookieValue
          : null;

      const result = await claimMagicLinkOrIssueCode(token, requestingPendingSessionId);

      if (!result.ok) {
        // Redirect to login with a generic error reason. Don't leak the
        // specific failure mode (consumed/expired/not_found/code_already_issued
        // are equivalent from the user's perspective).
        return redirect(`${env.APP_URL}/login?error=link-invalid`, 302);
      }

      if (result.action === "code_issued") {
        // Cross-device: surface the code to the user on this device so they
        // can type it back on the originating device. Plaintext goes via the
        // URL fragment so it never reaches the server or proxy logs.
        const expSeconds = Math.max(0, Math.floor((result.expiresAt.getTime() - Date.now()) / 1000));
        const fragment = `code=${encodeURIComponent(result.code)}&exp=${expSeconds}`;
        return redirect(`${env.APP_URL}/signin/code#${fragment}`, 302);
      }

      // Same device: standard sign-in path.
      const user = await findOrCreateUserByEmail(result.row.email);

      const { session, token: sessionToken } = await createSession({
        userId: user.id,
        ipContext,
        userAgent,
      });

      cookie[SESSION_COOKIE_NAME].set({
        value: sessionToken,
        ...SESSION_COOKIE_OPTIONS,
        maxAge: Math.floor(SESSION_ABSOLUTE_MS / 1000),
        expires: session.absoluteExpiresAt,
      });
      cookie[PENDING_LOGIN_COOKIE_NAME].remove();

      await logAuthEvent({
        eventType: "magic_link_consumed",
        userId: user.id,
        email: user.email,
        ipContext,
        userAgent,
      });
      await logAuthEvent({
        eventType: "login_success",
        userId: user.id,
        email: user.email,
        ipContext,
        userAgent,
      });

      return redirect(`${env.APP_URL}/dashboard`, 302);
    },
    {
      query: t.Object({
        token: t.String({ maxLength: 256 }),
      }),
    },
  )

  // Same as GET /verify, but the token arrives in the body from the SPA after
  // it reads the link fragment. Preferred path: the token never touches a URL
  // the server or CDN sees, and prefetching bots cannot consume it.
  .post(
    "/verify",
    async ({ body, request, cookie, ipContext, originRejected, set }) => {
      if (originRejected) {
        set.status = 403;
        return { error: "Forbidden" };
      }

      const userAgent = request.headers.get("user-agent");

      const verifyLimit = await checkIpRateLimit(ipContext, rateLimiters.authVerifyPerIp);
      if (!verifyLimit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(verifyLimit.resetIn);
        return { error: "Too many verification attempts. Try again later." };
      }

      const pendingCookieValue = cookie[PENDING_LOGIN_COOKIE_NAME]?.value;
      const requestingPendingSessionId =
        typeof pendingCookieValue === "string" && pendingCookieValue.length > 0
          ? pendingCookieValue
          : null;

      const result = await claimMagicLinkOrIssueCode(body.token, requestingPendingSessionId);

      if (!result.ok) {
        // Generic, like the GET path: consumed/expired/not_found are all
        // equivalent to the user and the difference must not leak.
        set.status = 400;
        return { error: "link-invalid" };
      }

      if (result.action === "code_issued") {
        const expiresIn = Math.max(
          0,
          Math.floor((result.expiresAt.getTime() - Date.now()) / 1000),
        );
        return { action: "code_issued" as const, code: result.code, expiresIn };
      }

      const user = await findOrCreateUserByEmail(result.row.email);

      const { session, token: sessionToken } = await createSession({
        userId: user.id,
        ipContext,
        userAgent,
      });

      cookie[SESSION_COOKIE_NAME].set({
        value: sessionToken,
        ...SESSION_COOKIE_OPTIONS,
        maxAge: Math.floor(SESSION_ABSOLUTE_MS / 1000),
        expires: session.absoluteExpiresAt,
      });
      cookie[PENDING_LOGIN_COOKIE_NAME].remove();

      await logAuthEvent({
        eventType: "magic_link_consumed",
        userId: user.id,
        email: user.email,
        ipContext,
        userAgent,
      });
      await logAuthEvent({
        eventType: "login_success",
        userId: user.id,
        email: user.email,
        ipContext,
        userAgent,
      });

      return { action: "signed_in" as const };
    },
    {
      body: t.Object({
        token: t.String({ maxLength: 256 }),
      }),
    },
  )

  // Current user.
  .get("/me", ({ me, currentAuthenticatorId }) => {
    if (!me) return { user: null };
    return {
      user: {
        id: me.id,
        email: me.email,
        tier: me.tier,
        createdAt: me.createdAt,
        // The language chosen for this account, or null when none was.
        locale: me.locale ?? null,
        // The authenticator that minted this session, or null for magic-link
        // / verify-code sessions and any pre-migration rows. Drives the
        // "Used to sign in here" hint on /dashboard/settings.
        currentAuthenticatorId: currentAuthenticatorId ?? null,
        // Non-null once the user has completed vault setup. Drives
        // the dashboard's "set up vault" prompt and the route guard
        // that bounces signed-in users without a vault to /setup/vault.
        vaultSetupCompletedAt: me.vaultSetupCompletedAt
          ? me.vaultSetupCompletedAt.toISOString()
          : null,
      },
    };
  })

  // Logout — revokes the current session.
  .post("/logout", async ({ me, sessionId, ipContext, originRejected, cookie, request, set }) => {
    if (originRejected) {
      set.status = 403;
      return { error: "Forbidden" };
    }
    if (sessionId) {
      await revokeSession(sessionId);
    }
    if (me) {
      await logAuthEvent({
        eventType: "logout",
        userId: me.id,
        email: me.email,
        ipContext,
        userAgent: request.headers.get("user-agent"),
      });
    }
    cookie[SESSION_COOKIE_NAME].remove();
    return { ok: true };
  })

  // Logout from all devices.
  .post(
    "/logout-all",
    async ({ me, ipContext, originRejected, cookie, request, set }) => {
      if (originRejected) {
        set.status = 403;
        return { error: "Forbidden" };
      }
      if (!me) {
        set.status = 401;
        return { error: "Not authenticated" };
      }
      const count = await revokeAllSessionsForUser(me.id);
      // Access keys outlive sessions, so "everywhere" has to include them.
      const devicesRevoked = await revokeAllDevicesForUser(me.id);
      await logAuthEvent({
        eventType: "logout_all",
        userId: me.id,
        email: me.email,
        ipContext,
        userAgent: request.headers.get("user-agent"),
      });
      cookie[SESSION_COOKIE_NAME].remove();
      return { ok: true, sessionsRevoked: count, devicesRevoked };
    },
  );

// Surface constants for frontend session-cookie maxAge sanity (Phase A.5).
export { MAGIC_LINK_TTL_MS, SESSION_ABSOLUTE_MS };
