// Portal endpoints. See docs/adr/0014-portal-keys-and-vault-items.md.
//
//   POST   /api/portals              (auth, paid) create a portal
//   GET    /api/portals              (auth) portals the user is a member of
//   PATCH  /api/portals/:id          (auth, owner) disable/enable, replace the public bundle
//   DELETE /api/portals/:id          (auth, owner)
//   GET    /api/portals/:id/public   (anyone) what a depositor needs
//
// Every blob here is encrypted in the browser. The server checks sizes
// and ownership and nothing else.

import { Elysia, t } from "elysia";
import { authPlugin } from "../auth/middleware";
import { ipContextPlugin } from "../auth/ipContextPlugin";
import { logAuthEvent } from "../auth/events";
import { findUserById } from "../auth/users";
import { resolveCaps } from "../config/tiers";
import { checkIpRateLimit, checkRateLimit, rateLimiters } from "../services/ratelimit.service";
import {
  PUBLIC_BUNDLE_MAX_BYTES,
  PUBLIC_BUNDLE_MIN_BYTES,
  SEALED_KEYS_MAX_BYTES,
  SEALED_KEYS_MIN_BYTES,
  createPortal,
  deleteOwnedPortal,
  getPortal,
  listPortalsForMember,
  updateOwnedPortal,
} from "../services/portal.service";

const NANOID_PATTERN = /^[A-Za-z0-9_-]{21}$/;

function decodeBounded(input: string, min: number, max: number): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(input)) return null;
  const bytes = new Uint8Array(Buffer.from(input, "base64url"));
  return bytes.length >= min && bytes.length <= max ? bytes : null;
}

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");

const NOT_FOUND = { error: "Portal not found" };

export const portalRoutes = new Elysia({ prefix: "/api/portals" })
  .use(authPlugin)
  .use(ipContextPlugin)

  .post(
    "/",
    async ({ body, me, ipContext, originRejected, request, set }) => {
      if (originRejected) {
        set.status = 403;
        return { error: "Forbidden" };
      }
      if (!me) {
        set.status = 401;
        return { error: "Not authenticated" };
      }

      const limit = await checkRateLimit(me.id, rateLimiters.portalWrite);
      if (!limit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(limit.resetIn);
        return { error: "Rate limit exceeded. Try again later." };
      }

      const caps = resolveCaps(me);
      if (caps.maxPortals === 0) {
        set.status = 402;
        return {
          error: "Portals are part of the paid plans.",
          code: "portals_require_paid_plan",
          upgradeUrl: "/pricing",
        };
      }
      // The portal's keys are sealed to this key; without it nothing could open them.
      if (!me.publicKey) {
        set.status = 409;
        return { error: "Unlock your vault first.", code: "keypair_required" };
      }

      const publicBundle = decodeBounded(body.publicBundle, PUBLIC_BUNDLE_MIN_BYTES, PUBLIC_BUNDLE_MAX_BYTES);
      const sealedKeys = decodeBounded(body.sealedKeys, SEALED_KEYS_MIN_BYTES, SEALED_KEYS_MAX_BYTES);
      if (!publicBundle || !sealedKeys) {
        set.status = 400;
        return { error: "Malformed portal payload." };
      }

      const portal = await createPortal(me.id, caps.maxPortals, { publicBundle, sealedKeys });
      if (!portal) {
        set.status = 409;
        return {
          error: `Your plan includes ${caps.maxPortals} portals.`,
          code: "portal_limit_reached",
          upgradeUrl: "/pricing",
        };
      }

      await logAuthEvent({
        eventType: "portal_created",
        userId: me.id,
        email: me.email,
        ipContext,
        userAgent: request.headers.get("user-agent"),
      });

      set.status = 201;
      return { id: portal.id, createdAt: portal.createdAt.toISOString() };
    },
    {
      body: t.Object({
        publicBundle: t.String({ maxLength: 4096 }),
        sealedKeys: t.String({ maxLength: 2048 }),
      }),
    },
  )

  .get("/", async ({ me, set }) => {
    if (!me) {
      set.status = 401;
      return { error: "Not authenticated" };
    }
    const rows = await listPortalsForMember(me.id);
    return {
      maxPortals: resolveCaps(me).maxPortals,
      portals: rows.map((row) => ({
        id: row.id,
        role: row.role,
        publicBundle: b64(row.publicBundle),
        sealedKeys: b64(row.sealedKeys),
        keyVersion: row.keyVersion,
        isDisabled: row.isDisabled,
        createdAt: row.createdAt.toISOString(),
      })),
    };
  })

  .patch(
    "/:id",
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
        return NOT_FOUND;
      }

      const limit = await checkRateLimit(me.id, rateLimiters.portalWrite);
      if (!limit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(limit.resetIn);
        return { error: "Rate limit exceeded. Try again later." };
      }

      const changes: { isDisabled?: boolean; publicBundle?: Uint8Array } = {};
      if (body.isDisabled !== undefined) changes.isDisabled = body.isDisabled;
      if (body.publicBundle !== undefined) {
        const bundle = decodeBounded(body.publicBundle, PUBLIC_BUNDLE_MIN_BYTES, PUBLIC_BUNDLE_MAX_BYTES);
        if (!bundle) {
          set.status = 400;
          return { error: "Malformed portal payload." };
        }
        changes.publicBundle = bundle;
      }
      if (Object.keys(changes).length === 0) {
        set.status = 400;
        return { error: "Nothing to change." };
      }

      // Not found and not yours look the same, so IDs cannot be probed.
      if (!(await updateOwnedPortal(me.id, params.id, changes))) {
        set.status = 404;
        return NOT_FOUND;
      }
      return { ok: true as const };
    },
    {
      params: t.Object({ id: t.String() }),
      body: t.Object({
        isDisabled: t.Optional(t.Boolean()),
        publicBundle: t.Optional(t.String({ maxLength: 4096 })),
      }),
    },
  )

  .delete(
    "/:id",
    async ({ params, me, ipContext, originRejected, request, set }) => {
      if (originRejected) {
        set.status = 403;
        return { error: "Forbidden" };
      }
      if (!me) {
        set.status = 401;
        return { error: "Not authenticated" };
      }
      if (!NANOID_PATTERN.test(params.id) || !(await deleteOwnedPortal(me.id, params.id))) {
        set.status = 404;
        return NOT_FOUND;
      }

      await logAuthEvent({
        eventType: "portal_deleted",
        userId: me.id,
        email: me.email,
        ipContext,
        userAgent: request.headers.get("user-agent"),
      });

      set.status = 204;
      return null;
    },
    { params: t.Object({ id: t.String() }) },
  )

  // What a depositor's browser needs. The bundle is ciphertext under the
  // link key, so this reveals nothing about the portal to anyone who only
  // has its ID.
  .get(
    "/:id/public",
    async ({ params, ipContext, set }) => {
      if (!NANOID_PATTERN.test(params.id)) {
        set.status = 404;
        return NOT_FOUND;
      }
      const limit = await checkIpRateLimit(ipContext, rateLimiters.portalPublic);
      if (!limit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(limit.resetIn);
        return { error: "Rate limit exceeded. Try again later." };
      }

      const portal = await getPortal(params.id);
      if (!portal) {
        set.status = 404;
        return NOT_FOUND;
      }

      // A portal stops accepting when its owner switches it off or is no
      // longer on a plan that includes portals. It stays visible so the
      // depositor gets an explanation, not a dead link.
      const owner = await findUserById(portal.ownerId);
      const ownerCaps = resolveCaps(owner && !owner.deletedAt ? owner : null);
      const accepting = !portal.isDisabled && ownerCaps.maxPortals > 0;

      return {
        id: portal.id,
        publicBundle: b64(portal.publicBundle),
        keyVersion: portal.keyVersion,
        accepting,
      };
    },
    { params: t.Object({ id: t.String() }) },
  );
