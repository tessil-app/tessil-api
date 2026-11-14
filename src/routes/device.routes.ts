// Access keys: a program registers itself, a signed-in person approves it,
// and from then on it may act for that account within what it was given.
// See docs/adr/0015-access-keys-cli-and-mcp.md.

import { Elysia, t } from "elysia";
import { authPlugin } from "../auth/middleware";
import { ipContextPlugin } from "../auth/ipContextPlugin";
import { logAuthEvent } from "../auth/events";
import { denialResponse, resolveDevice } from "../auth/deviceAuth";
import { resolveCaps } from "../config/tiers";
import type { Device } from "../db/schema";
import {
  DEVICE_PUBLIC_KEY_BYTES,
  TRANSFER_PERMISSIONS,
  approveDevice,
  canonicalisePairingCode,
  cleanPermissions,
  countActiveDevices,
  findPendingByCode,
  isActive,
  listDevices,
  registerPendingDevice,
  revokeOwnedDevice,
  updateOwnedDevice,
  type DevicePermission,
} from "../services/device.service";
import { listTransfersForUser, softDeleteDeviceTransfer } from "../services/file.service";
import { checkIpRateLimit, checkRateLimit, rateLimiters } from "../services/ratelimit.service";

const NANOID_PATTERN = /^[A-Za-z0-9_-]{21}$/;
const TOKEN_HASH_PATTERN = /^[0-9a-f]{64}$/;
const NOT_FOUND = { error: "Access key not found" };
const PAGE_SIZE = 50;

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");

function decodePublicKey(input: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(input)) return null;
  const bytes = new Uint8Array(Buffer.from(input, "base64url"));
  // An uncompressed point starts with 0x04.
  return bytes.length === DEVICE_PUBLIC_KEY_BYTES && bytes[0] === 0x04 ? bytes : null;
}

function cleanName(input: string): string | null {
  const name = input.replace(/[\u0000-\u001f\u007f]/g, "").trim();
  return name.length > 0 && name.length <= 80 ? name : null;
}

/** What an account may hand out: without portals, only the transfer ones. */
function allowedFor(maxPortals: number, wanted: DevicePermission[]): DevicePermission[] {
  return maxPortals > 0 ? wanted : wanted.filter((p) => TRANSFER_PERMISSIONS.includes(p));
}

function view(device: Device) {
  return {
    id: device.id,
    name: device.name,
    publicKey: b64(device.publicKey),
    permissions: device.permissions,
    approvedAt: device.approvedAt?.toISOString() ?? null,
    expiresAt: device.expiresAt?.toISOString() ?? null,
    lastUsedAt: device.lastUsedAt?.toISOString() ?? null,
    revokedAt: device.revokedAt?.toISOString() ?? null,
    createdAt: device.createdAt.toISOString(),
    active: isActive(device),
  };
}

export const deviceRoutes = new Elysia({ prefix: "/api/devices" })
  .use(authPlugin)
  .use(ipContextPlugin)

  // ─── the program's side ───────────────────────────────────────────────────

  // Announce a new key. Needs no account: the row is nobody's until a
  // signed-in person approves it with the code returned here.
  .post(
    "/",
    async ({ body, ipContext, request, set }) => {
      // A page has no business making access keys.
      if (request.headers.get("origin")) {
        set.status = 403;
        return { error: "Forbidden" };
      }
      const limit = await checkIpRateLimit(ipContext, rateLimiters.deviceRegister);
      if (!limit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(limit.resetIn);
        return { error: "Too many new access keys from here. Try again later." };
      }
      const name = cleanName(body.name);
      const publicKey = decodePublicKey(body.publicKey);
      if (!name || !publicKey || !TOKEN_HASH_PATTERN.test(body.tokenHash)) {
        set.status = 400;
        return { error: "Malformed access key." };
      }
      const made = await registerPendingDevice({ name, publicKey, tokenHash: body.tokenHash });
      if (!made) {
        set.status = 409;
        return { error: "That access key already exists." };
      }
      set.status = 201;
      return {
        id: made.id,
        pairingCode: `${made.pairingCode.slice(0, 4)}-${made.pairingCode.slice(4)}`,
        pairingExpiresAt: made.pairingExpiresAt.toISOString(),
      };
    },
    {
      body: t.Object({
        name: t.String({ maxLength: 200 }),
        publicKey: t.String({ maxLength: 128 }),
        tokenHash: t.String({ maxLength: 64 }),
      }),
    },
  )

  // What a key is and may do, asked by the key itself. Also how a program
  // waits for approval: a pending key gets "pending", not an error.
  .get("/self", async ({ request, set }) => {
    const resolved = await resolveDevice(request);
    if (resolved.pending) {
      return { status: "pending" as const, pairingExpiresAt: resolved.pending.pairingExpiresAt?.toISOString() ?? null };
    }
    if (!resolved.device) {
      const { status, body } = denialResponse(resolved.denied ?? "invalid");
      set.status = status;
      return body;
    }
    const { device, user } = resolved.device;
    const caps = resolveCaps(user);
    return {
      status: "active" as const,
      device: view(device),
      account: {
        email: user.email,
        tier: user.tier,
        // The key the account's portal grants are signed with; pinned by the program.
        publicKey: user.publicKey ? b64(user.publicKey) : null,
      },
      caps: {
        maxFileSize: caps.maxFileSize,
        maxTransferSize: caps.maxTransferSize,
        allowedExpiryHours: caps.allowedExpiryHours,
      },
    };
  })

  // A key signs itself out.
  .delete("/self", async ({ request, set }) => {
    const resolved = await resolveDevice(request);
    if (!resolved.device) {
      const { status, body } = denialResponse(resolved.denied ?? "invalid");
      set.status = status;
      return body;
    }
    await revokeOwnedDevice(resolved.device.user.id, resolved.device.device.id);
    set.status = 204;
    return null;
  })

  // What this key sent, and nothing else of the account's.
  .get(
    "/self/transfers",
    async ({ request, query, set }) => {
      const resolved = await resolveDevice(request);
      if (!resolved.device) {
        const { status, body } = denialResponse(resolved.denied ?? "invalid");
        set.status = status;
        return body;
      }
      const { device, user } = resolved.device;
      if (!device.permissions.includes("transfers:read")) {
        set.status = 403;
        return { error: "This access key is not allowed to do that.", code: "device_forbidden", permission: "transfers:read" };
      }
      let cursor: Date | null = null;
      if (query.cursor) {
        const parsed = new Date(query.cursor);
        if (Number.isNaN(parsed.getTime())) {
          set.status = 400;
          return { error: "Invalid cursor" };
        }
        cursor = parsed;
      }
      const rows = await listTransfersForUser(user.id, cursor, PAGE_SIZE, device.id);
      return {
        transfers: rows,
        nextCursor: rows.length === PAGE_SIZE ? rows[rows.length - 1].createdAt.toISOString() : null,
      };
    },
    { query: t.Object({ cursor: t.Optional(t.String({ maxLength: 64 })) }) },
  )

  .delete(
    "/self/transfers/:id",
    async ({ request, params, set }) => {
      const resolved = await resolveDevice(request);
      if (!resolved.device) {
        const { status, body } = denialResponse(resolved.denied ?? "invalid");
        set.status = status;
        return body;
      }
      const { device } = resolved.device;
      if (!device.permissions.includes("transfers:delete")) {
        set.status = 403;
        return { error: "This access key is not allowed to do that.", code: "device_forbidden", permission: "transfers:delete" };
      }
      if (!NANOID_PATTERN.test(params.id) || !(await softDeleteDeviceTransfer(device.id, params.id))) {
        set.status = 404;
        return { error: "Not found" };
      }
      set.status = 204;
      return null;
    },
    { params: t.Object({ id: t.String() }) },
  )

  // ─── the person's side: session only ──────────────────────────────────────

  .get("/", async ({ me, set }) => {
    if (!me) {
      set.status = 401;
      return { error: "Not authenticated" };
    }
    const caps = resolveCaps(me);
    return {
      maxDevices: caps.maxDevices,
      portalsAllowed: caps.maxPortals > 0,
      devices: (await listDevices(me.id)).map(view),
    };
  })

  // Shows who is asking, before approving: the name and the public key,
  // whose fingerprint the person compares with what the program printed.
  .get(
    "/pending/:code",
    async ({ me, params, set }) => {
      if (!me) {
        set.status = 401;
        return { error: "Not authenticated" };
      }
      const limit = await checkRateLimit(me.id, rateLimiters.devicePairingLookup);
      if (!limit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(limit.resetIn);
        return { error: "Too many tries. Wait a while and try again." };
      }
      const code = canonicalisePairingCode(params.code);
      const pending = code ? await findPendingByCode(code) : null;
      if (!pending) {
        set.status = 404;
        return { error: "No access key is waiting under that code. Codes last ten minutes." };
      }
      return { name: pending.name, publicKey: b64(pending.publicKey), createdAt: pending.createdAt.toISOString() };
    },
    { params: t.Object({ code: t.String({ maxLength: 32 }) }) },
  )

  .post(
    "/approve",
    async ({ me, body, ipContext, originRejected, request, set }) => {
      if (originRejected) {
        set.status = 403;
        return { error: "Forbidden" };
      }
      if (!me) {
        set.status = 401;
        return { error: "Not authenticated" };
      }
      const limit = await checkRateLimit(me.id, rateLimiters.devicePairingLookup);
      if (!limit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(limit.resetIn);
        return { error: "Too many tries. Wait a while and try again." };
      }
      const code = canonicalisePairingCode(body.code);
      const name = body.name === undefined ? undefined : cleanName(body.name);
      if (!code || name === null) {
        set.status = 400;
        return { error: "Malformed request." };
      }
      const caps = resolveCaps(me);
      const permissions = allowedFor(caps.maxPortals, cleanPermissions(body.permissions));
      if (permissions.length === 0) {
        set.status = 400;
        return { error: "Choose at least one thing this access key may do.", code: "device_no_permissions" };
      }
      const result = await approveDevice(me.id, code, caps.maxDevices, permissions, name);
      if (!result.ok) {
        if (result.reason === "limit_reached") {
          set.status = 409;
          return {
            error: `Your plan includes ${caps.maxDevices} access ${caps.maxDevices === 1 ? "key" : "keys"}. Revoke one first.`,
            code: "device_limit_reached",
            upgradeUrl: "/pricing",
          };
        }
        set.status = 404;
        return { error: "No access key is waiting under that code. Codes last ten minutes." };
      }
      await logAuthEvent({
        eventType: "device_approved",
        userId: me.id,
        email: me.email,
        ipContext,
        userAgent: request.headers.get("user-agent"),
      });
      set.status = 201;
      return view(result.device);
    },
    {
      body: t.Object({
        code: t.String({ maxLength: 32 }),
        name: t.Optional(t.String({ maxLength: 200 })),
        permissions: t.Array(t.String({ maxLength: 32 }), { maxItems: 16 }),
      }),
    },
  )

  .patch(
    "/:id",
    async ({ me, params, body, ipContext, originRejected, request, set }) => {
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
      const limit = await checkRateLimit(me.id, rateLimiters.deviceWrite);
      if (!limit.allowed) {
        set.status = 429;
        set.headers["Retry-After"] = String(limit.resetIn);
        return { error: "Rate limit exceeded. Try again later." };
      }
      const name = body.name === undefined ? undefined : cleanName(body.name);
      if (name === null) {
        set.status = 400;
        return { error: "Malformed request." };
      }
      const caps = resolveCaps(me);
      let permissions: DevicePermission[] | undefined;
      if (body.permissions !== undefined) {
        permissions = allowedFor(caps.maxPortals, cleanPermissions(body.permissions));
        if (permissions.length === 0) {
          set.status = 400;
          return { error: "Choose at least one thing this access key may do.", code: "device_no_permissions" };
        }
      }
      if (name === undefined && permissions === undefined && !body.renew) {
        set.status = 400;
        return { error: "Nothing to change." };
      }
      // Renewing a lapsed key brings it back among the active ones.
      if (body.renew && (await countActiveDevices(me.id)) >= caps.maxDevices) {
        const mine = (await listDevices(me.id)).find((d) => d.id === params.id);
        if (mine && !isActive(mine)) {
          set.status = 409;
          return {
            error: `Your plan includes ${caps.maxDevices} access ${caps.maxDevices === 1 ? "key" : "keys"}. Revoke one first.`,
            code: "device_limit_reached",
            upgradeUrl: "/pricing",
          };
        }
      }
      const device = await updateOwnedDevice(me.id, params.id, { name, permissions, renew: body.renew });
      if (!device) {
        set.status = 404;
        return NOT_FOUND;
      }
      await logAuthEvent({
        eventType: "device_changed",
        userId: me.id,
        email: me.email,
        ipContext,
        userAgent: request.headers.get("user-agent"),
      });
      return view(device);
    },
    {
      params: t.Object({ id: t.String() }),
      body: t.Object({
        name: t.Optional(t.String({ maxLength: 200 })),
        permissions: t.Optional(t.Array(t.String({ maxLength: 32 }), { maxItems: 16 })),
        renew: t.Optional(t.Boolean()),
      }),
    },
  )

  .delete(
    "/:id",
    async ({ me, params, ipContext, originRejected, request, set }) => {
      if (originRejected) {
        set.status = 403;
        return { error: "Forbidden" };
      }
      if (!me) {
        set.status = 401;
        return { error: "Not authenticated" };
      }
      if (!NANOID_PATTERN.test(params.id) || !(await revokeOwnedDevice(me.id, params.id))) {
        set.status = 404;
        return NOT_FOUND;
      }
      await logAuthEvent({
        eventType: "device_revoked",
        userId: me.id,
        email: me.email,
        ipContext,
        userAgent: request.headers.get("user-agent"),
      });
      set.status = 204;
      return null;
    },
    { params: t.Object({ id: t.String() }) },
  );
