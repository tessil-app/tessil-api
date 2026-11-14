// Access keys on a request. See docs/adr/0015-access-keys-cli-and-mcp.md.
//
// A request that carries `Authorization: Bearer tsl_…` is a device's. It
// never becomes `me` by itself: a route group has to ask for a permission
// with `deviceAccess(...)`. Everything that does not ask stays out of a
// device's reach, which is how account, billing, vault and passkey routes
// are kept away from access keys without listing them anywhere.

import { Elysia } from "elysia";
import { eq } from "drizzle-orm";
import { db } from "../db";
import { users, type Device, type User } from "../db/schema";
import {
  DEVICE_TOKEN_PREFIX,
  findDeviceByToken,
  isActive,
  touchDevice,
  type DevicePermission,
} from "../services/device.service";
import { checkRateLimit, rateLimiters } from "../services/ratelimit.service";

export type DeviceDenial =
  /** No such token, or it is revoked, lapsed or its account is gone. */
  | "invalid"
  /** Registered, waiting for a person to approve it. */
  | "pending"
  /** A browser sent it. Access keys are not for pages. */
  | "browser"
  | "rate_limited";

export interface DeviceContext {
  device: Device;
  user: User;
}

export interface ResolvedDevice {
  /** Set when the request carries a usable access key. */
  device: DeviceContext | null;
  /** Set when it carries an access key that cannot be used. */
  denied: DeviceDenial | null;
  /** The row behind a pending key, for the one route that reports on it. */
  pending: Device | null;
}

const NONE: ResolvedDevice = { device: null, denied: null, pending: null };

export function bearerToken(request: Request): string | null {
  const header = request.headers.get("authorization");
  if (!header) return null;
  const match = /^Bearer\s+(\S+)$/i.exec(header);
  if (!match || !match[1].startsWith(DEVICE_TOKEN_PREFIX)) return null;
  return match[1];
}

export async function resolveDevice(request: Request): Promise<ResolvedDevice> {
  const token = bearerToken(request);
  if (!token) return NONE;
  // A page has an Origin; a program does not. A token in a page is a
  // token that leaked into one.
  if (request.headers.get("origin")) return { ...NONE, denied: "browser" };

  const device = await findDeviceByToken(token);
  if (!device) return { ...NONE, denied: "invalid" };
  if (device.userId === null) {
    const waiting = device.revokedAt === null && device.pairingExpiresAt !== null && device.pairingExpiresAt > new Date();
    return waiting ? { device: null, denied: "pending", pending: device } : { ...NONE, denied: "invalid" };
  }
  if (!isActive(device)) return { ...NONE, denied: "invalid" };

  const limit = await checkRateLimit(device.id, rateLimiters.deviceRequests);
  if (!limit.allowed) return { ...NONE, denied: "rate_limited" };

  const [user] = await db.select().from(users).where(eq(users.id, device.userId)).limit(1);
  if (!user || user.deletedAt) return { ...NONE, denied: "invalid" };

  void touchDevice(device).catch(() => {});
  return { device: { device, user }, denied: null, pending: null };
}

export function denialResponse(denied: DeviceDenial): { status: number; body: { error: string; code: string } } {
  switch (denied) {
    case "pending":
      return { status: 403, body: { error: "This access key is waiting to be approved.", code: "device_pending" } };
    case "browser":
      return { status: 403, body: { error: "Access keys cannot be used from a web page.", code: "device_browser" } };
    case "rate_limited":
      return { status: 429, body: { error: "This access key is doing too much. Try again shortly.", code: "device_rate_limited" } };
    default:
      return { status: 401, body: { error: "This access key is not valid.", code: "device_invalid" } };
  }
}

/**
 * Lets an access key with `permission` act as its account on the routes
 * of the group this is used in. Use it after `authPlugin`.
 *
 * A request with a session cookie is untouched. A request with a usable
 * key gets `me` set to the key's account and `device` set to the key. A
 * request with a key that is unusable, or lacks the permission, is
 * answered here and never reaches the route. It must not fall through as
 * a request from nobody: some routes serve nobody too.
 */
export function deviceAccess(permission: DevicePermission) {
  return new Elysia({ name: `device-access:${permission}` })
    .derive({ as: "scoped" }, async ({ request }) => {
      const resolved = await resolveDevice(request);
      if (!resolved.device) return { device: null as Device | null, deviceDenied: resolved.denied, deviceLacks: false };
      const allowed = resolved.device.device.permissions.includes(permission);
      return allowed
        ? { device: resolved.device.device as Device | null, deviceDenied: null as DeviceDenial | null, deviceLacks: false, me: resolved.device.user as User | null }
        : { device: null as Device | null, deviceDenied: null as DeviceDenial | null, deviceLacks: true };
    })
    .onBeforeHandle({ as: "scoped" }, ({ deviceDenied, deviceLacks, set }) => {
      if (deviceDenied) {
        const { status, body } = denialResponse(deviceDenied);
        set.status = status;
        return body;
      }
      if (deviceLacks) {
        set.status = 403;
        return { error: "This access key is not allowed to do that.", code: "device_forbidden", permission };
      }
    });
}
