// Auth-event audit log writer. 30-day retention enforced by a
// separate purge job.
//
// No raw IP is persisted. Each event row stores country + ASN + an
// HMAC correlator keyed under the active `auth_events` salt (24h
// rotation, 30d retention). When the salt is purged, the correlator
// becomes permanently un-correlatable.

import { db } from "../db";
import { authEvents } from "../db/schema";
import { getActiveSalt } from "../services/saltService";
import type { IpContext } from "../utils/ipContext";

export type AuthEventType =
  | "magic_link_requested"
  | "magic_link_consumed"
  | "login_success"
  | "logout"
  | "logout_all"
  | "session_revoked_admin"
  | "session_anomaly"
  | "transfer_deleted"
  | "account_deleted"
  | "account_exported"
  | "passkey_registered"
  | "passkey_login_success"
  | "passkey_deleted"
  | "vault_setup_completed"
  | "vault_keypair_created"
  | "portal_created"
  | "portal_deleted"
  | "vault_password_changed"
  | "vault_phrase_regenerated";

interface LogAuthEventInput {
  eventType: AuthEventType;
  userId?: string | null;
  email?: string | null;
  ipContext: IpContext;
  userAgent?: string | null;
}

export async function logAuthEvent(input: LogAuthEventInput): Promise<void> {
  try {
    const salt = await getActiveSalt("auth_events");
    const correlator = input.ipContext.hmac(salt.secret);

    await db.insert(authEvents).values({
      eventType: input.eventType,
      userId: input.userId ?? null,
      email: input.email ?? null,
      country: normaliseCountry(input.ipContext.country),
      asn: input.ipContext.asn,
      ipCorrelator: correlator,
      saltId: salt.id,
      userAgent: input.userAgent ?? null,
    });
  } catch (err) {
    // Never let audit-log writes break the auth flow itself. Surface to logs.
    console.error(`[auth-events] failed to log ${input.eventType}:`, err);
  }
}

function normaliseCountry(country: string): string | null {
  if (!country || country === "unknown") return null;
  return country.toUpperCase().slice(0, 2);
}
