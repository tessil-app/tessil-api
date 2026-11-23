// Session-anomaly detection + notification.
//
// On every authenticated request we recompute the request's ip_hmac under
// the session's per-session correlation_secret and compare to the value
// stored at session-create time. If both the ip_hmac and one of country
// or ASN have changed, we log a `session_anomaly` auth event and — when
// `ENABLE_SESSION_ANOMALY_EMAIL` is on — send the account a heads-up
// email so the user can self-revoke from /dashboard/settings.
//
// No auto-revoke: too noisy for legitimate travel / network switching.
//
// In-process dedup: a single session that bounces between two networks
// would otherwise spam both the audit log and the user's inbox. We
// remember the most recently logged anomaly per session for a short TTL.
// The same dedup key gates the email send.

import { timingSafeEqual } from "node:crypto";
import { env } from "../config/env";
import type { Session } from "../db/schema";
import { logAuthEvent } from "./events";
import { mailLocale, sendSessionAnomalyNotification } from "../services/email.service";
import { findUserById } from "./users";
import type { IpContext } from "../utils/ipContext";

const DEDUP_TTL_MS = 60 * 60 * 1000; // 1 hour — bounds duplicate writes.
const dedupCache = new Map<string, number>();

function shouldLog(sessionId: string, country: string | null, asn: number | null): boolean {
  const key = `${sessionId}:${country ?? "-"}:${asn ?? "-"}`;
  const last = dedupCache.get(key);
  const now = Date.now();
  if (last !== undefined && now - last < DEDUP_TTL_MS) {
    return false;
  }
  dedupCache.set(key, now);

  // Cheap eviction: prune entries older than the TTL so the map doesn't
  // grow unbounded across long-running processes.
  if (dedupCache.size > 1024) {
    for (const [k, t] of dedupCache) {
      if (now - t > DEDUP_TTL_MS) dedupCache.delete(k);
    }
  }
  return true;
}

function bytesEqual(a: Uint8Array | null, b: Uint8Array | null): boolean {
  if (!a || !b) return false;
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

interface DetectInput {
  session: Session;
  ipContext: IpContext;
  userId: string;
  email: string;
  userAgent: string | null;
}

/**
 * Compare the request's ip_hmac (computed under the session's own
 * correlation_secret) and country/ASN to what was stored at session
 * create. If both differ, log a `session_anomaly` event. Fire-and-forget
 * — never throws to the caller.
 */
export async function detectAndReportSessionAnomaly(input: DetectInput): Promise<void> {
  if (!env.ENABLE_SESSION_ANOMALY_DETECTION) return;
  const { session, ipContext } = input;

  // Correlation secret is wiped on revoke (sessions.ts). If it's gone for
  // any reason on a still-active session, we cannot recompute the hmac —
  // skip silently. (validateSession already filters out revoked rows.)
  if (!session.correlationSecret || !session.ipHmac) return;

  const currentHmac = ipContext.hmac(session.correlationSecret);
  if (bytesEqual(currentHmac, session.ipHmac)) return;

  const storedCountry = session.country ?? null;
  const storedAsn = session.asn ?? null;
  const currentCountry = ipContext.country === "unknown" ? null : ipContext.country.toUpperCase().slice(0, 2);
  const currentAsn = ipContext.asn;

  const countryChanged = storedCountry !== currentCountry;
  const asnChanged = storedAsn !== currentAsn;

  // Per spec: only flag when both ip_hmac AND (country OR ASN) differ.
  // Same-network re-DHCP shouldn't fire. NAT pool churn shouldn't fire.
  if (!countryChanged && !asnChanged) return;

  if (!shouldLog(session.id, currentCountry, currentAsn)) return;

  await logAuthEvent({
    eventType: "session_anomaly",
    userId: input.userId,
    email: input.email,
    ipContext,
    userAgent: input.userAgent,
  });

  if (!env.ENABLE_SESSION_ANOMALY_EMAIL) return;
  try {
    const locale = mailLocale((await findUserById(input.userId))?.locale);
    await sendSessionAnomalyNotification({
      locale,
      to: input.email,
      previousCountry: storedCountry,
      previousAsnOrg: session.asnOrg,
      previousAsn: storedAsn,
      currentCountry: currentCountry,
      currentAsnOrg: ipContext.asnOrg,
      currentAsn: currentAsn,
      sessionUserAgent: session.userAgent,
      sessionCreatedAt: session.createdAt,
      settingsUrl: `${env.APP_URL.replace(/\/$/, "")}/dashboard/settings`,
    });
  } catch (err) {
    // Fire-and-forget: a TEM failure must never break the request path.
    // The audit-log row is already written above, so the signal isn't lost.
    console.error("[session-anomaly] email send failed:", err);
  }
}

export function __resetSessionAnomalyDedupForTests(): void {
  dedupCache.clear();
}
