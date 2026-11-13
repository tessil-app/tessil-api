// Scaleway Transactional Email integration. Transactional only —
// no marketing, per Scaleway TEM ToS.
//
// In dev when SCW_TEM credentials are not configured, the magic
// link is logged to stdout so flows can be tested without a real
// send.

import { env } from "../config/env";
import type { IpContext } from "../utils/ipContext";

interface SendMagicLinkInput {
  to: string;
  link: string;
  expiresAt: Date;
  /**
   * Derived request context (country / ASN / city). The magic-link
   * email body shows this derived signal rather than the raw IP, so
   * the user can recognise legitimate sign-in attempts without us
   * persisting (or transmitting) the IP itself.
   */
  ipContext: IpContext;
  userAgent: string | null;
}

function formatLocation(ipContext: IpContext): string {
  const parts: string[] = [];
  if (ipContext.city) parts.push(ipContext.city);
  if (ipContext.country && ipContext.country !== "unknown") parts.push(ipContext.country);
  const location = parts.join(", ");
  const asn = ipContext.asn
    ? `AS${ipContext.asn}${ipContext.asnOrg ? ` (${ipContext.asnOrg})` : ""}`
    : null;
  if (location && asn) return `${location} · ${asn}`;
  if (location) return location;
  if (asn) return asn;
  return "unknown";
}

const SCW_TEM_ENDPOINT = (region: string) =>
  `https://api.scaleway.com/transactional-email/v1alpha1/regions/${region}/emails`;

function isConfigured(): boolean {
  return Boolean(env.SCW_TEM_PROJECT_ID && env.SCW_TEM_SECRET_KEY);
}

function buildMagicLinkSubject(): string {
  return "Your Tessil sign-in link";
}

function buildMagicLinkText({ link, expiresAt, ipContext, userAgent }: SendMagicLinkInput): string {
  const expiresIn = Math.max(1, Math.round((expiresAt.getTime() - Date.now()) / 60000));
  return [
    "Sign in to Tessil",
    "",
    "Click the link below to sign in. It expires in " +
      expiresIn +
      " minutes and can only be used once.",
    "",
    link,
    "",
    "If you open this link on a different device than the one you started",
    "signing in on, we'll show you a short code to type back into your",
    "original device — no sign-in happens on the wrong device.",
    "",
    "Request details:",
    `  Location: ${formatLocation(ipContext)}`,
    `  Browser: ${userAgent ?? "unknown"}`,
    "",
    "We show approximate location and network rather than your IP address.",
    "Tessil does not store the IP itself.",
    "",
    "If you didn't request this, ignore this email — no account changes were made.",
    "",
    "— Tessil",
  ].join("\n");
}

function buildMagicLinkHtml(input: SendMagicLinkInput): string {
  const expiresIn = Math.max(1, Math.round((input.expiresAt.getTime() - Date.now()) / 60000));
  // Minimal inline-styled HTML — no tracking pixels, no remote assets.
  return [
    "<!doctype html>",
    '<html lang="en"><head><meta charset="utf-8"><title>Sign in to Tessil</title></head>',
    '<body style="font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;line-height:1.5;color:#111;max-width:560px;margin:24px auto;padding:0 16px;">',
    '  <h1 style="font-size:20px;margin:0 0 16px;">Sign in to Tessil</h1>',
    `  <p>Click the button below to sign in. The link expires in <strong>${expiresIn} minutes</strong> and can only be used once.</p>`,
    `  <p style="margin:24px 0;"><a href="${escapeHtml(input.link)}" style="display:inline-block;padding:12px 20px;background:#111;color:#fff;text-decoration:none;border-radius:8px;">Sign in to Tessil</a></p>`,
    `  <p style="font-size:13px;color:#555;">Or paste this URL into your browser:<br><code style="word-break:break-all;">${escapeHtml(input.link)}</code></p>`,
    '  <p style="font-size:13px;color:#555;">Opening this link on a different device than the one you started signing in on will show you a short code to type back into your original device — no sign-in happens on the wrong device.</p>',
    '  <hr style="border:none;border-top:1px solid #eee;margin:24px 0;">',
    '  <p style="font-size:12px;color:#666;">Request details — Location: ' +
      escapeHtml(formatLocation(input.ipContext)) +
      " &middot; Browser: " +
      escapeHtml(input.userAgent ?? "unknown") +
      "</p>",
    '  <p style="font-size:12px;color:#666;">We show approximate location and network rather than your IP address. Tessil does not store the IP itself.</p>',
    '  <p style="font-size:12px;color:#666;">If you didn\'t request this, ignore this email — no account changes were made.</p>',
    "</body></html>",
  ].join("\n");
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

interface SendAccountDeletedInput {
  to: string;
}

function buildAccountDeletedSubject(): string {
  return "Your Tessil account was deleted";
}

function buildAccountDeletedText({ to }: SendAccountDeletedInput): string {
  return [
    "Your Tessil account and all associated transfers were permanently deleted just now.",
    "",
    "If you did this, no further action is needed. If you did not request this deletion, your account may have been accessed by someone else — we recommend rotating the credentials on the email address used to sign in (" +
      to +
      "), and reviewing other services where you used the same address.",
    "",
    "We don't retain copies. The account and its files cannot be restored.",
    "",
    "— Tessil",
  ].join("\n");
}

function buildAccountDeletedHtml({ to }: SendAccountDeletedInput): string {
  return [
    "<!doctype html>",
    '<html lang="en"><head><meta charset="utf-8"><title>Your Tessil account was deleted</title></head>',
    '<body style="font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;line-height:1.5;color:#111;max-width:560px;margin:24px auto;padding:0 16px;">',
    '  <h1 style="font-size:20px;margin:0 0 16px;">Your Tessil account was deleted</h1>',
    "  <p>Your Tessil account and all associated transfers were permanently deleted just now.</p>",
    "  <p>If you did this, no further action is needed. If you did not request this deletion, your account may have been accessed by someone else — we recommend rotating the credentials on the email address used to sign in (<strong>" +
      escapeHtml(to) +
      "</strong>), and reviewing other services where you used the same address.</p>",
    '  <p style="font-size:13px;color:#555;">We don\'t retain copies. The account and its files cannot be restored.</p>',
    "</body></html>",
  ].join("\n");
}

export async function sendAccountDeletedNotification(input: SendAccountDeletedInput): Promise<void> {
  if (!isConfigured()) {
    console.log(
      `[email] SCW_TEM not configured — logging account-deleted notification instead.\n  to: ${input.to}`,
    );
    return;
  }

  const body = {
    from: { email: env.EMAIL_FROM, name: env.EMAIL_FROM_NAME },
    to: [{ email: input.to }],
    project_id: env.SCW_TEM_PROJECT_ID,
    subject: buildAccountDeletedSubject(),
    text: buildAccountDeletedText(input),
    html: buildAccountDeletedHtml(input),
    ...(env.EMAIL_REPLY_TO
      ? { additional_headers: [{ key: "Reply-To", value: env.EMAIL_REPLY_TO }] }
      : {}),
  };

  const response = await fetch(SCW_TEM_ENDPOINT(env.SCW_TEM_REGION), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Auth-Token": env.SCW_TEM_SECRET_KEY,
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const errorBody = await response.text().catch(() => "<unreadable>");
    console.error(
      `[email] Scaleway TEM account-deleted send failed (${response.status}) for ${input.to}: ${errorBody.slice(0, 500)}`,
    );
    throw new Error(`Email send failed: ${response.status}`);
  }
}

interface SendSessionAnomalyInput {
  to: string;
  /** ISO 3166-1 alpha-2 stored on the session at create. May be null. */
  previousCountry: string | null;
  /** ASN org label stored on the session at create. May be null. */
  previousAsnOrg: string | null;
  /** ASN integer stored on the session at create. May be null. */
  previousAsn: number | null;
  /** ISO 3166-1 alpha-2 from the current request. May be null. */
  currentCountry: string | null;
  /** ASN org label from the current request. May be null. */
  currentAsnOrg: string | null;
  /** ASN integer from the current request. May be null. */
  currentAsn: number | null;
  /** User-agent from the session at create — disambiguates which session. */
  sessionUserAgent: string | null;
  /** When the affected session was created. */
  sessionCreatedAt: Date;
  /** Absolute URL to /dashboard/settings, where the user can sign out everywhere. */
  settingsUrl: string;
}

// Resolves an ISO-2 country code to its English display name via the
// platform's `Intl.DisplayNames`. Falls back to the raw code (or "unknown"
// when both code and name are missing) so the email always has something
// readable.
function countryName(iso2: string | null): string {
  if (!iso2) return "an unknown location";
  try {
    const dn = new Intl.DisplayNames(["en"], { type: "region" });
    return dn.of(iso2.toUpperCase()) ?? iso2;
  } catch {
    return iso2;
  }
}

function formatAnomalyNetwork(
  country: string | null,
  asnOrg: string | null,
  asn: number | null,
): string {
  const place = countryName(country);
  const org = asnOrg ?? (asn ? `AS${asn}` : null);
  return org ? `${place} (${org})` : place;
}

function buildSessionAnomalySubject(): string {
  return "Heads up — your Tessil session is being used from a new network";
}

function buildSessionAnomalyText(input: SendSessionAnomalyInput): string {
  const previous = formatAnomalyNetwork(
    input.previousCountry,
    input.previousAsnOrg,
    input.previousAsn,
  );
  const current = formatAnomalyNetwork(
    input.currentCountry,
    input.currentAsnOrg,
    input.currentAsn,
  );
  const createdAt = input.sessionCreatedAt.toISOString().slice(0, 10);
  return [
    "We noticed a change of network on one of your Tessil sessions.",
    "",
    `Your session previously seen from ${previous} is now being used from ${current}.`,
    "",
    `Affected session: signed in on ${createdAt}` +
      (input.sessionUserAgent ? ` from "${input.sessionUserAgent}"` : ""),
    "",
    "If this wasn't you, sign out everywhere from your dashboard settings:",
    input.settingsUrl,
    "",
    "If this was you (you're travelling, on a VPN, or switched networks),",
    "you can ignore this email. We won't sign you out automatically.",
    "",
    "We show approximate country and network rather than your IP address.",
    "Tessil does not store the IP itself.",
    "",
    "— Tessil",
  ].join("\n");
}

function buildSessionAnomalyHtml(input: SendSessionAnomalyInput): string {
  const previous = formatAnomalyNetwork(
    input.previousCountry,
    input.previousAsnOrg,
    input.previousAsn,
  );
  const current = formatAnomalyNetwork(
    input.currentCountry,
    input.currentAsnOrg,
    input.currentAsn,
  );
  const createdAt = input.sessionCreatedAt.toISOString().slice(0, 10);
  const sessionLine = input.sessionUserAgent
    ? `Affected session: signed in on ${createdAt} from <code>${escapeHtml(input.sessionUserAgent)}</code>`
    : `Affected session: signed in on ${createdAt}`;
  return [
    "<!doctype html>",
    '<html lang="en"><head><meta charset="utf-8"><title>Tessil session change</title></head>',
    '<body style="font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;line-height:1.5;color:#111;max-width:560px;margin:24px auto;padding:0 16px;">',
    '  <h1 style="font-size:20px;margin:0 0 16px;">A Tessil session is on a new network</h1>',
    `  <p>Your session previously seen from <strong>${escapeHtml(previous)}</strong> is now being used from <strong>${escapeHtml(current)}</strong>.</p>`,
    `  <p style="font-size:13px;color:#555;">${sessionLine}</p>`,
    `  <p style="margin:24px 0;"><a href="${escapeHtml(input.settingsUrl)}" style="display:inline-block;padding:12px 20px;background:#111;color:#fff;text-decoration:none;border-radius:8px;">Sign out everywhere</a></p>`,
    '  <p style="font-size:13px;color:#555;">If this was you (you\'re travelling, on a VPN, or switched networks), you can ignore this email. We won\'t sign you out automatically.</p>',
    '  <hr style="border:none;border-top:1px solid #eee;margin:24px 0;">',
    '  <p style="font-size:12px;color:#666;">We show approximate country and network rather than your IP address. Tessil does not store the IP itself.</p>',
    "</body></html>",
  ].join("\n");
}

export async function sendSessionAnomalyNotification(
  input: SendSessionAnomalyInput,
): Promise<void> {
  if (!isConfigured()) {
    console.log(
      `[email] SCW_TEM not configured — logging session-anomaly notification instead.\n  to: ${input.to}\n  previous: ${formatAnomalyNetwork(input.previousCountry, input.previousAsnOrg, input.previousAsn)}\n  current: ${formatAnomalyNetwork(input.currentCountry, input.currentAsnOrg, input.currentAsn)}`,
    );
    return;
  }

  const body = {
    from: { email: env.EMAIL_FROM, name: env.EMAIL_FROM_NAME },
    to: [{ email: input.to }],
    project_id: env.SCW_TEM_PROJECT_ID,
    subject: buildSessionAnomalySubject(),
    text: buildSessionAnomalyText(input),
    html: buildSessionAnomalyHtml(input),
    ...(env.EMAIL_REPLY_TO
      ? { additional_headers: [{ key: "Reply-To", value: env.EMAIL_REPLY_TO }] }
      : {}),
  };

  const response = await fetch(SCW_TEM_ENDPOINT(env.SCW_TEM_REGION), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Auth-Token": env.SCW_TEM_SECRET_KEY,
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const errorBody = await response.text().catch(() => "<unreadable>");
    console.error(
      `[email] Scaleway TEM session-anomaly send failed (${response.status}) for ${input.to}: ${errorBody.slice(0, 500)}`,
    );
    throw new Error(`Email send failed: ${response.status}`);
  }
}

export async function sendMagicLink(input: SendMagicLinkInput): Promise<void> {
  if (!isConfigured()) {
    console.log(
      `[email] SCW_TEM not configured — logging magic link instead.\n  to: ${input.to}\n  link: ${input.link}\n  expires: ${input.expiresAt.toISOString()}`,
    );
    return;
  }

  const body = {
    from: { email: env.EMAIL_FROM, name: env.EMAIL_FROM_NAME },
    to: [{ email: input.to }],
    project_id: env.SCW_TEM_PROJECT_ID,
    subject: buildMagicLinkSubject(),
    text: buildMagicLinkText(input),
    html: buildMagicLinkHtml(input),
    ...(env.EMAIL_REPLY_TO
      ? { additional_headers: [{ key: "Reply-To", value: env.EMAIL_REPLY_TO }] }
      : {}),
  };

  const response = await fetch(SCW_TEM_ENDPOINT(env.SCW_TEM_REGION), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Auth-Token": env.SCW_TEM_SECRET_KEY,
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const errorBody = await response.text().catch(() => "<unreadable>");
    // Don't include the magic link in error logs.
    console.error(
      `[email] Scaleway TEM send failed (${response.status}) for ${input.to}: ${errorBody.slice(0, 500)}`,
    );
    throw new Error(`Email send failed: ${response.status}`);
  }
}

// ─── portal sharing ─────────────────────────────────────────────────────────
// Three short notices. They name the other person's address and nothing
// about the portal: its title is encrypted and never reaches the server.

export type PortalNotice =
  /** To the invitee: someone wants to share a portal with them. */
  | { kind: "invited"; to: string; ownerEmail: string }
  /** To the owner: the invitee now has a vault, so access can be given. */
  | { kind: "invitee_ready"; to: string; inviteeEmail: string; portalId: string }
  /** To the guest: the owner handed over access. */
  | { kind: "access_given"; to: string; ownerEmail: string };

interface NoticeContent {
  subject: string;
  heading: string;
  paragraphs: string[];
  button: { label: string; url: string };
  footnote: string;
}

export function buildPortalNotice(notice: PortalNotice): NoticeContent {
  const portals = `${env.APP_URL}/dashboard/portals`;
  switch (notice.kind) {
    case "invited":
      return {
        subject: `${notice.ownerEmail} wants to share a Tessil portal with you`,
        heading: "You're invited to a portal",
        paragraphs: [
          `${notice.ownerEmail} wants to share a portal with you on Tessil. A portal is a link through which other people send them files, encrypted so only its members can open them.`,
          "Sign in with this email address and set up a vault. A free account is enough. They can then give you access, and we'll email you when they have.",
        ],
        button: { label: "Sign in to Tessil", url: portals },
        footnote: `If you don't know ${notice.ownerEmail}, ignore this email. Nothing happens unless you sign in.`,
      };
    case "invitee_ready":
      return {
        subject: `${notice.inviteeEmail} is ready for your portal`,
        heading: "Your invite is ready",
        paragraphs: [
          `${notice.inviteeEmail} has signed in and set up a vault. Open the portal and choose Sharing to give them access.`,
          "This step happens in your browser, because only you hold the portal's keys.",
        ],
        button: { label: "Open the portal", url: `${portals}/${notice.portalId}` },
        footnote: "You're getting this because you invited them to a portal.",
      };
    case "access_given":
      return {
        subject: `${notice.ownerEmail} shared a Tessil portal with you`,
        heading: "A portal was shared with you",
        paragraphs: [
          `${notice.ownerEmail} gave you access to a portal. Open your portals and accept it to see the files sent to it.`,
        ],
        button: { label: "View your portals", url: portals },
        footnote: `If you don't know ${notice.ownerEmail}, you can decline it there.`,
      };
  }
}

function noticeText(c: NoticeContent): string {
  return [c.heading, "", ...c.paragraphs.flatMap((p) => [p, ""]), c.button.url, "", c.footnote, "", "Tessil"].join("\n");
}

function noticeHtml(c: NoticeContent): string {
  return [
    "<!doctype html>",
    `<html lang="en"><head><meta charset="utf-8"><title>${escapeHtml(c.heading)}</title></head>`,
    '<body style="font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;line-height:1.5;color:#111;max-width:560px;margin:24px auto;padding:0 16px;">',
    `  <h1 style="font-size:20px;margin:0 0 16px;">${escapeHtml(c.heading)}</h1>`,
    ...c.paragraphs.map((p) => `  <p>${escapeHtml(p)}</p>`),
    `  <p style="margin:24px 0;"><a href="${escapeHtml(c.button.url)}" style="display:inline-block;padding:12px 20px;background:#111;color:#fff;text-decoration:none;border-radius:8px;">${escapeHtml(c.button.label)}</a></p>`,
    `  <p style="font-size:12px;color:#666;">${escapeHtml(c.footnote)}</p>`,
    "</body></html>",
  ].join("\n");
}

/** Never throws: a failed notice must not fail the action that caused it. */
export async function sendPortalNotice(notice: PortalNotice): Promise<void> {
  const content = buildPortalNotice(notice);
  if (!isConfigured()) {
    console.log(`[email] SCW_TEM not configured, logging portal notice instead.\n  to: ${notice.to}\n  subject: ${content.subject}`);
    return;
  }
  try {
    const response = await fetch(SCW_TEM_ENDPOINT(env.SCW_TEM_REGION), {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Auth-Token": env.SCW_TEM_SECRET_KEY },
      body: JSON.stringify({
        from: { email: env.EMAIL_FROM, name: env.EMAIL_FROM_NAME },
        to: [{ email: notice.to }],
        project_id: env.SCW_TEM_PROJECT_ID,
        subject: content.subject,
        text: noticeText(content),
        html: noticeHtml(content),
        ...(env.EMAIL_REPLY_TO
          ? { additional_headers: [{ key: "Reply-To", value: env.EMAIL_REPLY_TO }] }
          : {}),
      }),
    });
    if (!response.ok) {
      console.error(`[email] portal notice (${notice.kind}) failed with ${response.status}`);
    }
  } catch (err) {
    console.error(`[email] portal notice (${notice.kind}) failed:`, err);
  }
}
