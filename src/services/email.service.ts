// Scaleway Transactional Email integration. Transactional only,
// no marketing, per Scaleway TEM ToS.
//
// In dev when SCW_TEM credentials are not configured, the magic
// link is logged to stdout so flows can be tested without a real
// send.

import { env } from "../config/env";
import type { IpContext } from "../utils/ipContext";
import { emailCopy, mailLocale, type MailLocale } from "./emailCopy";

export { mailLocale, type MailLocale };

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
  locale?: MailLocale;
}

function formatLocation(ipContext: IpContext, unknown: string): string {
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
  return unknown;
}

const SCW_TEM_ENDPOINT = (region: string) =>
  `https://api.scaleway.com/transactional-email/v1alpha1/regions/${region}/emails`;

function isConfigured(): boolean {
  return Boolean(env.SCW_TEM_PROJECT_ID && env.SCW_TEM_SECRET_KEY);
}

const BODY_STYLE =
  'font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;line-height:1.5;color:#111;max-width:560px;margin:24px auto;padding:0 16px;';
const BUTTON_STYLE =
  "display:inline-block;padding:12px 20px;background:#111;color:#fff;text-decoration:none;border-radius:8px;";

function minutesLeft(expiresAt: Date): number {
  return Math.max(1, Math.round((expiresAt.getTime() - Date.now()) / 60000));
}

function buildMagicLinkText({ link, expiresAt, ipContext, userAgent, locale }: SendMagicLinkInput): string {
  const c = emailCopy[mailLocale(locale)];
  return [
    c.magic.heading,
    "",
    c.magic.intro(minutesLeft(expiresAt)),
    "",
    link,
    "",
    c.magic.otherDevice,
    "",
    `${c.magic.details}:`,
    `  ${c.magic.location}: ${formatLocation(ipContext, c.unknown)}`,
    `  ${c.magic.browser}: ${userAgent ?? c.unknown}`,
    "",
    c.magic.noIp,
    "",
    c.magic.notYou,
    "",
    c.signoff,
  ].join("\n");
}

function buildMagicLinkHtml(input: SendMagicLinkInput): string {
  const lang = mailLocale(input.locale);
  const c = emailCopy[lang];
  // Minimal inline-styled HTML: no tracking pixels, no remote assets.
  return [
    "<!doctype html>",
    `<html lang="${lang}"><head><meta charset="utf-8"><title>${c.magic.heading}</title></head>`,
    `<body style="${BODY_STYLE}">`,
    `  <h1 style="font-size:20px;margin:0 0 16px;">${c.magic.heading}</h1>`,
    `  <p>${c.magic.introHtml(minutesLeft(input.expiresAt))}</p>`,
    `  <p style="margin:24px 0;"><a href="${escapeHtml(input.link)}" style="${BUTTON_STYLE}">${c.magic.button}</a></p>`,
    `  <p style="font-size:13px;color:#555;">${c.magic.paste}<br><code style="word-break:break-all;">${escapeHtml(input.link)}</code></p>`,
    `  <p style="font-size:13px;color:#555;">${escapeHtml(c.magic.otherDevice)}</p>`,
    '  <hr style="border:none;border-top:1px solid #eee;margin:24px 0;">',
    `  <p style="font-size:12px;color:#666;">${c.magic.details}: ${c.magic.location}: ` +
      escapeHtml(formatLocation(input.ipContext, c.unknown)) +
      ` &middot; ${c.magic.browser}: ` +
      escapeHtml(input.userAgent ?? c.unknown) +
      "</p>",
    `  <p style="font-size:12px;color:#666;">${escapeHtml(c.magic.noIp)}</p>`,
    `  <p style="font-size:12px;color:#666;">${escapeHtml(c.magic.notYou)}</p>`,
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
  locale?: MailLocale;
}

function buildAccountDeletedText({ to, locale }: SendAccountDeletedInput): string {
  const c = emailCopy[mailLocale(locale)].deleted;
  return [c.body, "", c.notYou(to), "", c.noCopies, "", emailCopy.en.signoff].join("\n");
}

function buildAccountDeletedHtml({ to, locale }: SendAccountDeletedInput): string {
  const lang = mailLocale(locale);
  const c = emailCopy[lang].deleted;
  return [
    "<!doctype html>",
    `<html lang="${lang}"><head><meta charset="utf-8"><title>${c.subject}</title></head>`,
    `<body style="${BODY_STYLE}">`,
    `  <h1 style="font-size:20px;margin:0 0 16px;">${c.subject}</h1>`,
    `  <p>${escapeHtml(c.body)}</p>`,
    `  <p>${escapeHtml(c.notYou(to))}</p>`,
    `  <p style="font-size:13px;color:#555;">${escapeHtml(c.noCopies)}</p>`,
    "</body></html>",
  ].join("\n");
}

export async function sendAccountDeletedNotification(input: SendAccountDeletedInput): Promise<void> {
  if (!isConfigured()) {
    console.log(
      `[email] SCW_TEM not configured, logging account-deleted notification instead.\n  to: ${input.to}`,
    );
    return;
  }

  const body = {
    from: { email: env.EMAIL_FROM, name: env.EMAIL_FROM_NAME },
    to: [{ email: input.to }],
    project_id: env.SCW_TEM_PROJECT_ID,
    subject: emailCopy[mailLocale(input.locale)].deleted.subject,
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
  /** User-agent from the session at create, to tell which session. */
  sessionUserAgent: string | null;
  /** When the affected session was created. */
  sessionCreatedAt: Date;
  /** Absolute URL to /dashboard/settings, where the user can sign out everywhere. */
  settingsUrl: string;
  locale?: MailLocale;
}

// The country's name in the reader's language, or the raw code when the
// platform does not know it.
function countryName(iso2: string | null, locale: MailLocale = "en"): string {
  if (!iso2) return emailCopy[locale].unknownPlace;
  try {
    const dn = new Intl.DisplayNames([locale], { type: "region" });
    return dn.of(iso2.toUpperCase()) ?? iso2;
  } catch {
    return iso2;
  }
}

function formatAnomalyNetwork(
  country: string | null,
  asnOrg: string | null,
  asn: number | null,
  locale: MailLocale = "en",
): string {
  const place = countryName(country, locale);
  const org = asnOrg ?? (asn ? `AS${asn}` : null);
  return org ? `${place} (${org})` : place;
}

function anomalyParts(input: SendSessionAnomalyInput) {
  const lang = mailLocale(input.locale);
  return {
    lang,
    c: emailCopy[lang].anomaly,
    previous: formatAnomalyNetwork(input.previousCountry, input.previousAsnOrg, input.previousAsn, lang),
    current: formatAnomalyNetwork(input.currentCountry, input.currentAsnOrg, input.currentAsn, lang),
    createdAt: input.sessionCreatedAt.toISOString().slice(0, 10),
  };
}

function buildSessionAnomalyText(input: SendSessionAnomalyInput): string {
  const { c, previous, current, createdAt } = anomalyParts(input);
  return [
    c.noticed,
    "",
    c.moved(previous, current),
    "",
    c.session(createdAt) + (input.sessionUserAgent ? ` ${c.from} "${input.sessionUserAgent}"` : ""),
    "",
    c.ifNot,
    input.settingsUrl,
    "",
    c.ifYou,
    "",
    c.noIp,
    "",
    emailCopy.en.signoff,
  ].join("\n");
}

function buildSessionAnomalyHtml(input: SendSessionAnomalyInput): string {
  const { lang, c, previous, current, createdAt } = anomalyParts(input);
  const sessionLine = input.sessionUserAgent
    ? `${c.session(createdAt)} ${c.from} <code>${escapeHtml(input.sessionUserAgent)}</code>`
    : c.session(createdAt);
  return [
    "<!doctype html>",
    `<html lang="${lang}"><head><meta charset="utf-8"><title>${c.title}</title></head>`,
    `<body style="${BODY_STYLE}">`,
    `  <h1 style="font-size:20px;margin:0 0 16px;">${c.heading}</h1>`,
    `  <p>${c.moved(`<strong>${escapeHtml(previous)}</strong>`, `<strong>${escapeHtml(current)}</strong>`)}</p>`,
    `  <p style="font-size:13px;color:#555;">${sessionLine}</p>`,
    `  <p style="margin:24px 0;"><a href="${escapeHtml(input.settingsUrl)}" style="${BUTTON_STYLE}">${c.button}</a></p>`,
    `  <p style="font-size:13px;color:#555;">${escapeHtml(c.ifYou)}</p>`,
    '  <hr style="border:none;border-top:1px solid #eee;margin:24px 0;">',
    `  <p style="font-size:12px;color:#666;">${escapeHtml(c.noIp)}</p>`,
    "</body></html>",
  ].join("\n");
}

export async function sendSessionAnomalyNotification(
  input: SendSessionAnomalyInput,
): Promise<void> {
  if (!isConfigured()) {
    console.log(
      `[email] SCW_TEM not configured, logging session-anomaly notification instead.\n  to: ${input.to}\n  previous: ${formatAnomalyNetwork(input.previousCountry, input.previousAsnOrg, input.previousAsn)}\n  current: ${formatAnomalyNetwork(input.currentCountry, input.currentAsnOrg, input.currentAsn)}`,
    );
    return;
  }

  const body = {
    from: { email: env.EMAIL_FROM, name: env.EMAIL_FROM_NAME },
    to: [{ email: input.to }],
    project_id: env.SCW_TEM_PROJECT_ID,
    subject: emailCopy[mailLocale(input.locale)].anomaly.subject,
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
      `[email] SCW_TEM not configured, logging magic link instead.\n  to: ${input.to}\n  link: ${input.link}\n  expires: ${input.expiresAt.toISOString()}`,
    );
    return;
  }

  const body = {
    from: { email: env.EMAIL_FROM, name: env.EMAIL_FROM_NAME },
    to: [{ email: input.to }],
    project_id: env.SCW_TEM_PROJECT_ID,
    subject: emailCopy[mailLocale(input.locale)].magic.subject,
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

export type PortalNotice = (
  /** To the invitee: someone wants to share a portal with them. */
  | { kind: "invited"; to: string; ownerEmail: string }
  /** To the owner: the invitee now has a vault, so access can be given. */
  | { kind: "invitee_ready"; to: string; inviteeEmail: string; portalId: string }
  /** To the guest: the owner handed over access. */
  | { kind: "access_given"; to: string; ownerEmail: string }
  /** To a member: files arrived in a portal that has arrival emails on. */
  | { kind: "delivery"; to: string; portalId: string }
) & {
  /** About a form rather than a portal. */
  form?: boolean;
  /** The recipient's language. */
  locale?: MailLocale;
};

interface NoticeContent {
  lang: MailLocale;
  subject: string;
  heading: string;
  paragraphs: string[];
  button: { label: string; url: string };
  footnote: string;
}

export function buildPortalNotice(notice: PortalNotice): NoticeContent {
  const noun = notice.form ? "form" : "portal";
  const lang = mailLocale(notice.locale);
  const c = emailCopy[lang].notice;
  const list = `${env.APP_URL}/dashboard/${noun}s`;
  switch (notice.kind) {
    case "invited":
      return {
        lang,
        subject: c.invited.subject(notice.ownerEmail, noun),
        heading: c.invited.heading(noun),
        paragraphs: [c.invited.what(notice.ownerEmail, noun), c.invited.next],
        button: { label: c.invited.button, url: list },
        footnote: c.invited.footnote(notice.ownerEmail),
      };
    case "invitee_ready":
      return {
        lang,
        subject: c.ready.subject(notice.inviteeEmail, noun),
        heading: c.ready.heading,
        paragraphs: [c.ready.body(notice.inviteeEmail, noun), c.ready.why(noun)],
        button: { label: c.ready.button(noun), url: `${list}/${notice.portalId}` },
        footnote: c.ready.footnote(noun),
      };
    case "access_given":
      return {
        lang,
        subject: c.given.subject(notice.ownerEmail, noun),
        heading: c.given.heading(noun),
        paragraphs: [c.given.body(notice.ownerEmail, noun)],
        button: { label: c.given.button(noun), url: list },
        footnote: c.given.footnote(notice.ownerEmail),
      };
    case "delivery": {
      const d = notice.form ? c.response : c.files;
      return {
        lang,
        subject: d.subject,
        heading: d.heading,
        paragraphs: [d.body, d.why],
        button: { label: d.button, url: `${list}/${notice.portalId}` },
        footnote: d.footnote,
      };
    }
  }
}

function noticeText(c: NoticeContent): string {
  return [c.heading, "", ...c.paragraphs.flatMap((p) => [p, ""]), c.button.url, "", c.footnote, "", emailCopy.en.signoff].join("\n");
}

function noticeHtml(c: NoticeContent): string {
  return [
    "<!doctype html>",
    `<html lang="${c.lang}"><head><meta charset="utf-8"><title>${escapeHtml(c.heading)}</title></head>`,
    `<body style="${BODY_STYLE}">`,
    `  <h1 style="font-size:20px;margin:0 0 16px;">${escapeHtml(c.heading)}</h1>`,
    ...c.paragraphs.map((p) => `  <p>${escapeHtml(p)}</p>`),
    `  <p style="margin:24px 0;"><a href="${escapeHtml(c.button.url)}" style="${BUTTON_STYLE}">${escapeHtml(c.button.label)}</a></p>`,
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
