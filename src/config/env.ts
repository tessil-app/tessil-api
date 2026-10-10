function getEnv(key: string, defaultValue?: string): string {
  const value = process.env[key] ?? defaultValue;
  if (value === undefined) {
    throw new Error(`Missing required environment variable: ${key}`);
  }
  return value;
}

const GB = 1024 * 1024 * 1024;

const NODE_ENV = process.env.NODE_ENV ?? "development";
const IS_PRODUCTION = NODE_ENV === "production";

function randomSecret(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Buffer.from(bytes).toString("base64url");
}

export const env = {
  DATABASE_URL: getEnv("DATABASE_URL"),
  REDIS_URL: process.env.REDIS_URL, // Optional - falls back to in-memory if not set
  CORS_ORIGINS: getEnv("CORS_ORIGINS", "http://localhost:5173"),
  PORT: parseInt(getEnv("PORT", "3000"), 10),
  MAX_FILE_SIZE: parseInt(
    getEnv("MAX_FILE_SIZE", String(1024 * 1024 * 1024)),
    10
  ), // 1GB default
  MAX_TOTAL_UPLOAD_SIZE: parseInt(
    getEnv("MAX_TOTAL_UPLOAD_SIZE", String(1024 * 1024 * 1024)),
    10
  ), // 1GB total per transfer default

  // Cloudflare R2 configuration
  R2_ENDPOINT: getEnv("R2_ENDPOINT"),
  R2_ACCESS_KEY_ID: getEnv("R2_ACCESS_KEY_ID"),
  R2_SECRET_ACCESS_KEY: getEnv("R2_SECRET_ACCESS_KEY"),
  R2_BUCKET_NAME: getEnv("R2_BUCKET_NAME"),

  // Rate limits (configurable)
  RATE_LIMIT_VALIDATE_PER_MINUTE: parseInt(getEnv("RATE_LIMIT_VALIDATE_PER_MINUTE", "30"), 10),
  RATE_LIMIT_UPLOADS_PER_MINUTE: parseInt(getEnv("RATE_LIMIT_UPLOADS_PER_MINUTE", "20"), 10),
  RATE_LIMIT_DOWNLOADS_PER_MINUTE: parseInt(getEnv("RATE_LIMIT_DOWNLOADS_PER_MINUTE", "20"), 10),
  RATE_LIMIT_DAILY_TRANSFERS: parseInt(getEnv("RATE_LIMIT_DAILY_TRANSFERS", "20"), 10),
  RATE_LIMIT_DAILY_DOWNLOADS: parseInt(getEnv("RATE_LIMIT_DAILY_DOWNLOADS", "200"), 10),
  RATE_LIMIT_MONTHLY_UPLOAD_GB: parseInt(getEnv("RATE_LIMIT_MONTHLY_UPLOAD_GB", "2"), 10) * GB,

  // Auth — magic-link primary. APP_URL is the public frontend origin
  // used to compose magic links and as the default base for WebAuthn
  // RP origin and the Polar checkout success URL.
  APP_URL: getEnv("APP_URL", "http://localhost:5173"),

  // Scaleway Transactional Email — transactional only per ToS (no marketing).
  // When PROJECT_ID + SECRET_KEY are unset (dev), the email service logs the
  // magic link to stdout instead of sending. NEVER deploy unset.
  SCW_TEM_REGION: getEnv("SCW_TEM_REGION", "fr-par"),
  SCW_TEM_PROJECT_ID: process.env.SCW_TEM_PROJECT_ID ?? "",
  SCW_TEM_SECRET_KEY: process.env.SCW_TEM_SECRET_KEY ?? "",
  EMAIL_FROM: getEnv("EMAIL_FROM", "noreply@localhost"),
  EMAIL_FROM_NAME: getEnv("EMAIL_FROM_NAME", "Tessil"),
  EMAIL_REPLY_TO: process.env.EMAIL_REPLY_TO ?? "",

  // Magic-link auth rate limits. Configurable for operator tuning if
  // abuse signals appear.
  RATE_LIMIT_AUTH_REQUEST_PER_HOUR_PER_EMAIL: parseInt(
    getEnv("RATE_LIMIT_AUTH_REQUEST_PER_HOUR_PER_EMAIL", "5"),
    10,
  ),
  RATE_LIMIT_AUTH_REQUEST_PER_HOUR_PER_IP: parseInt(
    getEnv("RATE_LIMIT_AUTH_REQUEST_PER_HOUR_PER_IP", "20"),
    10,
  ),
  RATE_LIMIT_AUTH_VERIFY_PER_MINUTE_PER_IP: parseInt(
    getEnv("RATE_LIMIT_AUTH_VERIFY_PER_MINUTE_PER_IP", "10"),
    10,
  ),

  // HMAC secret for the short-lived "password OK" download token
  // issued by /api/download/transfer/:id/verify and required by
  // /api/download/file/:id/url when the transfer is
  // password-protected. In production this must be set explicitly
  // so the secret survives restarts; in dev/test a per-process
  // random value is fine.
  DOWNLOAD_TOKEN_SECRET: process.env.DOWNLOAD_TOKEN_SECRET ?? (IS_PRODUCTION ? "" : randomSecret()),

  // WebAuthn / passkeys.
  //
  // `WEBAUTHN_RP_ID` = the host without scheme or port (e.g.
  // `tessil.com`). Browsers reject registrations where the RP ID
  // is not a registrable suffix of the page origin, so the value
  // must match the deployment domain. `WEBAUTHN_RP_ORIGIN` = the
  // full origin sent in `expectedOrigin` on verify. Defaults derive
  // from APP_URL; both must be set explicitly in prod.
  WEBAUTHN_RP_ID:
    process.env.WEBAUTHN_RP_ID ??
    (() => {
      try {
        return new URL(process.env.APP_URL ?? "http://localhost:5173").hostname;
      } catch {
        return "localhost";
      }
    })(),
  WEBAUTHN_RP_ORIGIN: process.env.WEBAUTHN_RP_ORIGIN ?? (process.env.APP_URL ?? "http://localhost:5173"),
  WEBAUTHN_RP_NAME: process.env.WEBAUTHN_RP_NAME ?? "Tessil",

  // IP minimization / GeoIP.
  //
  // Raw client IPs are never stored. They are resolved to country +
  // ASN (+ city for outbound email recognition copy) and HMAC'd
  // with a rotating salt for correlation. Country/ASN come from
  // Cloudflare `CF-IPCountry` / `CF-IPASN` when present; the MMDB
  // files are the fallback when the API is hit directly.
  //
  // `MAXMIND_ACCOUNT_ID` + `MAXMIND_LICENSE_KEY` are only needed by
  // the weekly refresh script; the running API just reads the MMDB
  // files from disk.
  MAXMIND_ACCOUNT_ID: process.env.MAXMIND_ACCOUNT_ID ?? "",
  MAXMIND_LICENSE_KEY: process.env.MAXMIND_LICENSE_KEY ?? "",
  GEOIP_DIR: getEnv("GEOIP_DIR", "/var/lib/geoip"),
  ENABLE_IP_DERIVATION: (process.env.ENABLE_IP_DERIVATION ?? "true") === "true",
  // Session-anomaly detection. Off-switch for the same-session ip_hmac
  // comparison in case it ever produces noise we want to silence quickly.
  ENABLE_SESSION_ANOMALY_DETECTION:
    (process.env.ENABLE_SESSION_ANOMALY_DETECTION ?? "true") === "true",
  // Session-anomaly email notification. Default off — the operator flips
  // it on after observing the in-prod false-positive rate. The audit-log
  // row is written either way; this flag only gates the outbound email.
  ENABLE_SESSION_ANOMALY_EMAIL:
    (process.env.ENABLE_SESSION_ANOMALY_EMAIL ?? "false") === "true",

  // Polar — payment processor + Merchant of Record for Pro
  // subscriptions. Sandbox in dev and CI; production carries real
  // money. The access token authenticates server-side API calls
  // (create checkouts, open portal sessions); the webhook secret
  // verifies signatures on inbound events. Product IDs are
  // configured in the Polar dashboard once and pasted here. The
  // success URL is where the Polar-hosted checkout redirects after
  // a completed purchase.
  POLAR_SERVER: (process.env.POLAR_SERVER ?? "sandbox") as "sandbox" | "production",
  POLAR_ACCESS_TOKEN: process.env.POLAR_ACCESS_TOKEN ?? "",
  POLAR_WEBHOOK_SECRET: process.env.POLAR_WEBHOOK_SECRET ?? "",
  POLAR_PRODUCT_ID_MONTHLY: process.env.POLAR_PRODUCT_ID_MONTHLY ?? "",
  POLAR_PRODUCT_ID_ANNUAL: process.env.POLAR_PRODUCT_ID_ANNUAL ?? "",
  // One-time product behind the single-transfer pass.
  POLAR_PRODUCT_ID_PASS: process.env.POLAR_PRODUCT_ID_PASS ?? "",
  // Kill switch for the pay-to-send experiment. Off means every tier
  // behaves as before and pass tokens are ignored.
  PAYWALL_ENABLED: (process.env.PAYWALL_ENABLED ?? "false") === "true",
  POLAR_SUCCESS_URL: process.env.POLAR_SUCCESS_URL ?? "",

  NODE_ENV,
  IS_PRODUCTION,
};

// Production-only assertions — fail fast on misconfiguration that would let
// real-world traffic hit dev defaults (insecure cookies, no email, etc.).
if (IS_PRODUCTION) {
  const missing: string[] = [];
  if (!env.SCW_TEM_PROJECT_ID) missing.push("SCW_TEM_PROJECT_ID");
  if (!env.SCW_TEM_SECRET_KEY) missing.push("SCW_TEM_SECRET_KEY");
  if (env.EMAIL_FROM === "noreply@localhost") missing.push("EMAIL_FROM (still default)");
  if (env.APP_URL.startsWith("http://localhost")) missing.push("APP_URL (still localhost default)");
  if (!env.DOWNLOAD_TOKEN_SECRET) missing.push("DOWNLOAD_TOKEN_SECRET");
  if (missing.length > 0) {
    throw new Error(
      `Production env misconfigured. Required for auth: ${missing.join(", ")}. ` +
        `In dev (NODE_ENV != production), these can be left unset and email is logged to stdout.`,
    );
  }

  // A paywall that cannot take payment locks every sender out.
  if (env.PAYWALL_ENABLED) {
    const missingBilling: string[] = [];
    if (!env.POLAR_ACCESS_TOKEN) missingBilling.push("POLAR_ACCESS_TOKEN");
    if (!env.POLAR_WEBHOOK_SECRET) missingBilling.push("POLAR_WEBHOOK_SECRET");
    if (!env.POLAR_PRODUCT_ID_MONTHLY) missingBilling.push("POLAR_PRODUCT_ID_MONTHLY");
    if (!env.POLAR_PRODUCT_ID_PASS) missingBilling.push("POLAR_PRODUCT_ID_PASS");
    if (missingBilling.length > 0) {
      throw new Error(
        `PAYWALL_ENABLED=true but billing is not configured: ${missingBilling.join(", ")}.`,
      );
    }
  }

  // CORS `*` + credentials reflects the request origin, making
  // every cookied response readable cross-origin. Always a
  // misconfiguration in prod.
  const corsOrigins = env.CORS_ORIGINS.split(",").map((o) => o.trim()).filter(Boolean);
  if (corsOrigins.includes("*")) {
    throw new Error(
      "Production env misconfigured: CORS_ORIGINS must not contain `*`. " +
        "Set it to the explicit frontend origin(s), e.g. `https://tessil.app`.",
    );
  }
}
