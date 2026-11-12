import { env } from "./env";

const MB = 1024 * 1024;
const GB = 1024 * 1024 * 1024;

export interface TierCaps {
  maxFileSize: number;
  maxTransferSize: number;
  monthlyVolumeBytes: number;
  dailyTransferCount: number;
  /** Allowed values for the `expiresInHours` body field on create-transfer. */
  allowedExpiryHours: readonly number[];
  /**
   * Bytes the account may have stored at any one time, across everything
   * it owns. NULL on plans that keep nothing for long and are bounded by
   * the flow limits above instead.
   */
  storageBytes: number | null;
  /** How long portal deposits are kept. NULL on plans without portals. */
  depositRetentionDays: number | null;
  /** Portals an account may own. 0 on plans without portals. */
  maxPortals: number;
}

const ANONYMOUS_CAPS: TierCaps = {
  maxFileSize: 500 * MB,
  maxTransferSize: 500 * MB,
  monthlyVolumeBytes: 500 * MB,
  dailyTransferCount: 5,
  allowedExpiryHours: [1, 6, 12, 24],
  storageBytes: null,
  depositRetentionDays: null,
  maxPortals: 0,
};

// Free reads from env so production deploys can override the defaults
// without a code change. Wrapped in a function so test-time env
// overrides are picked up on the next call.
function freeCaps(): TierCaps {
  return {
    maxFileSize: env.MAX_FILE_SIZE,
    maxTransferSize: env.MAX_TOTAL_UPLOAD_SIZE,
    monthlyVolumeBytes: env.RATE_LIMIT_MONTHLY_UPLOAD_GB,
    dailyTransferCount: env.RATE_LIMIT_DAILY_TRANSFERS,
    allowedExpiryHours: [1, 6, 12, 24, 72],
    storageBytes: null,
    depositRetentionDays: null,
    maxPortals: 0,
  };
}

// 168h = 7d, 336h = 14d, 720h = 30d, 1440h = 60d, 2160h = 90d.
const PRO_EXPIRY_HOURS = [1, 6, 12, 24, 72, 168, 336, 720] as const;
const MAX_EXPIRY_HOURS = [...PRO_EXPIRY_HOURS, 1440, 2160] as const;

// The two paid plans share every limit except storage and how long
// things are kept. The storage quota is what a paying user sees; the
// monthly volume stays only as a fair-use backstop. The per-file cap is
// held down until uploads can resume: a dropped connection restarts a
// file from zero and upload URLs last 4 hours.
function proCaps(): TierCaps {
  return {
    maxFileSize: env.PLAN_PAID_MAX_FILE_GB,
    maxTransferSize: 2 * env.PLAN_PAID_MAX_FILE_GB,
    monthlyVolumeBytes: 100 * GB,
    dailyTransferCount: 100,
    allowedExpiryHours: PRO_EXPIRY_HOURS,
    storageBytes: env.PLAN_PRO_STORAGE_GB,
    depositRetentionDays: env.PLAN_PRO_RETENTION_DAYS,
    maxPortals: env.PLAN_PRO_MAX_PORTALS,
  };
}

function maxCaps(): TierCaps {
  return {
    ...proCaps(),
    monthlyVolumeBytes: 500 * GB,
    allowedExpiryHours: MAX_EXPIRY_HOURS,
    storageBytes: env.PLAN_MAX_STORAGE_GB,
    depositRetentionDays: env.PLAN_MAX_RETENTION_DAYS,
    maxPortals: env.PLAN_MAX_MAX_PORTALS,
  };
}

export type PaidTier = "pro" | "max";

/**
 * Resolve the active caps for a request. `null` / `undefined` means
 * anonymous. Unknown tier strings fail closed to Free.
 */
export function resolveCaps(user: { tier: string } | null | undefined): TierCaps {
  if (!user) return ANONYMOUS_CAPS;
  if (user.tier === "pro") return proCaps();
  if (user.tier === "max") return maxCaps();
  return freeCaps();
}
