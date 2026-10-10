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
}

const ANONYMOUS_CAPS: TierCaps = {
  maxFileSize: 500 * MB,
  maxTransferSize: 500 * MB,
  monthlyVolumeBytes: 500 * MB,
  dailyTransferCount: 5,
  allowedExpiryHours: [1, 6, 12, 24],
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
  };
}

const PRO_CAPS: TierCaps = {
  maxFileSize: 2 * GB,
  maxTransferSize: 2 * GB,
  monthlyVolumeBytes: 100 * GB,
  dailyTransferCount: 100,
  // 168h = 7d, 336h = 14d, 720h = 30d.
  allowedExpiryHours: [1, 6, 12, 24, 72, 168, 336, 720],
};

/**
 * Resolve the active caps for a request. `null` / `undefined` means
 * anonymous. Unknown tier strings fail closed to Free.
 */
export function resolveCaps(user: { tier: string } | null | undefined): TierCaps {
  if (!user) return ANONYMOUS_CAPS;
  if (user.tier === "pro") return PRO_CAPS;
  return freeCaps();
}

/**
 * Caps for a transfer that may be riding on a single-transfer pass. A
 * pass buys the paid per-transfer limits for that one transfer, whoever
 * the sender is.
 */
export function resolveTransferCaps(
  user: { tier: string } | null | undefined,
  hasPass: boolean,
): TierCaps {
  return hasPass ? PRO_CAPS : resolveCaps(user);
}

/** The limits shown to a sender who has not paid yet. */
export function paidCaps(): TierCaps {
  return PRO_CAPS;
}
