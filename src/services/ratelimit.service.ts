import Redis from 'ioredis';
import { env } from '../config/env';
import { getActiveSalt } from './saltService';
import type { IpContext } from '../utils/ipContext';

// Sliding-window check + add in one round trip. Without this, two
// concurrent MULTIs against the same key can each see count = N-1,
// both ZADD, and the limiter ends up at N+1. Returning
// [allowed (0|1), countAfter] keeps the API identical to a
// MULTI-then-ZREM sequence but race-free.
export const SLIDING_WINDOW_LUA = `
local window_start = tonumber(ARGV[1])
local now = tonumber(ARGV[2])
local max = tonumber(ARGV[3])
local member = ARGV[4]
local ttl = tonumber(ARGV[5])

redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, window_start)
local count = redis.call('ZCARD', KEYS[1])
if count >= max then
  return {0, count}
end
redis.call('ZADD', KEYS[1], now, member)
redis.call('EXPIRE', KEYS[1], ttl)
return {1, count + 1}
`;

// Redis client (lazy initialized)
let redis: Redis | null = null;
let redisAvailable = true;

function getRedis(): Redis | null {
  if (!env.REDIS_URL) {
    return null;
  }

  if (!redis && redisAvailable) {
    redis = new Redis(env.REDIS_URL, {
      maxRetriesPerRequest: 1,
      retryStrategy: (times) => {
        if (times > 3) {
          console.warn('[RateLimit] Redis unavailable, falling back to in-memory');
          redisAvailable = false;
          return null; // Stop retrying
        }
        return Math.min(times * 100, 1000);
      },
      lazyConnect: true,
    });

    redis.defineCommand('jtSlidingWindow', {
      numberOfKeys: 1,
      lua: SLIDING_WINDOW_LUA,
    });

    redis.on('error', (err) => {
      if (redisAvailable) {
        console.warn('[RateLimit] Redis error:', err.message);
      }
    });

    redis.on('connect', () => {
      console.log('[RateLimit] Redis connected');
      redisAvailable = true;
    });

    // Attempt connection
    redis.connect().catch(() => {
      redisAvailable = false;
    });
  }

  return redisAvailable ? redis : null;
}

interface RedisWithSlidingWindow extends Redis {
  jtSlidingWindow(
    key: string,
    windowStart: number,
    now: number,
    max: number,
    member: string,
    ttl: number,
  ): Promise<[number, number]>;
}

// In-memory fallback for development or when Redis is unavailable
const memoryLimits = new Map<string, { count: number; resetAt: number }>();
const memoryCounters = new Map<string, { value: number; resetAt: number }>();

// Clean up old entries periodically (every 5 minutes)
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of memoryLimits.entries()) {
    if (now > value.resetAt) {
      memoryLimits.delete(key);
    }
  }
  for (const [key, value] of memoryCounters.entries()) {
    if (now > value.resetAt) {
      memoryCounters.delete(key);
    }
  }
}, 5 * 60 * 1000);

/**
 * Drop all rate-limit + volume-counter state. Intended for test
 * isolation: the in-memory store is process-global and survives
 * `resetDb()`, so without this every test shares one anonymous
 * per-IP bucket and the low caps trip across the suite. Clears the
 * in-memory maps always; flushes Redis only outside production (so a
 * misconfigured prod runner can never wipe a live limiter store).
 */
export async function resetRateLimits(): Promise<void> {
  memoryLimits.clear();
  memoryCounters.clear();
  if (redis && redisAvailable && !env.IS_PRODUCTION) {
    await redis.flushdb();
  }
}

interface RateLimitConfig {
  /** Unique prefix for this limiter (e.g., 'upload', 'download', 'password') */
  prefix: string;
  /** Time window in seconds */
  windowSeconds: number;
  /** Maximum requests allowed in the window */
  maxRequests: number;
}

interface VolumeLimitConfig {
  prefix: string;
  windowSeconds: number;
  /** Maximum bytes allowed in the window */
  maxBytes: number;
  /** Bytes to add for this request */
  increment: number;
}

interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetIn: number; // seconds until reset
}

/**
 * Check rate limit for an opaque identifier — used for non-IP keys
 * (email, userId, transferId). IP-keyed limiters MUST use
 * `checkIpRateLimit` instead so the IP never lands in a Redis key.
 */
export async function checkRateLimit(
  identifier: string,
  config: RateLimitConfig
): Promise<RateLimitResult> {
  const key = `ratelimit:${config.prefix}:${identifier}`;
  const redisClient = getRedis();

  if (redisClient && redisAvailable) {
    return checkRedisRateLimit(redisClient, key, config);
  }

  return checkMemoryRateLimit(key, config);
}

/**
 * IP-keyed rate-limit check. The Redis key is built from
 * `HMAC(ratelimit_salt, ip)` so the raw IP never enters a key, log,
 * or counter.
 *
 * The ratelimit salt rotates every 35 days (≥ max rate-limit window),
 * so a single salt always covers a full counter lifetime — counters
 * expire before salts rotate and no rehash is ever needed.
 */
export async function checkIpRateLimit(
  ipContext: IpContext,
  config: RateLimitConfig
): Promise<RateLimitResult> {
  const identifier = await ipRateLimitIdentifier(ipContext);
  return checkRateLimit(identifier, config);
}

/**
 * Tier-aware rate-limit check. Per-user when authed, per-IP otherwise —
 * authenticated users see their cap unified across devices and networks;
 * anonymous traffic falls back to the IP-keyed bucket.
 */
export async function checkAuthedOrIpRateLimit(
  userId: string | null | undefined,
  ipContext: IpContext,
  config: RateLimitConfig
): Promise<RateLimitResult> {
  return userId
    ? checkRateLimit(userId, config)
    : checkIpRateLimit(ipContext, config);
}

async function ipRateLimitIdentifier(ipContext: IpContext): Promise<string> {
  const salt = await getActiveSalt("ratelimit");
  return ipContext.hmac(salt.secret).toString("hex");
}

async function checkRedisRateLimit(
  redis: Redis,
  key: string,
  config: RateLimitConfig
): Promise<RateLimitResult> {
  try {
    const now = Math.floor(Date.now() / 1000);
    const windowStart = now - config.windowSeconds;
    const member = `${now}:${Math.random()}`;

    // One Lua round-trip: prune old → count → add iff under cap → set TTL.
    // Returns [0|1, countAfter]. Race-free vs concurrent callers on the
    // same key (a check-then-add sequence in two round-trips can race).
    const [allowedFlag, countAfter] = await (redis as RedisWithSlidingWindow)
      .jtSlidingWindow(
        key,
        windowStart,
        now,
        config.maxRequests,
        member,
        config.windowSeconds,
      );

    const allowed = allowedFlag === 1;

    return {
      allowed,
      remaining: Math.max(0, config.maxRequests - countAfter),
      resetIn: config.windowSeconds,
    };
  } catch (err) {
    console.warn('[RateLimit] Redis error, falling back to memory:', err);
    return checkMemoryRateLimit(key, config);
  }
}

function checkMemoryRateLimit(
  key: string,
  config: RateLimitConfig
): RateLimitResult {
  const now = Date.now();
  const windowMs = config.windowSeconds * 1000;
  const limit = memoryLimits.get(key);

  if (!limit || now > limit.resetAt) {
    memoryLimits.set(key, { count: 1, resetAt: now + windowMs });
    return {
      allowed: true,
      remaining: config.maxRequests - 1,
      resetIn: config.windowSeconds,
    };
  }

  if (limit.count >= config.maxRequests) {
    return {
      allowed: false,
      remaining: 0,
      resetIn: Math.ceil((limit.resetAt - now) / 1000),
    };
  }

  limit.count++;
  return {
    allowed: true,
    remaining: config.maxRequests - limit.count,
    resetIn: Math.ceil((limit.resetAt - now) / 1000),
  };
}

/**
 * Increment a counter and check if it exceeds the limit. Used for
 * volume-based limits (e.g., daily upload bytes). Opaque identifier
 * variant — see `checkIpVolumeLimit` for IP-keyed counters.
 */
export async function checkVolumeLimit(
  identifier: string,
  config: VolumeLimitConfig
): Promise<RateLimitResult> {
  const key = `volume:${config.prefix}:${identifier}`;
  const redisClient = getRedis();

  if (redisClient && redisAvailable) {
    return checkRedisVolumeLimit(redisClient, key, config);
  }

  return checkMemoryVolumeLimit(key, config);
}

/**
 * IP-keyed volume counter. Like `checkIpRateLimit` but for byte-counters
 * (monthly upload volume). See `checkIpRateLimit` for the salt rationale.
 */
export async function checkIpVolumeLimit(
  ipContext: IpContext,
  config: VolumeLimitConfig
): Promise<RateLimitResult> {
  const identifier = await ipRateLimitIdentifier(ipContext);
  return checkVolumeLimit(identifier, config);
}

/**
 * Tier-aware volume counter. Per-user when a session is attached,
 * per-IP otherwise. The matching primitive to
 * `checkAuthedOrIpRateLimit` for byte-counters.
 */
export async function checkAuthedOrIpVolumeLimit(
  userId: string | null | undefined,
  ipContext: IpContext,
  config: VolumeLimitConfig
): Promise<RateLimitResult> {
  return userId
    ? checkVolumeLimit(userId, config)
    : checkIpVolumeLimit(ipContext, config);
}

/**
 * Decrement a volume counter (bytes) — the inverse of
 * `checkVolumeLimit`'s increment. Caller passes the same `identifier`
 * and `config.prefix` used when reserving; only `bytes` is consumed
 * from `config`.
 *
 * Clamped to zero so a bug in caller code can never create a
 * free-volume exploit by over-releasing.
 */
export async function releaseVolumeLimit(
  identifier: string,
  config: VolumeLimitConfig,
  bytes: number,
): Promise<void> {
  if (bytes <= 0) return;
  const key = `volume:${config.prefix}:${identifier}`;
  const redisClient = getRedis();

  if (redisClient && redisAvailable) {
    try {
      // Read-then-write rather than DECRBY so we can clamp to zero. The
      // race against a concurrent CHECK is benign — worst case the
      // CHECK saw a slightly higher counter than reality and rejected,
      // which is fail-closed.
      const current = await redisClient.get(key);
      const currentValue = current ? parseInt(current, 10) : 0;
      const next = Math.max(0, currentValue - bytes);
      if (next === 0) {
        await redisClient.del(key);
      } else {
        const ttl = await redisClient.ttl(key);
        if (ttl > 0) {
          await redisClient.set(key, String(next), "EX", ttl);
        } else {
          await redisClient.set(key, String(next), "EX", config.windowSeconds);
        }
      }
      return;
    } catch (err) {
      console.warn("[RateLimit] Redis error in volume release, falling back to memory:", err);
    }
  }

  const counter = memoryCounters.get(key);
  if (!counter || Date.now() > counter.resetAt) return;
  counter.value = Math.max(0, counter.value - bytes);
  if (counter.value === 0) {
    memoryCounters.delete(key);
  }
}

/**
 * Tier-aware wrapper around `releaseVolumeLimit`. Mirrors the
 * authed-or-IP pattern so the call site doesn't pick the right
 * primitive itself.
 */
export async function releaseAuthedOrIpVolumeLimit(
  userId: string | null | undefined,
  ipContext: IpContext,
  config: VolumeLimitConfig,
  bytes: number,
): Promise<void> {
  if (userId) {
    return releaseVolumeLimit(userId, config, bytes);
  }
  const identifier = await ipRateLimitIdentifier(ipContext);
  return releaseVolumeLimit(identifier, config, bytes);
}

/**
 * Read a rate-limit counter without incrementing — used by the usage
 * endpoint to surface "X of Y used" without consuming a slot. Returns
 * `{ used, resetIn }` rather than the `RateLimitResult` shape because
 * the cap is supplied by the caller (tier-resolved), not by the
 * limiter config.
 */
export async function peekRateLimit(
  identifier: string,
  config: RateLimitConfig
): Promise<{ used: number; resetIn: number }> {
  const key = `ratelimit:${config.prefix}:${identifier}`;
  const redisClient = getRedis();

  if (redisClient && redisAvailable) {
    try {
      const now = Math.floor(Date.now() / 1000);
      const windowStart = now - config.windowSeconds;
      // Prune expired entries first so the count reflects the live window.
      await redisClient.zremrangebyscore(key, 0, windowStart);
      const used = await redisClient.zcard(key);
      const ttl = await redisClient.ttl(key);
      return { used, resetIn: ttl > 0 ? ttl : config.windowSeconds };
    } catch (err) {
      console.warn("[RateLimit] Redis error in peek, falling back to memory:", err);
    }
  }

  const limit = memoryLimits.get(key);
  if (!limit || Date.now() > limit.resetAt) {
    return { used: 0, resetIn: config.windowSeconds };
  }
  return {
    used: limit.count,
    resetIn: Math.ceil((limit.resetAt - Date.now()) / 1000),
  };
}

/**
 * Read a volume counter (bytes) without incrementing. Companion to
 * `peekRateLimit` for `checkVolumeLimit`-tracked windows.
 */
export async function peekVolumeLimit(
  identifier: string,
  config: VolumeLimitConfig
): Promise<{ usedBytes: number; resetIn: number }> {
  const key = `volume:${config.prefix}:${identifier}`;
  const redisClient = getRedis();

  if (redisClient && redisAvailable) {
    try {
      const current = await redisClient.get(key);
      const usedBytes = current ? parseInt(current, 10) : 0;
      const ttl = await redisClient.ttl(key);
      return { usedBytes, resetIn: ttl > 0 ? ttl : config.windowSeconds };
    } catch (err) {
      console.warn("[RateLimit] Redis error in volume peek, falling back to memory:", err);
    }
  }

  const counter = memoryCounters.get(key);
  if (!counter || Date.now() > counter.resetAt) {
    return { usedBytes: 0, resetIn: config.windowSeconds };
  }
  return {
    usedBytes: counter.value,
    resetIn: Math.ceil((counter.resetAt - Date.now()) / 1000),
  };
}

async function checkRedisVolumeLimit(
  redis: Redis,
  key: string,
  config: VolumeLimitConfig
): Promise<RateLimitResult> {
  try {
    // Get current value
    const current = await redis.get(key);
    const currentValue = current ? parseInt(current, 10) : 0;

    // Check if adding increment would exceed limit
    if (currentValue + config.increment > config.maxBytes) {
      const ttl = await redis.ttl(key);
      return {
        allowed: false,
        remaining: Math.max(0, config.maxBytes - currentValue),
        resetIn: ttl > 0 ? ttl : config.windowSeconds,
      };
    }

    // Increment the counter
    const multi = redis.multi();
    multi.incrby(key, config.increment);
    multi.expire(key, config.windowSeconds);
    await multi.exec();

    return {
      allowed: true,
      remaining: Math.max(0, config.maxBytes - currentValue - config.increment),
      resetIn: config.windowSeconds,
    };
  } catch (err) {
    console.warn('[RateLimit] Redis error in volume check:', err);
    return checkMemoryVolumeLimit(key, config);
  }
}

function checkMemoryVolumeLimit(
  key: string,
  config: VolumeLimitConfig
): RateLimitResult {
  const now = Date.now();
  const windowMs = config.windowSeconds * 1000;
  const counter = memoryCounters.get(key);

  if (!counter || now > counter.resetAt) {
    if (config.increment > config.maxBytes) {
      return {
        allowed: false,
        remaining: config.maxBytes,
        resetIn: config.windowSeconds,
      };
    }
    memoryCounters.set(key, { value: config.increment, resetAt: now + windowMs });
    return {
      allowed: true,
      remaining: config.maxBytes - config.increment,
      resetIn: config.windowSeconds,
    };
  }

  if (counter.value + config.increment > config.maxBytes) {
    return {
      allowed: false,
      remaining: Math.max(0, config.maxBytes - counter.value),
      resetIn: Math.ceil((counter.resetAt - now) / 1000),
    };
  }

  counter.value += config.increment;
  return {
    allowed: true,
    remaining: Math.max(0, config.maxBytes - counter.value),
    resetIn: Math.ceil((counter.resetAt - now) / 1000),
  };
}

// Bumped whenever the rate-limit keyspace changes shape. On startup,
// if Redis doesn't record the current version, we flush all rate-limit
// keys once and then set the version so subsequent boots no-op.
const RATELIMIT_KEYSPACE_VERSION = '2';
const RATELIMIT_VERSION_KEY = 'ratelimit:keyspace-version';

/**
 * One-shot startup flush of all rate-limit keys, gated by a
 * Redis-stored keyspace version. Called once on boot; subsequent
 * boots are no-ops until the version constant is bumped again.
 */
export async function flushLegacyRateLimitKeys(): Promise<number> {
  const redisClient = getRedis();
  if (!redisClient || !redisAvailable) {
    // Memory-only mode has no cross-restart state, so nothing to flush.
    return 0;
  }

  const current = await redisClient.get(RATELIMIT_VERSION_KEY);
  if (current === RATELIMIT_KEYSPACE_VERSION) {
    return 0;
  }

  let deleted = 0;
  for (const pattern of ['ratelimit:*', 'volume:*']) {
    let cursor = '0';
    do {
      const [next, keys] = await redisClient.scan(cursor, 'MATCH', pattern, 'COUNT', 1000);
      cursor = next;
      const targets = keys.filter((k) => k !== RATELIMIT_VERSION_KEY);
      if (targets.length > 0) {
        deleted += await redisClient.del(...targets);
      }
    } while (cursor !== '0');
  }

  await redisClient.set(RATELIMIT_VERSION_KEY, RATELIMIT_KEYSPACE_VERSION);
  return deleted;
}

// Pre-configured rate limiters
const DAY_SECONDS = 24 * 60 * 60;
const MONTH_SECONDS = 30 * DAY_SECONDS;
const HOUR_SECONDS = 60 * 60;

export const rateLimiters = {
  // Per-minute limits
  validate: { prefix: 'validate', windowSeconds: 60, maxRequests: env.RATE_LIMIT_VALIDATE_PER_MINUTE },
  upload: { prefix: 'upload', windowSeconds: 60, maxRequests: env.RATE_LIMIT_UPLOADS_PER_MINUTE },
  download: { prefix: 'download', windowSeconds: 60, maxRequests: env.RATE_LIMIT_DOWNLOADS_PER_MINUTE },
  password: { prefix: 'password', windowSeconds: 60, maxRequests: 5 },

  // Daily limits
  dailyTransfers: { prefix: 'daily-transfers', windowSeconds: DAY_SECONDS, maxRequests: env.RATE_LIMIT_DAILY_TRANSFERS },
  dailyDownloads: { prefix: 'daily-downloads', windowSeconds: DAY_SECONDS, maxRequests: env.RATE_LIMIT_DAILY_DOWNLOADS },

  // Monthly volume limit (bytes)
  monthlyUploadVolume: { prefix: 'monthly-upload-volume', windowSeconds: MONTH_SECONDS, maxBytes: env.RATE_LIMIT_MONTHLY_UPLOAD_GB },

  // Auth — magic-link request + verify.
  authRequestPerEmail: { prefix: 'auth-request-email', windowSeconds: HOUR_SECONDS, maxRequests: env.RATE_LIMIT_AUTH_REQUEST_PER_HOUR_PER_EMAIL },
  authRequestPerIp: { prefix: 'auth-request-ip', windowSeconds: HOUR_SECONDS, maxRequests: env.RATE_LIMIT_AUTH_REQUEST_PER_HOUR_PER_IP },
  authVerifyPerIp: { prefix: 'auth-verify-ip', windowSeconds: 60, maxRequests: env.RATE_LIMIT_AUTH_VERIFY_PER_MINUTE_PER_IP },

  // Pass checkout opens a Polar session per call; status is polled by the
  // buyer's tab while they pay.
  passCheckout: { prefix: 'pass-checkout', windowSeconds: HOUR_SECONDS, maxRequests: 10 },
  passStatus: { prefix: 'pass-status', windowSeconds: 60, maxRequests: 40 },

  // Per-user limits on /me/transfers
  meTransfersList: { prefix: 'me-transfers-list', windowSeconds: 60, maxRequests: 60 },
  meTransfersDelete: { prefix: 'me-transfers-delete', windowSeconds: 60, maxRequests: 10 },
  // Title rewrites — generous for legitimate edits, tight enough to
  // bound mass-rewrite under session compromise.
  meTransferTitle: { prefix: 'me-transfer-title', windowSeconds: 60, maxRequests: 30 },

  // Account erasure and export are intentionally strict — both are
  // expensive operations that no legitimate user invokes in bursts.
  accountDelete: { prefix: 'account-delete', windowSeconds: HOUR_SECONDS, maxRequests: 5 },
  accountExport: { prefix: 'account-export', windowSeconds: HOUR_SECONDS, maxRequests: 3 },

  // Vault writes — setup is one-shot; password/phrase rewrap is gated
  // to dampen brute-force-by-reupload of wrap blobs and accidental
  // double-submits from the UI.
  vaultSetup: { prefix: 'vault-setup', windowSeconds: HOUR_SECONDS, maxRequests: 5 },
  vaultPasswordChange: { prefix: 'vault-password-change', windowSeconds: HOUR_SECONDS, maxRequests: 10 },
  vaultPhraseRegenerate: { prefix: 'vault-phrase-regen', windowSeconds: HOUR_SECONDS, maxRequests: 5 },
} as const;
