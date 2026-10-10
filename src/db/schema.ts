import { sql } from 'drizzle-orm';
import { pgTable, varchar, bigint, timestamp, integer, boolean, serial, uniqueIndex, index, text, jsonb, customType } from 'drizzle-orm/pg-core';

// Drizzle ORM ships a `bytea` type only via the experimental column builder
// in some versions. customType is portable and lets us round-trip Uint8Array.
const bytea = customType<{ data: Uint8Array; default: false }>({
  dataType() {
    return 'bytea';
  },
});

export const transfers = pgTable('transfers', {
  id: varchar('id', { length: 21 }).primaryKey(), // nanoid
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  downloadCount: integer('download_count').default(0).notNull(),
  maxDownloads: integer('max_downloads'), // NULL = unlimited
  isDeleted: boolean('is_deleted').default(false).notNull(),
  isCompleted: boolean('is_completed').default(false).notNull(),
  passwordHash: varchar('password_hash', { length: 255 }), // NULL = no password
  // NULL on anonymous transfers; otherwise references the creator.
  userId: varchar('user_id', { length: 21 }).references(() => users.id),
  // K_transfer wrapped under the owner's per-user K_vault. NULL on
  // anonymous rows; set on every signed-in upload (vault is
  // mandatory). Wire layout: iv(12B) || ciphertext(32B) || tag(16B)
  // = 60 bytes.
  wrappedKey: bytea('wrapped_key'),
  // Optional human-readable title encrypted under the per-transfer fragment
  // key (AES-GCM 256), padded to a 32-byte multiple — same scheme as the
  // filename columns on `files`. Both columns are nullable; either both are
  // set or both are null (invariant enforced at the application layer).
  // See docs/adr/0005-encrypted-transfer-title-scope.md.
  encryptedTitle: varchar('encrypted_title', { length: 1024 }),
  encryptedTitleIv: varchar('encrypted_title_iv', { length: 32 }),
  // Single-transfer pass paying for this upload. Set at creation and
  // cleared when the transfer completes, so a finished transfer keeps
  // no pointer to the payment behind it. No FK: the link is temporary.
  passId: varchar('pass_id', { length: 21 }),
}, (table) => ({
  // Dashboard list: filter by owner, ORDER BY created_at DESC. Postgres can
  // scan the index backwards, so an ascending createdAt covers the sort.
  userIdIdx: index('transfers_user_id_idx')
    .on(table.userId, table.createdAt)
    .where(sql`${table.userId} IS NOT NULL`),
  // The three cleanup sweeps. Each is a partial index matching its query
  // predicate so the 15-minute job never full-scans.
  expiresAtIdx: index('transfers_expires_at_idx')
    .on(table.expiresAt)
    .where(sql`${table.isDeleted} = false`),
  abandonedIdx: index('transfers_abandoned_idx')
    .on(table.createdAt)
    .where(sql`${table.isDeleted} = false AND ${table.isCompleted} = false`),
  softDeletedIdx: index('transfers_soft_deleted_idx')
    .on(table.createdAt)
    .where(sql`${table.isDeleted} = true`),
}));

export const files = pgTable('files', {
  id: varchar('id', { length: 21 }).primaryKey(), // nanoid
  transferId: varchar('transfer_id', { length: 21 }).notNull().references(() => transfers.id),
  r2Key: varchar('r2_key', { length: 255 }).notNull().unique(), // Storage path (column name kept for DB compatibility)
  storageType: varchar('storage_type', { length: 10 }).default('r2').notNull(), // Storage backend; R2 is the only one.
  encryptedName: varchar('encrypted_name', { length: 1024 }).notNull(), // base64 encrypted filename (padded + AES-GCM tag)
  encryptedNameIv: varchar('encrypted_name_iv', { length: 32 }).notNull(),
  fileIv: varchar('file_iv', { length: 32 }).notNull(), // IV for file content encryption
  size: bigint('size', { mode: 'number' }).notNull(),
  mimeType: varchar('mime_type', { length: 127 }),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  isDeleted: boolean('is_deleted').default(false).notNull()
}, (table) => ({
  // Every per-transfer file lookup and the cascade in the cleanup path.
  transferIdIdx: index('files_transfer_id_idx').on(table.transferId),
}));

// Immutable event log — no sensitive data, used for stats. Records survive transfer deletion.
export const transferEvents = pgTable('transfer_events', {
  id: serial('id').primaryKey(),
  event: varchar('event', { length: 32 }).notNull(), // completed | expired | aborted
  transferId: varchar('transfer_id', { length: 21 }).notNull(),
  fileCount: integer('file_count').default(0).notNull(),
  totalBytes: bigint('total_bytes', { mode: 'number' }).default(0).notNull(),
  downloadCount: integer('download_count').default(0).notNull(),
  hasPassword: boolean('has_password').default(false).notNull(),
  maxDownloads: integer('max_downloads'),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

export type TransferEvent = typeof transferEvents.$inferSelect;
export type Transfer = typeof transfers.$inferSelect;
export type NewTransfer = typeof transfers.$inferInsert;
export type File = typeof files.$inferSelect;
export type NewFile = typeof files.$inferInsert;

// Auth — magic-link primary, server-side sessions.
// Email is stored lowercased + trimmed (app-side normalisation) with
// a unique index. Token hashes are hex-encoded SHA-256 (64 chars) —
// never store plaintext bearer tokens.

export const users = pgTable('users', {
  id: varchar('id', { length: 21 }).primaryKey(), // nanoid
  email: varchar('email', { length: 320 }).notNull(), // RFC 5321 max length
  tier: varchar('tier', { length: 16 }).default('free').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  deletedAt: timestamp('deleted_at', { withTimezone: true }),
  // Set when the user finishes the mandatory vault setup flow.
  // The dashboard route guard treats NULL as "redirect to /setup/vault".
  vaultSetupCompletedAt: timestamp('vault_setup_completed_at', { withTimezone: true }),
  // Stable 1:1 identifier with this user on the payment-processor
  // side. Set on first checkout; nullable for users who never reach
  // billing.
  polarCustomerId: varchar('polar_customer_id', { length: 64 }),
}, (table) => ({
  emailUnique: uniqueIndex('users_email_unique').on(table.email),
  polarCustomerIdUnique: uniqueIndex('users_polar_customer_id_unique').on(table.polarCustomerId),
}));

export const sessions = pgTable('sessions', {
  id: varchar('id', { length: 21 }).primaryKey(), // nanoid
  userId: varchar('user_id', { length: 21 }).notNull().references(() => users.id),
  tokenHash: varchar('token_hash', { length: 64 }).notNull(), // hex SHA-256
  // Sliding idle expiry: refreshed to now + 30d on activity.
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  // Hard cap: created_at + 90d. Never refreshed.
  absoluteExpiresAt: timestamp('absolute_expires_at', { withTimezone: true }).notNull(),
  lastSeenAt: timestamp('last_seen_at', { withTimezone: true }).defaultNow().notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  revokedAt: timestamp('revoked_at', { withTimezone: true }),
  // IP minimization: no raw IP stored. `country` is ISO 3166-1
  // alpha-2 or "XX" when unresolvable. `ip_hmac` is
  // HMAC-SHA-256(correlation_secret, raw_ip) at session create,
  // recomputed and compared per request for anomaly detection.
  // `correlation_secret` is wiped on revoke/expiry — once cleared,
  // the stored ip_hmac is permanently un-correlatable to any IP.
  country: varchar('country', { length: 2 }),
  asn: integer('asn'),
  // ASN organisation label (e.g. "KPN") captured at session create
  // so the anomaly-notification email can render a human name
  // without a MaxMind lookup at send time. No extra privacy cost vs
  // the integer above — the integer already identifies the org.
  asnOrg: varchar('asn_org', { length: 255 }),
  ipHmac: bytea('ip_hmac'),
  correlationSecret: bytea('correlation_secret'),
  userAgent: text('user_agent'),
  // Set on sessions minted via a passkey assertion. Drives the
  // "Used to sign in here" hint on /dashboard/settings. NULL for
  // sessions minted via magic link / verify-code.
  authenticatorId: varchar('authenticator_id', { length: 21 })
    .references(() => authenticators.id, { onDelete: 'set null' }),
}, (table) => ({
  tokenHashUnique: uniqueIndex('sessions_token_hash_unique').on(table.tokenHash),
  userIdIdx: index('sessions_user_id_idx').on(table.userId),
}));

export const magicLinkTokens = pgTable('magic_link_tokens', {
  id: varchar('id', { length: 21 }).primaryKey(), // nanoid
  email: varchar('email', { length: 320 }).notNull(),
  tokenHash: varchar('token_hash', { length: 64 }).notNull(), // hex SHA-256
  // Cross-device 6-digit code: hex SHA-256 of zero-padded digits.
  // Bound to pendingSessionId — code alone is insufficient.
  codeHash: varchar('code_hash', { length: 64 }),
  pendingSessionId: varchar('pending_session_id', { length: 21 }),
  codeAttempts: integer('code_attempts').default(0).notNull(),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  consumedAt: timestamp('consumed_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  // No IP column: the token itself is the secret, and layering an
  // IP check would block the legitimate cross-device happy path.
  userAgent: text('user_agent'),
}, (table) => ({
  tokenHashUnique: uniqueIndex('magic_link_tokens_token_hash_unique').on(table.tokenHash),
  emailIdx: index('magic_link_tokens_email_idx').on(table.email),
  pendingSessionIdx: index('magic_link_tokens_pending_session_idx')
    .on(table.pendingSessionId)
    .where(sql`${table.pendingSessionId} IS NOT NULL`),
}));

// 30-day retention; daily purge job clears older rows.
export const authEvents = pgTable('auth_events', {
  id: serial('id').primaryKey(),
  userId: varchar('user_id', { length: 21 }), // nullable — pre-account events log only email
  email: varchar('email', { length: 320 }), // captured for pre-account events
  eventType: varchar('event_type', { length: 32 }).notNull(),
  // IP minimization: no raw IP stored. `ip_correlator` is
  // HMAC-SHA-256 keyed against the active `auth_events` salt (24h
  // rotation). `salt_id` records which salt was active so the
  // correlator can be reproduced within the window; once the salt
  // is purged the correlator becomes permanently un-correlatable.
  country: varchar('country', { length: 2 }),
  asn: integer('asn'),
  ipCorrelator: bytea('ip_correlator'),
  saltId: integer('salt_id').references(() => salts.id, { onDelete: 'set null' }),
  userAgent: text('user_agent'),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
  createdAtIdx: index('auth_events_created_at_idx').on(table.createdAt),
  userIdIdx: index('auth_events_user_id_idx').on(table.userId),
  saltCorrelatorIdx: index('auth_events_salt_correlator_idx').on(table.saltId, table.ipCorrelator),
}));

// Per-purpose rotating salts for IP correlation. `namespace`
// discriminates between rotation cadences:
//
//   - 'auth_events'  — 24h rotation, 30d retention
//   - 'ratelimit'    — 35d rotation, 35d retention
//
// `correlation_secret` for `sessions` is *not* here — sessions
// store their secret per-row because per-session secrets are
// per-row by construction.
export const salts = pgTable('salts', {
  id: serial('id').primaryKey(),
  namespace: varchar('namespace', { length: 32 }).notNull(),
  secret: bytea('secret').notNull(), // 32 random bytes
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  retiredAt: timestamp('retired_at', { withTimezone: true }),
}, (table) => ({
  activeIdx: index('salts_active_idx')
    .on(table.namespace, table.createdAt.desc())
    .where(sql`${table.retiredAt} IS NULL`),
}));

export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;
export type Session = typeof sessions.$inferSelect;
export type NewSession = typeof sessions.$inferInsert;
export type MagicLinkToken = typeof magicLinkTokens.$inferSelect;
export type NewMagicLinkToken = typeof magicLinkTokens.$inferInsert;
export type AuthEvent = typeof authEvents.$inferSelect;
export type NewAuthEvent = typeof authEvents.$inferInsert;
export type Salt = typeof salts.$inferSelect;
export type NewSalt = typeof salts.$inferInsert;

// WebAuthn / passkeys — alternative login factor.
//
// One row per enrolled credential. No attestation statements
// retained (`attestation: none` at registration). `device_type` and
// `backed_up` come from the authenticator data BS/BE flags and
// drive UX badges ("Sync'd" vs "This device"). Passkeys are a login
// factor only — they don't participate in vault key derivation.
export const authenticators = pgTable('authenticators', {
  id: varchar('id', { length: 21 }).primaryKey(), // nanoid
  userId: varchar('user_id', { length: 21 }).notNull().references(() => users.id, { onDelete: 'cascade' }),
  credentialId: bytea('credential_id').notNull(), // raw rawId
  publicKey: bytea('public_key').notNull(), // COSE key blob
  signCount: bigint('sign_count', { mode: 'number' }).default(0).notNull(),
  transports: text('transports').array().default(sql`'{}'::text[]`).notNull(),
  deviceType: varchar('device_type', { length: 16 }).notNull(), // 'singleDevice' | 'multiDevice'
  backedUp: boolean('backed_up').notNull(),
  nickname: varchar('nickname', { length: 64 }),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
}, (table) => ({
  credentialIdUnique: uniqueIndex('authenticators_credential_id_unique').on(table.credentialId),
  userIdIdx: index('authenticators_user_id_idx').on(table.userId),
}));

// One row per outstanding ceremony. `user_id` is nullable so
// resident-credential authentication (username-less) can issue a challenge
// before we know who is signing in. 5-min TTL; daily purge consumes
// expired rows via the existing cleanup job.
export const webauthnChallenges = pgTable('webauthn_challenges', {
  id: varchar('id', { length: 21 }).primaryKey(), // nanoid
  userId: varchar('user_id', { length: 21 }).references(() => users.id, { onDelete: 'cascade' }),
  challenge: bytea('challenge').notNull(), // 32 random bytes
  kind: varchar('kind', { length: 16 }).notNull(), // 'registration' | 'authentication'
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  consumedAt: timestamp('consumed_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
  userIdIdx: index('webauthn_challenges_user_id_idx').on(table.userId),
  expiresAtIdx: index('webauthn_challenges_expires_at_idx').on(table.expiresAt),
}));

// Per-user vault metadata. 1:1 with users.
// Holds two AES-GCM wraps of the same random per-user K_vault:
//   - wrap_password  = AES-GCM(KEK_password, K_vault)
//     KEK_password = Argon2id(password, salt_password)
//   - wrap_phrase    = AES-GCM(KEK_phrase, K_vault)
//     KEK_phrase   = Argon2id(phrase_entropy, salt_phrase)
// Either wrap decrypts the same K_vault. kdf_version is reserved for future
// Argon2id parameter bumps — re-wrap lazily on next unlock.
// Wire layout for the wrap columns: iv(12B) || ciphertext(32B) || tag(16B) = 60 bytes.
// Salts are 16 random bytes (Argon2id input salt, distinct per wrap).
export const userVaults = pgTable('user_vaults', {
  userId: varchar('user_id', { length: 21 })
    .primaryKey()
    .references(() => users.id, { onDelete: 'cascade' }),
  saltPassword: bytea('salt_password').notNull(),
  saltPhrase: bytea('salt_phrase').notNull(),
  wrapPassword: bytea('wrap_password').notNull(),
  wrapPhrase: bytea('wrap_phrase').notNull(),
  kdfVersion: integer('kdf_version').default(1).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  passwordChangedAt: timestamp('password_changed_at', { withTimezone: true }),
  phraseRegeneratedAt: timestamp('phrase_regenerated_at', { withTimezone: true }),
});

export type Authenticator = typeof authenticators.$inferSelect;
export type NewAuthenticator = typeof authenticators.$inferInsert;
export type WebauthnChallenge = typeof webauthnChallenges.$inferSelect;
export type NewWebauthnChallenge = typeof webauthnChallenges.$inferInsert;
export type UserVault = typeof userVaults.$inferSelect;
export type NewUserVault = typeof userVaults.$inferInsert;

// Pro subscriptions. Separate table rather than columns on `users`
// so history survives cancel + re-subscribe cycles and maps cleanly
// onto Polar's subscription-centric webhook model. `users.tier`
// stays as the denormalised cache for hot-path "is this user Pro?"
// reads; webhook handlers maintain it from the canonical row here.
export const subscriptions = pgTable('subscriptions', {
  id: varchar('id', { length: 21 }).primaryKey(), // nanoid
  userId: varchar('user_id', { length: 21 }).notNull().references(() => users.id, { onDelete: 'cascade' }),
  polarSubscriptionId: varchar('polar_subscription_id', { length: 64 }).notNull(),
  // 'active' | 'past_due' | 'canceled' | 'trialing' | 'incomplete'.
  // Pro tier reflects { active | past_due | trialing }; 'canceled' is
  // terminal and flips users.tier to 'free'.
  status: varchar('status', { length: 16 }).notNull(),
  currentPeriodEnd: timestamp('current_period_end', { withTimezone: true }).notNull(),
  // True between the user clicking Cancel and the period actually ending.
  // Tier stays 'pro' until current_period_end passes.
  cancelAtPeriodEnd: boolean('cancel_at_period_end').default(false).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
  // Set when the terminal `subscription.canceled` webhook arrives.
  canceledAt: timestamp('canceled_at', { withTimezone: true }),
}, (table) => ({
  polarSubscriptionIdUnique: uniqueIndex('subscriptions_polar_subscription_id_unique')
    .on(table.polarSubscriptionId),
  userIdIdx: index('subscriptions_user_id_idx').on(table.userId),
  // Load-bearing invariant: at most one in-flight subscription per user.
  // Catches duplicate `subscription.created` webhook delivery at the DB
  // layer even if the application handler dedup mis-fires.
  oneLivePerUser: uniqueIndex('subscriptions_one_live_per_user')
    .on(table.userId)
    .where(sql`${table.status} IN ('active', 'past_due', 'trialing')`),
}));

// Polar webhook event audit. One row per received event, dedup'd on
// `polarEventId` (UNIQUE) so duplicate deliveries no-op. Raw payload
// stored for forensics — Polar retains canonical invoice records for
// 7-year EU tax compliance, our 90-day local retention is operational
// only (matches auth_events convention).
export const billingEvents = pgTable('billing_events', {
  id: varchar('id', { length: 21 }).primaryKey(), // nanoid
  polarEventId: varchar('polar_event_id', { length: 64 }).notNull(),
  polarEventType: varchar('polar_event_type', { length: 64 }).notNull(),
  // FK to subscriptions.id when the event maps to a known subscription;
  // NULL for events that arrive before we've inserted the corresponding
  // subscription row (rare — handler upserts on receive).
  subscriptionId: varchar('subscription_id', { length: 21 })
    .references(() => subscriptions.id, { onDelete: 'set null' }),
  rawPayload: jsonb('raw_payload').notNull(),
  receivedAt: timestamp('received_at', { withTimezone: true }).defaultNow().notNull(),
  // Set when handler completes successfully. NULL means in-flight or
  // failed — the `error` column carries the failure message in the
  // latter case.
  processedAt: timestamp('processed_at', { withTimezone: true }),
  error: text('error'),
}, (table) => ({
  polarEventIdUnique: uniqueIndex('billing_events_polar_event_id_unique')
    .on(table.polarEventId),
  subscriptionIdIdx: index('billing_events_subscription_id_idx').on(table.subscriptionId),
}));

// One-time passes for the pay-to-send experiment. The browser holds a
// random token and we store only its SHA-256, so a database read does
// not yield usable passes. `polarCheckoutId` lets us ask Polar whether
// the checkout was paid; nothing here references the transfer it bought.
export const transferPasses = pgTable('transfer_passes', {
  id: varchar('id', { length: 21 }).primaryKey(), // nanoid
  tokenHash: varchar('token_hash', { length: 64 }).notNull(),
  polarCheckoutId: varchar('polar_checkout_id', { length: 64 }).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  paidAt: timestamp('paid_at', { withTimezone: true }),
  consumedAt: timestamp('consumed_at', { withTimezone: true }),
}, (table) => ({
  tokenHashUnique: uniqueIndex('transfer_passes_token_hash_unique').on(table.tokenHash),
  polarCheckoutIdUnique: uniqueIndex('transfer_passes_polar_checkout_id_unique')
    .on(table.polarCheckoutId),
  // Sweep of checkouts that were opened and never paid.
  unpaidIdx: index('transfer_passes_unpaid_idx')
    .on(table.createdAt)
    .where(sql`${table.paidAt} IS NULL`),
}));

export type TransferPass = typeof transferPasses.$inferSelect;
export type Subscription = typeof subscriptions.$inferSelect;
export type NewSubscription = typeof subscriptions.$inferInsert;
export type BillingEvent = typeof billingEvents.$inferSelect;
export type NewBillingEvent = typeof billingEvents.$inferInsert;
