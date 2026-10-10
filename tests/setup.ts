// Global test setup. Runs once before any test file is imported (configured
// via `bunfig.toml` preload). Responsibilities:
//
//   1. Force DATABASE_URL to the test database so production data is never
//      touched. The operator must export TEST_DATABASE_URL; we refuse to run
//      otherwise.
//   2. Stub the R2 client so tests don't make real network calls. Real R2
//      coverage lives in scripts/auth-smoke.ts (out-of-process).
//   3. Apply the migration journal to the test database.
//
// All in-process integration tests rely on this preload being active. Each
// test file is expected to call `resetDb()` in `beforeEach` for isolation.

import { mock } from "bun:test";

const testDbUrl = process.env.TEST_DATABASE_URL;
if (!testDbUrl) {
  throw new Error(
    "TEST_DATABASE_URL must be set to run the test suite. " +
      "Point it at a disposable Postgres database (NOT the dev DB). " +
      "Example: TEST_DATABASE_URL=postgresql://user:pass@localhost:5432/tessil_test bun test",
  );
}
if (testDbUrl === process.env.DATABASE_URL) {
  throw new Error(
    "TEST_DATABASE_URL must differ from DATABASE_URL. The test harness " +
      "truncates all tables between tests; pointing at the dev/prod DB would destroy data.",
  );
}

process.env.DATABASE_URL = testDbUrl;
// Tests run against a non-production env regardless of caller env.
process.env.NODE_ENV = "test";
// Pin a known APP_URL for Origin checks.
process.env.APP_URL = process.env.APP_URL ?? "http://localhost:5173";
process.env.CORS_ORIGINS = process.env.CORS_ORIGINS ?? "http://localhost:5173";
// R2 vars are required by env.ts but never used (the module is stubbed below).
process.env.R2_ENDPOINT = process.env.R2_ENDPOINT ?? "http://test.invalid";
process.env.R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID ?? "test";
process.env.R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY ?? "test";
process.env.R2_BUCKET_NAME = process.env.R2_BUCKET_NAME ?? "test";
// Force the email service into log-only mode so tests never hit Scaleway TEM,
// even when the operator's .env carries live credentials.
process.env.SCW_TEM_PROJECT_ID = "";
process.env.SCW_TEM_SECRET_KEY = "";
// Enable the session-anomaly email path so the send branch is exercised in
// tests. Cases that care about the call mock `email.service` to spy on it;
// cases that don't never trigger detection at all.
process.env.ENABLE_SESSION_ANOMALY_EMAIL = "true";
// Polar webhook signature verification needs a non-empty secret. Tests
// that exercise the webhook path use this exact value to sign their
// crafted payloads (see tests/integration/billing-webhook.test.ts).
process.env.POLAR_WEBHOOK_SECRET = "whsec_dGVzdHdlYmhvb2tzZWNyZXQ";
// Test fixtures for the checkout endpoint. The Polar API is mocked in
// tests that exercise checkout/portal — these env values just need to be
// non-empty so polar.service's lazy client init doesn't throw on import.
process.env.POLAR_ACCESS_TOKEN = process.env.POLAR_ACCESS_TOKEN ?? "polar_test_token";
process.env.POLAR_PRODUCT_ID_MONTHLY = process.env.POLAR_PRODUCT_ID_MONTHLY ?? "prod_test_monthly";
process.env.POLAR_PRODUCT_ID_ANNUAL = process.env.POLAR_PRODUCT_ID_ANNUAL ?? "prod_test_annual";
process.env.POLAR_PRODUCT_ID_PASS = process.env.POLAR_PRODUCT_ID_PASS ?? "prod_test_pass";
// The paywall is opt-in per test file (tests/integration/paywall.test.ts
// flips env.PAYWALL_ENABLED); every other suite runs with it off.
process.env.PAYWALL_ENABLED = "false";

// Default mock: presigned-URL handouts succeed, deletes are no-ops, and
// HeadObject pretends the upload landed at the size we have on the file
// row in the DB. Tests that need to exercise the missing-upload or
// size-mismatch failure paths (audit doc 25 §A.3) call `mock.module` again
// in their own file to override `headObject`, then re-apply `defaultR2Mock`
// in `afterEach` to avoid leaking the override into later test files (Bun
// runs them in the same process).
import { defaultR2Mock } from "./helpers/r2-mock";
mock.module("../src/services/r2.service", () => defaultR2Mock());

// Migrations run lazily on first import of the db helper. Keeping the
// migration side-effect out of this file lets tests opt in explicitly.
