// Test-DB lifecycle helpers. Migrations run once per test process; `resetDb`
// truncates user-data tables between tests for isolation.

import { sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/postgres-js";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import postgres from "postgres";
import { db } from "../../src/db";

let migrationsApplied = false;

export async function ensureMigrations(): Promise<void> {
  if (migrationsApplied) return;
  const client = postgres(process.env.DATABASE_URL!, { max: 1 });
  const migrator = drizzle(client);
  await migrate(migrator, { migrationsFolder: "./drizzle" });
  await client.end();
  migrationsApplied = true;
}

// Ordered to satisfy FKs. transfers must drop before users (FK in transfers).
const TABLES_TO_TRUNCATE = [
  "files",
  "transfer_events",
  "transfers",
  "transfer_passes",
  "sessions",
  "magic_link_tokens",
  "auth_events",
  "user_vaults",
  "webauthn_challenges",
  "authenticators",
  "users",
] as const;

export async function resetDb(): Promise<void> {
  await db.execute(
    sql.raw(`TRUNCATE TABLE ${TABLES_TO_TRUNCATE.join(", ")} RESTART IDENTITY CASCADE`),
  );
}
