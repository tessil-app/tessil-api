import { drizzle } from 'drizzle-orm/postgres-js';
import { migrate } from 'drizzle-orm/postgres-js/migrator';
import postgres from 'postgres';
import { env } from '../config/env';

function roleOf(url: string): string {
  return decodeURIComponent(new URL(url).username);
}

function quoteIdent(name: string): string {
  return `"${name.replaceAll('"', '""')}"`;
}

// The API connects as a role that cannot change the schema, while
// migrations run as an admin role. A table the admin creates belongs to
// the admin, and the API role cannot read it until told so. Without this
// step every migration that adds a table leaves the API answering 500 on
// it until someone fixes the grants by hand.
//
// Grants only what is missing, so tables the app can already use (and that
// this role may not own) are left alone.
async function grantToAppRole(client: postgres.Sql, appRole: string): Promise<void> {
  const role = quoteIdent(appRole);

  const tables = await client<{ tablename: string }[]>`
    SELECT tablename FROM pg_tables
    WHERE schemaname = 'public'
      AND NOT has_table_privilege(${appRole}, format('%I.%I', schemaname, tablename), 'SELECT, INSERT, UPDATE, DELETE')
  `;
  for (const { tablename } of tables) {
    await client.unsafe(
      `GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.${quoteIdent(tablename)} TO ${role}`,
    );
    console.log(`Granted ${appRole} access to ${tablename}`);
  }

  const sequences = await client<{ sequencename: string }[]>`
    SELECT sequencename FROM pg_sequences
    WHERE schemaname = 'public'
      AND NOT has_sequence_privilege(${appRole}, format('%I.%I', schemaname, sequencename), 'USAGE')
  `;
  for (const { sequencename } of sequences) {
    await client.unsafe(
      `GRANT USAGE, SELECT ON SEQUENCE public.${quoteIdent(sequencename)} TO ${role}`,
    );
  }

  // And for whatever this role creates next, should this step ever be skipped.
  await client.unsafe(
    `ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ${role}`,
  );
  await client.unsafe(
    `ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO ${role}`,
  );
}

async function runMigrations() {
  // Migrations are DDL, so they need the admin role. The least-privilege
  // app role (used by the running API via env.DATABASE_URL) has no DDL
  // grant. MIGRATION_DATABASE_URL lets the deploy hook point this step at
  // the admin connection without changing how the daemon connects. Falls
  // back to DATABASE_URL for local/dev where one role does everything.
  const migrationUrl = process.env.MIGRATION_DATABASE_URL ?? env.DATABASE_URL;
  const client = postgres(migrationUrl, { max: 1, onnotice: () => {} });
  const db = drizzle(client);

  console.log('Running migrations...');
  await migrate(db, { migrationsFolder: './drizzle' });
  console.log('Migrations complete!');

  const appRole = roleOf(env.DATABASE_URL);
  if (appRole && appRole !== roleOf(migrationUrl)) {
    // A failure here stops the deploy before the API restarts: new code on
    // tables it cannot read is worse than old code that never asks for them.
    await grantToAppRole(client, appRole);
    console.log(`Access for ${appRole} is up to date.`);
  }

  await client.end();
  process.exit(0);
}

runMigrations().catch((err) => {
  console.error('Migration failed:', err);
  process.exit(1);
});
