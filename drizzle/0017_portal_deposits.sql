-- A portal made before this column existed gets an empty hash, which no
-- token matches: it stays listed but cannot take deposits.
ALTER TABLE "portals" ADD COLUMN "deposit_token_hash" varchar(64) DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE "portals" ALTER COLUMN "deposit_token_hash" DROP DEFAULT;--> statement-breakpoint
ALTER TABLE "transfers" ADD COLUMN "portal_id" varchar(21);--> statement-breakpoint
ALTER TABLE "transfers" ADD COLUMN "sealed_key" "bytea";--> statement-breakpoint
ALTER TABLE "transfers" ADD CONSTRAINT "transfers_portal_id_portals_id_fk" FOREIGN KEY ("portal_id") REFERENCES "public"."portals"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "transfers_portal_id_idx" ON "transfers" USING btree ("portal_id","created_at") WHERE "transfers"."portal_id" IS NOT NULL;