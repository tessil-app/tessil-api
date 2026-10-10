CREATE TABLE "transfer_passes" (
	"id" varchar(21) PRIMARY KEY NOT NULL,
	"token_hash" varchar(64) NOT NULL,
	"polar_checkout_id" varchar(64) NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"paid_at" timestamp with time zone,
	"consumed_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "transfers" ADD COLUMN "pass_id" varchar(21);--> statement-breakpoint
CREATE UNIQUE INDEX "transfer_passes_token_hash_unique" ON "transfer_passes" USING btree ("token_hash");--> statement-breakpoint
CREATE UNIQUE INDEX "transfer_passes_polar_checkout_id_unique" ON "transfer_passes" USING btree ("polar_checkout_id");--> statement-breakpoint
CREATE INDEX "transfer_passes_unpaid_idx" ON "transfer_passes" USING btree ("created_at") WHERE "transfer_passes"."paid_at" IS NULL;