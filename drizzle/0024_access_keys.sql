CREATE TABLE "devices" (
	"id" varchar(21) PRIMARY KEY NOT NULL,
	"user_id" varchar(21),
	"name" varchar(80) NOT NULL,
	"public_key" "bytea" NOT NULL,
	"token_hash" varchar(64) NOT NULL,
	"pairing_hash" varchar(64),
	"pairing_expires_at" timestamp with time zone,
	"permissions" text[] DEFAULT '{}'::text[] NOT NULL,
	"approved_at" timestamp with time zone,
	"expires_at" timestamp with time zone,
	"last_used_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "transfers" ADD COLUMN "device_id" varchar(21);--> statement-breakpoint
ALTER TABLE "devices" ADD CONSTRAINT "devices_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "devices_token_hash_unique" ON "devices" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "devices_pairing_hash_idx" ON "devices" USING btree ("pairing_hash");--> statement-breakpoint
CREATE INDEX "devices_user_id_idx" ON "devices" USING btree ("user_id");