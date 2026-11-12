CREATE TABLE "vault_items" (
	"id" varchar(21) PRIMARY KEY NOT NULL,
	"user_id" varchar(21) NOT NULL,
	"kind" varchar(32) NOT NULL,
	"ciphertext" "bytea" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "public_key" "bytea";--> statement-breakpoint
ALTER TABLE "vault_items" ADD CONSTRAINT "vault_items_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "vault_items_user_kind_unique" ON "vault_items" USING btree ("user_id","kind");