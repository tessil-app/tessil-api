CREATE TABLE "vault_passkey_wraps" (
	"authenticator_id" varchar(21) PRIMARY KEY NOT NULL,
	"user_id" varchar(21) NOT NULL,
	"prf_salt" "bytea" NOT NULL,
	"wrap" "bytea" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "vault_passkey_wraps" ADD CONSTRAINT "vault_passkey_wraps_authenticator_id_authenticators_id_fk" FOREIGN KEY ("authenticator_id") REFERENCES "public"."authenticators"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vault_passkey_wraps" ADD CONSTRAINT "vault_passkey_wraps_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "vault_passkey_wraps_user_id_idx" ON "vault_passkey_wraps" USING btree ("user_id");