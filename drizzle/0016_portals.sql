CREATE TABLE "portal_members" (
	"portal_id" varchar(21) NOT NULL,
	"user_id" varchar(21) NOT NULL,
	"role" varchar(16) NOT NULL,
	"key_version" integer DEFAULT 1 NOT NULL,
	"sealed_keys" "bytea" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "portals" (
	"id" varchar(21) PRIMARY KEY NOT NULL,
	"owner_id" varchar(21) NOT NULL,
	"public_bundle" "bytea" NOT NULL,
	"key_version" integer DEFAULT 1 NOT NULL,
	"is_disabled" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "portal_members" ADD CONSTRAINT "portal_members_portal_id_portals_id_fk" FOREIGN KEY ("portal_id") REFERENCES "public"."portals"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "portal_members" ADD CONSTRAINT "portal_members_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "portals" ADD CONSTRAINT "portals_owner_id_users_id_fk" FOREIGN KEY ("owner_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "portal_members_portal_user_unique" ON "portal_members" USING btree ("portal_id","user_id");--> statement-breakpoint
CREATE INDEX "portal_members_user_id_idx" ON "portal_members" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "portals_owner_id_idx" ON "portals" USING btree ("owner_id");