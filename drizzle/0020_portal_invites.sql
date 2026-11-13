CREATE TABLE "portal_invites" (
	"id" varchar(21) PRIMARY KEY NOT NULL,
	"portal_id" varchar(21) NOT NULL,
	"email" varchar(320) NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "portal_invites" ADD CONSTRAINT "portal_invites_portal_id_portals_id_fk" FOREIGN KEY ("portal_id") REFERENCES "public"."portals"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "portal_invites_portal_email_unique" ON "portal_invites" USING btree ("portal_id","email");--> statement-breakpoint
CREATE INDEX "portal_invites_email_idx" ON "portal_invites" USING btree ("email");