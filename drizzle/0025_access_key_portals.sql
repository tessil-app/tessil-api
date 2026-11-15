CREATE TABLE "device_portal_keys" (
	"device_id" varchar(21) NOT NULL,
	"portal_id" varchar(21) NOT NULL,
	"key_version" integer NOT NULL,
	"sealed_keys" "bytea" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "device_portal_keys" ADD CONSTRAINT "device_portal_keys_device_id_devices_id_fk" FOREIGN KEY ("device_id") REFERENCES "public"."devices"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "device_portal_keys" ADD CONSTRAINT "device_portal_keys_portal_id_portals_id_fk" FOREIGN KEY ("portal_id") REFERENCES "public"."portals"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "device_portal_keys_device_portal_unique" ON "device_portal_keys" USING btree ("device_id","portal_id");--> statement-breakpoint
CREATE INDEX "device_portal_keys_portal_id_idx" ON "device_portal_keys" USING btree ("portal_id");