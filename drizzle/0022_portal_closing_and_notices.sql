ALTER TABLE "portals" ADD COLUMN "closes_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "portals" ADD COLUMN "notify_on_delivery" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "portals" ADD COLUMN "last_notified_at" timestamp with time zone;