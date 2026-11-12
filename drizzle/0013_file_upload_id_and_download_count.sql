ALTER TABLE "files" ADD COLUMN "upload_id" text;--> statement-breakpoint
ALTER TABLE "files" ADD COLUMN "download_count" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
-- The transfer counter used to count every file URL handed out. Carry it
-- onto each file so a limited transfer never gains downloads from this change.
UPDATE "files" SET "download_count" = "transfers"."download_count" FROM "transfers" WHERE "transfers"."id" = "files"."transfer_id" AND "transfers"."download_count" > 0;
