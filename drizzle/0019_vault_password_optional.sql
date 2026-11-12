ALTER TABLE "user_vaults" ALTER COLUMN "salt_password" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "user_vaults" ALTER COLUMN "wrap_password" DROP NOT NULL;