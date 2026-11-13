ALTER TABLE "user_vaults" ALTER COLUMN "salt_password" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "user_vaults" ALTER COLUMN "wrap_password" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "user_vaults" ADD CONSTRAINT "user_vaults_password_pair_together" CHECK (("user_vaults"."salt_password" IS NULL) = ("user_vaults"."wrap_password" IS NULL));