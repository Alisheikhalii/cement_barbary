CREATE TABLE "tenants" (
	"id" uuid PRIMARY KEY NOT NULL,
	"code" varchar(32) NOT NULL,
	"name" varchar(200) NOT NULL,
	"status" varchar(16) DEFAULT 'active' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" uuid,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "tenants_code_format" CHECK ("tenants"."code" ~ '^[a-z0-9-]{2,32}$'),
	CONSTRAINT "tenants_status_valid" CHECK ("tenants"."status" in ('active', 'suspended'))
);
--> statement-breakpoint
CREATE UNIQUE INDEX "tenants_code_uq" ON "tenants" USING btree ("code") WHERE "tenants"."deleted_at" is null;