CREATE TABLE "roles" (
	"code" varchar(32) PRIMARY KEY NOT NULL,
	"name_fa" varchar(100) NOT NULL,
	"scope" varchar(16) NOT NULL,
	"description" varchar(500),
	CONSTRAINT "roles_code_scope_uq" UNIQUE("code","scope"),
	CONSTRAINT "roles_scope_valid" CHECK ("roles"."scope" in ('platform', 'tenant', 'carrier', 'driver'))
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"username" varchar(32),
	"display_name" varchar(200) NOT NULL,
	"status" varchar(16) DEFAULT 'active' NOT NULL,
	"phone_enc" "bytea",
	"phone_hash" "bytea",
	"national_id_enc" "bytea",
	"national_id_hash" "bytea",
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" uuid,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "users_tenant_id_uq" UNIQUE("tenant_id","id"),
	CONSTRAINT "users_login_present" CHECK ("users"."username" is not null or "users"."phone_hash" is not null),
	CONSTRAINT "users_username_format" CHECK ("users"."username" ~ '^[a-z0-9._-]{3,32}$'),
	CONSTRAINT "users_status_valid" CHECK ("users"."status" in ('active', 'disabled')),
	CONSTRAINT "users_phone_pair" CHECK (("users"."phone_enc" is null) = ("users"."phone_hash" is null)),
	CONSTRAINT "users_national_id_pair" CHECK (("users"."national_id_enc" is null) = ("users"."national_id_hash" is null))
);
--> statement-breakpoint
CREATE TABLE "user_roles" (
	"tenant_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"role_code" varchar(32) NOT NULL,
	"role_scope" varchar(16) NOT NULL,
	CONSTRAINT "user_roles_pk" PRIMARY KEY("tenant_id","user_id","role_code"),
	CONSTRAINT "user_roles_no_platform" CHECK ("user_roles"."role_scope" <> 'platform')
);
--> statement-breakpoint
ALTER TABLE "users" ADD CONSTRAINT "users_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "users" ADD CONSTRAINT "users_created_by_fk" FOREIGN KEY ("tenant_id","created_by") REFERENCES "public"."users"("tenant_id","id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_roles" ADD CONSTRAINT "user_roles_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_roles" ADD CONSTRAINT "user_roles_user_fk" FOREIGN KEY ("tenant_id","user_id") REFERENCES "public"."users"("tenant_id","id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_roles" ADD CONSTRAINT "user_roles_role_fk" FOREIGN KEY ("role_code","role_scope") REFERENCES "public"."roles"("code","scope") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "users_tenant_username_uq" ON "users" USING btree ("tenant_id","username") WHERE "users"."deleted_at" is null;--> statement-breakpoint
CREATE UNIQUE INDEX "users_tenant_phone_uq" ON "users" USING btree ("tenant_id","phone_hash") WHERE "users"."deleted_at" is null;--> statement-breakpoint
CREATE UNIQUE INDEX "users_tenant_national_id_uq" ON "users" USING btree ("tenant_id","national_id_hash") WHERE "users"."deleted_at" is null;