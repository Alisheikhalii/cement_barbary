CREATE TABLE "user_credentials" (
	"id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"password_hash" text NOT NULL,
	"must_change_password" boolean DEFAULT true NOT NULL,
	"failed_attempts" integer DEFAULT 0 NOT NULL,
	"next_attempt_at" timestamp with time zone,
	"temporary_password_expires_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "user_credentials_tenant_user_uq" UNIQUE("tenant_id","user_id"),
	CONSTRAINT "user_credentials_phc_format" CHECK ("user_credentials"."password_hash" LIKE '$argon2id$%'),
	CONSTRAINT "user_credentials_failed_attempts_nonneg" CHECK ("user_credentials"."failed_attempts" >= 0),
	CONSTRAINT "user_credentials_temp_pw_forces_change" CHECK ("user_credentials"."temporary_password_expires_at" is null or "user_credentials"."must_change_password")
);
--> statement-breakpoint
CREATE TABLE "auth_sessions" (
	"id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"family_id" uuid NOT NULL,
	"refresh_hash" "bytea" NOT NULL,
	"previous_refresh_hash" "bytea",
	"ip" "inet",
	"user_agent" varchar(512),
	"expires_at" timestamp with time zone NOT NULL,
	"rotated_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"last_used_at" timestamp with time zone,
	"revoke_reason" varchar(32),
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "auth_sessions_previous_rotated" CHECK ("auth_sessions"."previous_refresh_hash" is null or "auth_sessions"."rotated_at" is not null)
);
--> statement-breakpoint
CREATE TABLE "auth_rate_limits" (
	"key" text PRIMARY KEY NOT NULL,
	"count" integer DEFAULT 0 NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	CONSTRAINT "auth_rate_limits_count_nonneg" CHECK ("auth_rate_limits"."count" >= 0)
);
--> statement-breakpoint
ALTER TABLE "user_credentials" ADD CONSTRAINT "user_credentials_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_credentials" ADD CONSTRAINT "user_credentials_user_fk" FOREIGN KEY ("tenant_id","user_id") REFERENCES "public"."users"("tenant_id","id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_sessions" ADD CONSTRAINT "auth_sessions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_sessions" ADD CONSTRAINT "auth_sessions_user_fk" FOREIGN KEY ("tenant_id","user_id") REFERENCES "public"."users"("tenant_id","id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "auth_sessions_refresh_hash_uq" ON "auth_sessions" USING btree ("refresh_hash");--> statement-breakpoint
CREATE INDEX "auth_sessions_tenant_user_idx" ON "auth_sessions" USING btree ("tenant_id","user_id");--> statement-breakpoint
CREATE INDEX "auth_sessions_tenant_family_idx" ON "auth_sessions" USING btree ("tenant_id","family_id");--> statement-breakpoint
CREATE INDEX "auth_sessions_previous_refresh_hash_idx" ON "auth_sessions" USING btree ("previous_refresh_hash");--> statement-breakpoint
CREATE INDEX "auth_rate_limits_expires_idx" ON "auth_rate_limits" USING btree ("expires_at");