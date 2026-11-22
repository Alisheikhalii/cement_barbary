CREATE TABLE "audit_logs" (
	"id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"occurred_at" timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
	"actor_type" varchar(16) NOT NULL,
	"actor_user_id" uuid,
	"actor_session_id" uuid,
	"action" varchar(64) NOT NULL,
	"resource_type" varchar(64) NOT NULL,
	"resource_id" varchar(128),
	"outcome" varchar(16) NOT NULL,
	"http_status" smallint,
	"reason" text,
	"before" jsonb,
	"after" jsonb,
	"metadata" jsonb,
	"ip_enc" "bytea",
	"ip_hash" "bytea",
	"request_id" varchar(64),
	CONSTRAINT "audit_logs_actor_type_valid" CHECK ("audit_logs"."actor_type" in ('user', 'system')),
	CONSTRAINT "audit_logs_actor_user_required" CHECK (("audit_logs"."actor_type" = 'user') = ("audit_logs"."actor_user_id" is not null)),
	CONSTRAINT "audit_logs_action_format" CHECK ("audit_logs"."action" ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
	CONSTRAINT "audit_logs_outcome_valid" CHECK ("audit_logs"."outcome" in ('success', 'failure', 'denied')),
	CONSTRAINT "audit_logs_http_status_valid" CHECK ("audit_logs"."http_status" is null or "audit_logs"."http_status" between 100 and 599),
	CONSTRAINT "audit_logs_reason_length" CHECK ("audit_logs"."reason" is null or length("audit_logs"."reason") <= 500),
	CONSTRAINT "audit_logs_before_size" CHECK ("audit_logs"."before" is null or octet_length("audit_logs"."before"::text) <= 16384),
	CONSTRAINT "audit_logs_after_size" CHECK ("audit_logs"."after" is null or octet_length("audit_logs"."after"::text) <= 16384),
	CONSTRAINT "audit_logs_metadata_size" CHECK ("audit_logs"."metadata" is null or octet_length("audit_logs"."metadata"::text) <= 16384),
	CONSTRAINT "audit_logs_ip_pair" CHECK (("audit_logs"."ip_enc" is null) = ("audit_logs"."ip_hash" is null)),
	CONSTRAINT "audit_logs_ip_enc_size" CHECK ("audit_logs"."ip_enc" is null or octet_length("audit_logs"."ip_enc") <= 1024),
	CONSTRAINT "audit_logs_ip_hash_size" CHECK ("audit_logs"."ip_hash" is null or octet_length("audit_logs"."ip_hash") = 32)
);
--> statement-breakpoint
ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_actor_user_fk" FOREIGN KEY ("tenant_id","actor_user_id") REFERENCES "public"."users"("tenant_id","id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "audit_logs_tenant_occurred_idx" ON "audit_logs" USING btree ("tenant_id","occurred_at" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "audit_logs_tenant_actor_idx" ON "audit_logs" USING btree ("tenant_id","actor_user_id","occurred_at");--> statement-breakpoint
CREATE INDEX "audit_logs_tenant_resource_idx" ON "audit_logs" USING btree ("tenant_id","resource_type","resource_id");