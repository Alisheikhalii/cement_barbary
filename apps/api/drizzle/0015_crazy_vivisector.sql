CREATE TABLE "integration_outbox" (
	"id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"topic" varchar(64) NOT NULL,
	"dedupe_key" varchar(128) NOT NULL,
	"payload_enc" "bytea" NOT NULL,
	"status" varchar(16) DEFAULT 'pending' NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"max_attempts" integer DEFAULT 5 NOT NULL,
	"next_attempt_at" timestamp with time zone DEFAULT now() NOT NULL,
	"locked_until" timestamp with time zone,
	"lock_token" uuid,
	"last_error_code" varchar(64),
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"sent_at" timestamp with time zone,
	CONSTRAINT "integration_outbox_scope_uq" UNIQUE("tenant_id","topic","dedupe_key"),
	CONSTRAINT "integration_outbox_status_valid" CHECK ("integration_outbox"."status" in ('pending', 'processing', 'sent', 'dead')),
	CONSTRAINT "integration_outbox_topic_format" CHECK ("integration_outbox"."topic" ~ '^[a-z][a-z0-9_.]{2,63}$'),
	CONSTRAINT "integration_outbox_dedupe_format" CHECK ("integration_outbox"."dedupe_key" ~ '^[A-Za-z0-9_.:-]{1,128}$'),
	CONSTRAINT "integration_outbox_payload_size" CHECK (octet_length("integration_outbox"."payload_enc") <= 65600),
	CONSTRAINT "integration_outbox_attempts_range" CHECK ("integration_outbox"."attempts" between 0 and "integration_outbox"."max_attempts" and "integration_outbox"."max_attempts" between 1 and 20 and ("integration_outbox"."status" <> 'pending' or "integration_outbox"."attempts" < "integration_outbox"."max_attempts")),
	CONSTRAINT "integration_outbox_lease_pair" CHECK (("integration_outbox"."status" = 'processing') = ("integration_outbox"."locked_until" is not null and "integration_outbox"."lock_token" is not null)),
	CONSTRAINT "integration_outbox_sent_at_valid" CHECK (("integration_outbox"."status" = 'sent') = ("integration_outbox"."sent_at" is not null))
);
--> statement-breakpoint
ALTER TABLE "integration_outbox" ADD CONSTRAINT "integration_outbox_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "integration_outbox_due_idx" ON "integration_outbox" USING btree ("tenant_id","next_attempt_at") WHERE "integration_outbox"."status" in ('pending', 'processing');--> statement-breakpoint
CREATE INDEX "integration_outbox_tenant_status_idx" ON "integration_outbox" USING btree ("tenant_id","status");