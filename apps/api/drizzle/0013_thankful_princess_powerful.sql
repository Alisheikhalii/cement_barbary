CREATE TABLE "idempotency_keys" (
	"id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"route_key" varchar(160) NOT NULL,
	"idem_key" varchar(128) NOT NULL,
	"fingerprint" "bytea" NOT NULL,
	"status" varchar(16) DEFAULT 'in_progress' NOT NULL,
	"response_status" smallint,
	"response_enc" "bytea",
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	CONSTRAINT "idempotency_keys_scope_uq" UNIQUE("tenant_id","user_id","route_key","idem_key"),
	CONSTRAINT "idempotency_keys_status_valid" CHECK ("idempotency_keys"."status" in ('in_progress', 'completed')),
	CONSTRAINT "idempotency_keys_key_format" CHECK ("idempotency_keys"."idem_key" ~ '^[A-Za-z0-9_-]{16,128}$'),
	CONSTRAINT "idempotency_keys_route_format" CHECK ("idempotency_keys"."route_key" ~ '^[A-Z]{3,7} /[A-Za-z0-9_:/{}.@-]{1,150}$'),
	CONSTRAINT "idempotency_keys_fingerprint_size" CHECK (octet_length("idempotency_keys"."fingerprint") = 32),
	CONSTRAINT "idempotency_keys_completed_fields" CHECK (("idempotency_keys"."status" = 'completed' and "idempotency_keys"."response_status" is not null and "idempotency_keys"."response_enc" is not null)
        or ("idempotency_keys"."status" <> 'completed' and "idempotency_keys"."response_status" is null and "idempotency_keys"."response_enc" is null)),
	CONSTRAINT "idempotency_keys_response_status_valid" CHECK ("idempotency_keys"."response_status" is null or "idempotency_keys"."response_status" between 100 and 599),
	CONSTRAINT "idempotency_keys_response_size" CHECK ("idempotency_keys"."response_enc" is null or octet_length("idempotency_keys"."response_enc") <= 65600),
	CONSTRAINT "idempotency_keys_expiry_order" CHECK ("idempotency_keys"."expires_at" > "idempotency_keys"."created_at")
);
--> statement-breakpoint
ALTER TABLE "idempotency_keys" ADD CONSTRAINT "idempotency_keys_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "idempotency_keys" ADD CONSTRAINT "idempotency_keys_user_fk" FOREIGN KEY ("tenant_id","user_id") REFERENCES "public"."users"("tenant_id","id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idempotency_keys_tenant_expiry_idx" ON "idempotency_keys" USING btree ("tenant_id","expires_at");