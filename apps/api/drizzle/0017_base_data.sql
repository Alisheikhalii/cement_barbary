CREATE TABLE "destinations" (
	"id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"name" varchar(64) NOT NULL,
	"name_key" varchar(64) NOT NULL,
	"province_name" varchar(64),
	"is_active" boolean DEFAULT true NOT NULL,
	"display_order" integer DEFAULT 0 NOT NULL,
	"version" integer DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "destinations_tenant_id_uq" UNIQUE("tenant_id","id"),
	CONSTRAINT "destinations_name_length" CHECK (char_length("destinations"."name") between 2 and 64),
	CONSTRAINT "destinations_name_key_present" CHECK ("destinations"."name_key" <> ''),
	CONSTRAINT "destinations_display_order_range" CHECK ("destinations"."display_order" between 0 and 9999),
	CONSTRAINT "destinations_version_positive" CHECK ("destinations"."version" >= 1)
);
--> statement-breakpoint
CREATE TABLE "halls" (
	"id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"name" varchar(64) NOT NULL,
	"name_key" varchar(64) NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"display_order" integer DEFAULT 0 NOT NULL,
	"version" integer DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "halls_tenant_id_uq" UNIQUE("tenant_id","id"),
	CONSTRAINT "halls_name_length" CHECK (char_length("halls"."name") between 2 and 64),
	CONSTRAINT "halls_name_key_present" CHECK ("halls"."name_key" <> ''),
	CONSTRAINT "halls_display_order_range" CHECK ("halls"."display_order" between 0 and 9999),
	CONSTRAINT "halls_version_positive" CHECK ("halls"."version" >= 1)
);
--> statement-breakpoint
CREATE TABLE "hall_terminals" (
	"id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"hall_id" uuid NOT NULL,
	"name" varchar(64) NOT NULL,
	"name_key" varchar(64) NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"display_order" integer DEFAULT 0 NOT NULL,
	"version" integer DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "hall_terminals_tenant_id_uq" UNIQUE("tenant_id","id"),
	CONSTRAINT "hall_terminals_name_length" CHECK (char_length("hall_terminals"."name") between 2 and 64),
	CONSTRAINT "hall_terminals_name_key_present" CHECK ("hall_terminals"."name_key" <> ''),
	CONSTRAINT "hall_terminals_display_order_range" CHECK ("hall_terminals"."display_order" between 0 and 9999),
	CONSTRAINT "hall_terminals_version_positive" CHECK ("hall_terminals"."version" >= 1)
);
--> statement-breakpoint
CREATE TABLE "loader_type_groups" (
	"id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"name" varchar(64) NOT NULL,
	"name_key" varchar(64) NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"display_order" integer DEFAULT 0 NOT NULL,
	"version" integer DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "loader_type_groups_tenant_id_uq" UNIQUE("tenant_id","id"),
	CONSTRAINT "loader_type_groups_name_length" CHECK (char_length("loader_type_groups"."name") between 2 and 64),
	CONSTRAINT "loader_type_groups_name_key_present" CHECK ("loader_type_groups"."name_key" <> ''),
	CONSTRAINT "loader_type_groups_display_order_range" CHECK ("loader_type_groups"."display_order" between 0 and 9999),
	CONSTRAINT "loader_type_groups_version_positive" CHECK ("loader_type_groups"."version" >= 1)
);
--> statement-breakpoint
CREATE TABLE "loader_types" (
	"id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"group_id" uuid NOT NULL,
	"name" varchar(64) NOT NULL,
	"name_key" varchar(64) NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"display_order" integer DEFAULT 0 NOT NULL,
	"version" integer DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "loader_types_tenant_id_uq" UNIQUE("tenant_id","id"),
	CONSTRAINT "loader_types_name_length" CHECK (char_length("loader_types"."name") between 2 and 64),
	CONSTRAINT "loader_types_name_key_present" CHECK ("loader_types"."name_key" <> ''),
	CONSTRAINT "loader_types_display_order_range" CHECK ("loader_types"."display_order" between 0 and 9999),
	CONSTRAINT "loader_types_version_positive" CHECK ("loader_types"."version" >= 1)
);
--> statement-breakpoint
ALTER TABLE "destinations" ADD CONSTRAINT "destinations_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "halls" ADD CONSTRAINT "halls_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hall_terminals" ADD CONSTRAINT "hall_terminals_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hall_terminals" ADD CONSTRAINT "hall_terminals_hall_fk" FOREIGN KEY ("tenant_id","hall_id") REFERENCES "public"."halls"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "loader_type_groups" ADD CONSTRAINT "loader_type_groups_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "loader_types" ADD CONSTRAINT "loader_types_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "loader_types" ADD CONSTRAINT "loader_types_group_fk" FOREIGN KEY ("tenant_id","group_id") REFERENCES "public"."loader_type_groups"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "destinations_tenant_name_key_uq" ON "destinations" USING btree ("tenant_id","name_key") WHERE "destinations"."deleted_at" is null;--> statement-breakpoint
CREATE INDEX "destinations_tenant_list_idx" ON "destinations" USING btree ("tenant_id","display_order","name_key") WHERE "destinations"."deleted_at" is null;--> statement-breakpoint
CREATE UNIQUE INDEX "halls_tenant_name_key_uq" ON "halls" USING btree ("tenant_id","name_key") WHERE "halls"."deleted_at" is null;--> statement-breakpoint
CREATE INDEX "halls_tenant_list_idx" ON "halls" USING btree ("tenant_id","display_order","name_key") WHERE "halls"."deleted_at" is null;--> statement-breakpoint
CREATE UNIQUE INDEX "hall_terminals_tenant_hall_name_key_uq" ON "hall_terminals" USING btree ("tenant_id","hall_id","name_key") WHERE "hall_terminals"."deleted_at" is null;--> statement-breakpoint
CREATE INDEX "hall_terminals_tenant_hall_list_idx" ON "hall_terminals" USING btree ("tenant_id","hall_id","display_order","name_key") WHERE "hall_terminals"."deleted_at" is null;--> statement-breakpoint
CREATE UNIQUE INDEX "loader_type_groups_tenant_name_key_uq" ON "loader_type_groups" USING btree ("tenant_id","name_key") WHERE "loader_type_groups"."deleted_at" is null;--> statement-breakpoint
CREATE INDEX "loader_type_groups_tenant_list_idx" ON "loader_type_groups" USING btree ("tenant_id","display_order","name_key") WHERE "loader_type_groups"."deleted_at" is null;--> statement-breakpoint
CREATE UNIQUE INDEX "loader_types_tenant_name_key_uq" ON "loader_types" USING btree ("tenant_id","name_key") WHERE "loader_types"."deleted_at" is null;--> statement-breakpoint
CREATE INDEX "loader_types_tenant_list_idx" ON "loader_types" USING btree ("tenant_id","display_order","name_key") WHERE "loader_types"."deleted_at" is null;--> statement-breakpoint
CREATE INDEX "loader_types_tenant_group_list_idx" ON "loader_types" USING btree ("tenant_id","group_id","display_order","name_key") WHERE "loader_types"."deleted_at" is null;