import { z } from 'zod';

/**
 * Startup environment validation (Zod). The process must fail fast on invalid
 * config instead of failing later at runtime. Extend this schema per phase;
 * keep it in sync with `.env.example`.
 */
const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  API_PORT: z.coerce.number().int().min(1).max(65535).default(4000),
  API_PUBLIC_URL: z.url().default('http://localhost:4000'),
  CORS_ALLOWED_ORIGINS: z.string().min(1).default('http://localhost:3000'),
});

/** Typed, validated application configuration. Inject via APP_CONFIG. */
export interface AppConfig {
  nodeEnv: 'development' | 'test' | 'production';
  port: number;
  publicUrl: string;
  corsOrigins: string[];
}

export function parseEnv(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const parsed = envSchema.safeParse(env);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((issue) => `${issue.path.join('.')}: ${issue.message}`)
      .join('; ');
    throw new Error(`Invalid environment configuration — ${issues}`);
  }
  return {
    nodeEnv: parsed.data.NODE_ENV,
    port: parsed.data.API_PORT,
    publicUrl: parsed.data.API_PUBLIC_URL,
    corsOrigins: parsed.data.CORS_ALLOWED_ORIGINS.split(',')
      .map((origin) => origin.trim())
      .filter((origin) => origin.length > 0),
  };
}
