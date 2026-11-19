import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

// Same SWC plugin as vitest.config.ts (NestJS decorator metadata), but only
// *.int.test.ts files, driven by a shared PostgreSQL 17 container (ADR-005 D12).
export default defineConfig({
  plugins: [swc.vite({ module: { type: 'es6' } })],
  test: {
    environment: 'node',
    include: ['test/**/*.int.test.ts'],
    globalSetup: ['test/setup/postgres.global.ts'],
    testTimeout: 30000,
    hookTimeout: 120000,
    fileParallelism: false,
  },
});
