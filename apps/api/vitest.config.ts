import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

// Vitest uses esbuild, which cannot emit decorator metadata; SWC handles NestJS DI decorators.
export default defineConfig({
  plugins: [swc.vite({ module: { type: 'es6' } })],
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts', 'test/**/*.test.ts'],
    // Integration tests (*.int.test.ts) need Docker; unit tests stay Docker-free (D12).
    exclude: ['**/*.int.test.ts', 'node_modules/**', 'dist/**'],
    // Cap worker count: one isolated fork per file oversubscribes CPU on dev
    // machines/CI and was the flaky-timeout amplifier (T08 investigation).
    maxWorkers: 4,
  },
});
