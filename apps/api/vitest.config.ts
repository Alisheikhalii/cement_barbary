import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

// Vitest uses esbuild, which cannot emit decorator metadata; SWC handles NestJS DI decorators.
export default defineConfig({
  plugins: [swc.vite({ module: { type: 'es6' } })],
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts', 'test/**/*.test.ts'],
  },
});
