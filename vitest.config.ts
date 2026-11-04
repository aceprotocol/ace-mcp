import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    testTimeout: 20_000,
    hookTimeout: 30_000,
    include: ['tests/**/*.test.ts'],
  },
});
