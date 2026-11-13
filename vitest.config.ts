import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  resolve: {
    alias: {
      '@tenantshield/catalog': fileURLToPath(
        new URL('./packages/catalog/src/index.ts', import.meta.url),
      ),
      '@tenantshield/config': fileURLToPath(
        new URL('./packages/config/src/index.ts', import.meta.url),
      ),
      '@tenantshield/findings': fileURLToPath(
        new URL('./packages/findings/src/index.ts', import.meta.url),
      ),
      '@tenantshield/reporters': fileURLToPath(
        new URL('./packages/reporters/src/index.ts', import.meta.url),
      ),
      '@tenantshield/rules': fileURLToPath(
        new URL('./packages/rules/src/index.ts', import.meta.url),
      ),
      '@tenantshield/runner': fileURLToPath(
        new URL('./packages/runner/src/index.ts', import.meta.url),
      ),
    },
  },
  test: {
    include: ['packages/**/*.test.ts', 'apps/**/*.test.ts'],
    coverage: {
      reporter: ['text', 'json', 'html'],
      include: ['packages/*/src/**/*.ts', 'apps/*/src/**/*.ts'],
      exclude: ['**/*.test.ts', '**/dist/**'],
      thresholds: {
        lines: 80,
        functions: 75,
        branches: 75,
        statements: 80,
      },
    },
  },
});
