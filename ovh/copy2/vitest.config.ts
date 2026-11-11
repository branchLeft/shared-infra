import { defineStandardTest } from '@branchleft/vitest-config';
import { defineConfig } from 'vitest/config';

/**
 * `node`, and coverage scoped to this package's own top-level modules: the
 * shared default globs `src/` and `app/`, neither of which exists in a flat
 * Pulumi program. `index.ts` only reads stack config and calls `declare`, so
 * it is excluded; `program.test.ts` imports it under mocks to prove the wiring.
 */
export default defineConfig(
  defineStandardTest({
    environment: 'node',
    coverageInclude: ['*.ts'],
    coverageExclude: ['**/*.test.ts', '**/*.d.ts', 'vitest.config.ts', 'index.ts'],
  })
);
