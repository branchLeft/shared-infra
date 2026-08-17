import { defineStandardTest } from '@branchleft/vitest-config';
import { defineConfig } from 'vitest/config';

/**
 * `node`, and coverage scoped to this package's own top-level modules: the
 * flat `host.ts`, `firewalls.ts`, `cloudInit.ts`, `addressPlan.ts` set that
 * makes up the whole published package. `index.ts` is a re-export barrel with
 * no logic of its own, excluded for the reason `@branchleft/vitest-config`'s
 * own default does not assume one: a barrel counted at 0% is misleading
 * coverage, not missing coverage.
 */
export default defineConfig(
  defineStandardTest({
    environment: 'node',
    coverageInclude: ['*.ts'],
    coverageExclude: ['**/*.test.ts', '**/*.d.ts', 'vitest.config.ts', 'index.ts'],
  })
);
