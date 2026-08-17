import { defineStandardTest } from '@branchleft/vitest-config';
import { defineConfig } from 'vitest/config';

/**
 * `node`, and coverage scoped to this package's own top-level modules: the
 * shared default globs `src/` and `app/`, neither of which exists here — a
 * Pulumi program is a flat set of modules at the project root.
 *
 * `estate.ts` and `network.ts` are excluded because importing either
 * *constructs resources* at module scope, which is what a Pulumi program is.
 * They are covered by `pulumi preview`, not by Vitest, and leaving them in the
 * coverage denominator would report a permanent zero for two files no unit
 * test can legitimately import.
 */
export default defineConfig(
  defineStandardTest({
    environment: 'node',
    coverageInclude: ['*.ts'],
    coverageExclude: [
      '**/*.test.ts',
      '**/*.d.ts',
      'vitest.config.ts',
      'index.ts',
      'network.ts',
      'estate.ts',
    ],
  })
);
