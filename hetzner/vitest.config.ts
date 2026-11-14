import { defineStandardTest } from '@branchleft/vitest-config';
import { defineConfig } from 'vitest/config';

/** `node` environment and coverage scoped to this package's own modules; rationale in `vitest.config.md` next to this file. */
export default defineConfig(
  defineStandardTest({
    environment: 'node',
    coverageInclude: ['*.ts', 'edge/*.ts', 'monitoring/*.ts'],
    coverageExclude: [
      '**/*.test.ts',
      '**/*.d.ts',
      'vitest.config.ts',
      'index.ts',
      'network.ts',
      'estate.ts',
      'dns.ts',
    ],
  })
);
