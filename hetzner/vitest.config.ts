import { defineStandardTest } from '@branchleft/vitest-config';
import { defineConfig } from 'vitest/config';

/**
 * `node`, and coverage scoped to this package's own top-level modules: the
 * shared default globs `src/` and `app/`, neither of which exists here — a
 * Pulumi program is a flat set of modules at the project root.
 *
 * `estate.ts`, `network.ts` and `index.ts` are excluded because importing any
 * of them *constructs resources* at module scope, which is what a Pulumi
 * program is. They are covered by `pulumi preview`, not by Vitest, and
 * leaving them in the coverage denominator would report a permanent zero for
 * files no unit test can legitimately import.
 *
 * `edge/` is included: it renders the edge host's Caddy and CrowdSec
 * configuration and constructs nothing, so unlike the three files above it is
 * both importable and worth measuring.
 *
 * `host.ts`, `firewalls.ts`, `cloudInit.ts` and `addressPlan.ts` — the four
 * files that used to be unit-tested here — moved to `@branchleft/hetzner-host`
 * (`../hetzner-host`), whose own suite covers them directly.
 * `hetznerHost.test.ts` is not a coverage target either: it exists to prove
 * this project can construct a `Host` across the package boundary, not to
 * measure this project's own line coverage.
 */
export default defineConfig(
  defineStandardTest({
    environment: 'node',
    coverageInclude: ['*.ts', 'edge/*.ts'],
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
