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
 * files this suite does not exercise as behaviour. `egress.test.ts` does
 * import `network.ts` under mocks, but only to pin one resolved resource
 * option — that single assertion is not the program-level coverage this
 * exclusion is about.
 *
 * `edge/` and `monitoring/` are included: each renders one host's config from
 * the registry and constructs nothing, so unlike the three files above both
 * are importable and worth measuring.
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
    coverageInclude: ['*.ts', 'edge/*.ts', 'monitoring/*.ts'],
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
