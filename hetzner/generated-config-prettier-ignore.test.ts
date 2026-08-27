import { readFileSync } from 'node:fs';
import path from 'node:path';

import prettier from 'prettier';
import { describe, expect, it } from 'vitest';

/**
 * `render.test.ts` in `edge/` and `monitoring/` proves the committed files
 * equal what their renderer emits today. It says nothing about whether a
 * repo-wide `npm run format` would rewrite them tomorrow -- that gap is what
 * let Prettier's YAML quote-style rewrite silently diverge from the renderer
 * once, and the two would fight over the same bytes on every future run
 * unless the formatter is kept off this list for good.
 */
const REPO_ROOT = path.resolve(__dirname, '..');
const PRETTIERIGNORE = path.join(REPO_ROOT, '.prettierignore');
const PRE_COMMIT_CONFIG = path.join(REPO_ROOT, '.pre-commit-config.yaml');

const GENERATED_FILES = [
  'hetzner/monitoring/stack/prometheus/prometheus.yml',
  'hetzner/monitoring/stack/prometheus/alerts.yml',
  'hetzner/monitoring/stack/alertmanager/alertmanager.yml.tmpl',
  'hetzner/edge/stack/Caddyfile',
  'hetzner/edge/stack/crowdsec/acquis.d/appsec.yaml',
  'hetzner/edge/stack/crowdsec/acquis.d/caddy.yaml',
  'hetzner/edge/validation/Caddyfile.enforcing',
  'hetzner/edge/validation/Caddyfile.authoring',
];

describe('generated config stays off Prettier and the pre-commit whitespace hooks', () => {
  it.each(GENERATED_FILES)('%s is ignored by .prettierignore', async (relPath) => {
    const info = await prettier.getFileInfo(path.join(REPO_ROOT, relPath), {
      ignorePath: [PRETTIERIGNORE],
    });
    expect(info.ignored).toBe(true);
  });

  // `.prettierignore` only reaches Prettier itself. `trailing-whitespace` and
  // `end-of-file-fixer` rewrite file content directly and never consult it,
  // so the same list has to reach them too -- but scoped to those two hooks
  // alone via the `&generated-config-exclude` anchor, not the file's
  // top-level `exclude`, which every hook inherits including
  // `hetzner-unit-tests`: excluding these paths there would silently stop it
  // running on a hand-edit to one of them, the exact drift it exists to catch.
  it.each(GENERATED_FILES)('%s matches the generated-config-exclude anchor', (relPath) => {
    const config = readFileSync(PRE_COMMIT_CONFIG, 'utf8');
    const anchor = config.match(/exclude:\s*&generated-config-exclude\s+(\S.*)$/m);
    expect(anchor, '.pre-commit-config.yaml defines &generated-config-exclude').not.toBeNull();
    const pattern = new RegExp(anchor![1].trim());
    expect(pattern.test(relPath)).toBe(true);
  });

  it('both trailing-whitespace and end-of-file-fixer carry the exclusion', () => {
    const config = readFileSync(PRE_COMMIT_CONFIG, 'utf8');
    // One definition (`&generated-config-exclude`) plus one alias reference
    // (`*generated-config-exclude`) is the minimum for both hooks to be
    // covered; fewer means a hook lost its reference silently.
    const occurrences = config.match(/generated-config-exclude/g) ?? [];
    expect(occurrences.length).toBeGreaterThanOrEqual(2);
  });
});
