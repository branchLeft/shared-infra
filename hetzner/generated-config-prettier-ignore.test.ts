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
  // so the same list has to appear in the pre-commit config's own top-level
  // `exclude`, which every hook in the file inherits.
  it.each(GENERATED_FILES)('%s matches the pre-commit exclude pattern', (relPath) => {
    const config = readFileSync(PRE_COMMIT_CONFIG, 'utf8');
    const excludeLine = config.match(/^exclude:\s*(.+)$/m);
    expect(excludeLine, 'pre-commit-config.yaml has a top-level `exclude:`').not.toBeNull();
    const pattern = new RegExp(excludeLine![1].trim());
    expect(pattern.test(relPath)).toBe(true);
  });
});
