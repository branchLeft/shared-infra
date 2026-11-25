import { spawnSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import { delimiter, join, relative, sep } from 'node:path';

import { describe, expect, it } from 'vitest';

// The commit hook runs `pnpm run test` with PRE_COMMIT=1 (set by the pre-commit
// framework), and CI runs the same script without it. The script excludes the
// Docker-backed suites only on the hook path. This test pins both halves: a
// suite that starts a container must stay out of the hook's collection, and
// must stay in CI's. It asks vitest which files it would collect (`list
// --filesOnly` imports nothing), so it does not start a container itself.

const root = __dirname;
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as {
  scripts: Record<string, string>;
};
const testScript = pkg.scripts.test;

// A suite is Docker-backed when it imports the harness that starts containers.
const HARNESS_IMPORT = /['"]\.\/dockerHarness(\.js)?['"]/;

function testFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      return entry.name === 'node_modules' ? [] : testFiles(full);
    }
    return entry.name.endsWith('.test.ts') ? [full] : [];
  });
}

const dockerSuites = testFiles(root)
  .filter((file) => HARNESS_IMPORT.test(readFileSync(file, 'utf8')))
  .map((file) => relative(root, file).split(sep).join('/'))
  .sort();

/** The files vitest would collect for the `test` script, run with the given environment. */
function collected(env: NodeJS.ProcessEnv): string[] {
  expect(testScript.startsWith('vitest run')).toBe(true);
  const listing = testScript.replace('vitest run', 'vitest list --filesOnly');
  const result = spawnSync('sh', ['-c', listing], {
    cwd: root,
    encoding: 'utf8',
    timeout: 120_000,
    env: { ...env, PATH: `${join(root, 'node_modules', '.bin')}${delimiter}${env.PATH ?? ''}` },
  });
  expect(result.status, result.stderr).toBe(0);
  return result.stdout
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.endsWith('.test.ts'));
}

const { PRE_COMMIT: _preCommit, ...ciEnv } = process.env;

describe('test scope on the commit hook and in CI', () => {
  it('finds the Docker-backed suites, so the guard is not vacuous', () => {
    expect(dockerSuites.length).toBeGreaterThan(0);
  });

  it('CI collects every Docker-backed suite', () => {
    const files = collected(ciEnv);
    for (const suite of dockerSuites) {
      expect(files, suite).toContain(suite);
    }
  });

  it('the commit hook path collects no Docker-backed suite', () => {
    const files = collected({ ...ciEnv, PRE_COMMIT: '1' });
    expect(files.length).toBeGreaterThan(0);
    expect(files.filter((file) => dockerSuites.includes(file))).toEqual([]);
  });
});
