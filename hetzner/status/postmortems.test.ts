import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import prettier from 'prettier';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { sites } from '../../sites';
import {
  loadPostmortems,
  parsePostmortem,
  POSTMORTEM_DIR,
  POSTMORTEM_URL_BASE,
  renderAnnouncements,
} from './postmortems';
import { renderStatusConfig } from './render';

const doc = (title: string, resolved?: string): string =>
  [
    '---',
    `title: ${title}`,
    ...(resolved === undefined ? [] : [`resolved: ${resolved}`]),
    '---',
    '',
    'Body.',
    '',
  ].join('\n');

describe('parsePostmortem', () => {
  it('reads the title and the resolved time', () => {
    expect(parsePostmortem('a-b.md', doc('Edge outage', '2026-12-01T10:42:00Z'))).toEqual({
      file: 'a-b.md',
      title: 'Edge outage',
      resolved: '2026-12-01T10:42:00Z',
    });
  });

  it('skips a post-mortem whose incident is not resolved', () => {
    expect(parsePostmortem('a-b.md', doc('Edge outage'))).toBeNull();
  });

  it.each([
    ['a bad file name', 'A_B.md', doc('T', '2026-12-01T10:42:00Z')],
    ['no front matter', 'a.md', 'Just prose.\n'],
    ['an unclosed block', 'a.md', '---\ntitle: T\n'],
    ['no title', 'a.md', '---\nresolved: 2026-12-01T10:42:00Z\n---\n'],
    ['a title that breaks the link', 'a.md', doc('A [b](c) d', '2026-12-01T10:42:00Z')],
    ['a resolved time that is not UTC', 'a.md', doc('T', '2026-12-01 10:42')],
    ['a resolved time that is no date', 'a.md', doc('T', '2026-13-45T10:42:00Z')],
  ])('refuses %s', (_name, file, text) => {
    expect(() => parsePostmortem(file, text)).toThrow();
  });
});

describe('renderAnnouncements', () => {
  it('is absent when there is no post-mortem', () => {
    expect(renderAnnouncements([])).toEqual([]);
  });

  it('is one archived, resolved announcement per post-mortem, linking its file', () => {
    const lines = renderAnnouncements([
      { file: 'edge-outage.md', title: 'Edge outage', resolved: '2026-12-01T10:42:00Z' },
    ]);
    expect(lines).toEqual([
      'announcements:',
      '  - timestamp: 2026-12-01T10:42:00Z',
      '    type: operational',
      '    archived: true',
      `    message: 'Post-mortem: [Edge outage](${POSTMORTEM_URL_BASE}/edge-outage.md)'`,
    ]);
  });

  it('points at the public repository, so the link works for a reader of the page', () => {
    expect(POSTMORTEM_URL_BASE).toBe(
      `https://github.com/branchLeft/shared-infra/blob/main/${POSTMORTEM_DIR}`
    );
  });

  it('renders as YAML that Prettier leaves alone, inside the page config', async () => {
    const text = renderStatusConfig(sites, [
      { file: 'edge-outage.md', title: 'Edge outage', resolved: '2026-12-01T10:42:00Z' },
    ]);
    expect(text).toContain('announcements:\n  - timestamp: 2026-12-01T10:42:00Z\n');
    expect(text.indexOf('announcements:')).toBeLessThan(text.indexOf('endpoints:'));
    const options = {
      ...(await prettier.resolveConfig(path.join(__dirname, 'stack/config.yaml'))),
      parser: 'yaml' as const,
    };
    expect(await prettier.format(text, options)).toBe(text);
  });
});

describe('loadPostmortems', () => {
  let repo: string;
  // Run under a git hook, the environment names the outer repository's index and
  // directory (GIT_INDEX_FILE, GIT_DIR), and every git command here, the loader's
  // included, would read and write that index instead of this throwaway
  // repository's. They are taken out of the environment for each test and put back.
  let outerGitEnv: [string, string][] = [];
  const run = (...args: string[]): void => {
    execFileSync(
      'git',
      [
        '-C',
        repo,
        '-c',
        'user.name=t',
        '-c',
        'user.email=t@example.test',
        '-c',
        'commit.gpgsign=false',
        ...args,
      ],
      { stdio: 'ignore' }
    );
  };
  const put = (file: string, text: string): void => {
    mkdirSync(path.join(repo, POSTMORTEM_DIR), { recursive: true });
    writeFileSync(path.join(repo, POSTMORTEM_DIR, file), text);
  };

  beforeEach(() => {
    outerGitEnv = Object.entries(process.env).filter(
      (entry): entry is [string, string] => entry[0].startsWith('GIT_') && entry[1] !== undefined
    );
    for (const [name] of outerGitEnv) delete process.env[name];
    repo = mkdtempSync(path.join(tmpdir(), 'postmortems-'));
    run('init', '-q');
  });
  afterEach(() => {
    rmSync(repo, { recursive: true, force: true });
    for (const [name, value] of outerGitEnv) process.env[name] = value;
  });

  it('shows a merged post-mortem of a resolved incident', () => {
    put('edge-outage.md', doc('Edge outage', '2026-12-01T10:42:00Z'));
    run('add', '.');
    run('commit', '-q', '-m', 'merged');
    expect(loadPostmortems(repo)).toEqual([
      { file: 'edge-outage.md', title: 'Edge outage', resolved: '2026-12-01T10:42:00Z' },
    ]);
  });

  it('control: a file that is not merged does not appear, written or only staged', () => {
    put('merged.md', doc('Merged', '2026-12-01T10:42:00Z'));
    run('add', '.');
    run('commit', '-q', '-m', 'merged');
    put('written-only.md', doc('Written only', '2026-12-02T10:42:00Z'));
    put('staged.md', doc('Staged', '2026-12-03T10:42:00Z'));
    run('add', `${POSTMORTEM_DIR}/staged.md`);
    expect(loadPostmortems(repo).map((p) => p.file)).toEqual(['merged.md']);
  });

  it('control: an edit not yet merged does not change a merged file', () => {
    put('edge-outage.md', doc('Edge outage', '2026-12-01T10:42:00Z'));
    run('add', '.');
    run('commit', '-q', '-m', 'merged');
    put('edge-outage.md', doc('Rewritten', '2026-12-09T10:42:00Z'));
    expect(loadPostmortems(repo)[0]?.title).toBe('Edge outage');
  });

  it('lists newest resolved first and leaves out an unresolved incident', () => {
    put('old.md', doc('Old', '2026-11-01T00:00:00Z'));
    put('new.md', doc('New', '2026-12-01T00:00:00Z'));
    put('open.md', doc('Still open'));
    run('add', '.');
    run('commit', '-q', '-m', 'merged');
    expect(loadPostmortems(repo).map((p) => p.file)).toEqual(['new.md', 'old.md']);
  });

  it('is empty when the directory does not exist', () => {
    writeFileSync(path.join(repo, 'x'), 'x');
    run('add', '.');
    run('commit', '-q', '-m', 'merged');
    expect(loadPostmortems(repo)).toEqual([]);
  });
});
