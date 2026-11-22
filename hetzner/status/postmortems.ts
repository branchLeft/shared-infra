import { execFileSync } from 'node:child_process';

/**
 * Post-mortems of the status page. A post-mortem is a markdown file in
 * `postmortems/`, written by a person and merged by pull request. The renderer
 * turns each one that is merged and resolved into an archived announcement
 * that links to it. Nothing here writes or edits a post-mortem. See render.md.
 */

/** Where the files live, relative to the repository root. */
export const POSTMORTEM_DIR = 'hetzner/status/postmortems';

/** Where a reader of the page finds a merged file: the repository is public. */
export const POSTMORTEM_URL_BASE =
  'https://github.com/branchLeft/shared-infra/blob/main/hetzner/status/postmortems';

export interface Postmortem {
  /** File name inside `postmortems/`. */
  file: string;
  /** One line of plain text, as the link reads on the page. */
  title: string;
  /** UTC instant the incident resolved, RFC 3339 with a `Z`. */
  resolved: string;
}

const FILE_NAME = /^[a-z0-9][a-z0-9-]*\.md$/;
const RESOLVED = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
/** Characters that would break the link text or leave one line. */
const UNSAFE_TITLE = /[[\]\r\n\\`<>]/;

/** The `key: value` lines between the opening `---` and the next `---`. */
function frontMatter(file: string, text: string): Map<string, string> {
  const lines = text.split('\n');
  if (lines[0] !== '---') {
    throw new Error(`${file}: a post-mortem starts with a front-matter block fenced by ---`);
  }
  const end = lines.indexOf('---', 1);
  if (end === -1) {
    throw new Error(`${file}: the front-matter block is never closed`);
  }
  const fields = new Map<string, string>();
  for (const line of lines.slice(1, end)) {
    const match = /^([a-z]+): (.*)$/.exec(line);
    if (match === null) {
      throw new Error(`${file}: front-matter line is not \`key: value\`: ${line}`);
    }
    fields.set(match[1]!, match[2]!.trim());
  }
  return fields;
}

/**
 * Reads one file. Returns null while the incident is not resolved: a draft
 * written during an incident has no `resolved` field and is not shown.
 */
export function parsePostmortem(file: string, text: string): Postmortem | null {
  if (!FILE_NAME.test(file)) {
    throw new Error(
      `${file}: a post-mortem file name is lower-case words joined by - and ends .md`
    );
  }
  const fields = frontMatter(file, text);
  const title = fields.get('title');
  if (title === undefined || title === '' || UNSAFE_TITLE.test(title)) {
    throw new Error(`${file}: title is required, on one line, without []\\\`<> characters`);
  }
  const resolved = fields.get('resolved');
  if (resolved === undefined || resolved === '') {
    return null;
  }
  if (!RESOLVED.test(resolved) || Number.isNaN(Date.parse(resolved))) {
    throw new Error(`${file}: resolved must be a UTC time such as 2026-12-01T10:42:00Z`);
  }
  return { file, title, resolved };
}

const git = (repo: string, args: string[]): string =>
  execFileSync('git', ['-C', repo, ...args], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });

/**
 * The resolved post-mortems that are committed at `HEAD` of `repo`, newest
 * first. The committed tree is the one source: a file that is only in a working
 * tree, or on a branch that has not landed, is not read, so it cannot appear.
 */
export function loadPostmortems(repo: string, dir: string = POSTMORTEM_DIR): Postmortem[] {
  const prefix = `${dir}/`;
  const files = git(repo, ['ls-tree', '-r', '--name-only', 'HEAD', '--', prefix])
    .split('\n')
    .filter((path) => path.startsWith(prefix))
    .map((path) => path.slice(prefix.length));
  const found: Postmortem[] = [];
  for (const file of files) {
    const parsed = parsePostmortem(file, git(repo, ['show', `HEAD:${prefix}${file}`]));
    if (parsed !== null) {
      found.push(parsed);
    }
  }
  return found.sort((a, b) => b.resolved.localeCompare(a.resolved) || a.file.localeCompare(b.file));
}

/** A YAML single-quoted scalar, the style the repository's Prettier keeps. */
const yamlSingleQuoted = (text: string): string => `'${text.replaceAll("'", "''")}'`;

/**
 * The `announcements:` block of the Gatus config: one archived, resolved-type
 * announcement per post-mortem, stamped with when its incident resolved and
 * linking to the file. Empty when there is none, so the key is absent.
 */
export function renderAnnouncements(postmortems: readonly Postmortem[]): string[] {
  if (postmortems.length === 0) {
    return [];
  }
  return [
    'announcements:',
    ...postmortems.flatMap((postmortem) => [
      `  - timestamp: ${postmortem.resolved}`,
      '    type: operational',
      '    archived: true',
      `    message: ${yamlSingleQuoted(
        `Post-mortem: [${postmortem.title}](${POSTMORTEM_URL_BASE}/${postmortem.file})`
      )}`,
    ]),
  ];
}
