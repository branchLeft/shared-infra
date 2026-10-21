import { createHash } from 'node:crypto';

import type { Enrolment, PullBootstrap } from './cloudInit';

/**
 * Values the enrolment tests build their documents from. Not part of the
 * package (the build excludes it) and not counted in coverage.
 */

export const SSH_ED25519 =
  'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE';
export const APPLY_KEY = `${SSH_ED25519} apply@edge2`;
export const CHECK_KEY =
  'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICHECKCHECKCHECKCHECKCHECKCHECKCHEC check@edge2';

// GitHub's public signing key for commits it makes, as the production group variables hold it.
export const PGP_PUBLIC_KEY = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBGWmxXYBEACyN+4viFQM6QQoKr0A2W0rGdMobTJwOZso2QPpewbyBsuL3rNW
5OmHrWwXAhPKNqUIyOzdq8MoSxoTTuqLksoahixEL/X2nyhOBxR9GkYz/oI9R3nY
cLRaFQoSJoVfOt61opkLUzbWAehpbgT8EKln8JsENq0+0nDlWQi0h2Q9oGmqlgVz
=NRlX
-----END PGP PUBLIC KEY BLOCK-----
`;

export const REPOSITORY_RAW = 'https://raw.githubusercontent.com/branchLeft/shared-infra';
export const PATHS = {
  wrapper: 'ansible/roles/pull_trigger/files/pull_trigger.py',
  program: 'ansible/roles/ansible_runtime/files/install_runtime.py',
  lock: 'ansible/requirements.txt',
} as const;
export const FILE_NAMES = {
  wrapper: 'pull_trigger.py',
  program: 'install_runtime.py',
  lock: 'requirements.txt',
} as const;
export const SERVED = {
  wrapper: '#!/usr/bin/python3 -I\nprint("the pull program")\n',
  program: '#!/usr/bin/python3 -I\nprint("the install program")\n',
  lock: 'alpha==1.0.0 \\\n    --hash=sha256:' + 'a'.repeat(64) + '\n',
} as const;

export const sha256 = (text: string): string => createHash('sha256').update(text).digest('hex');

export function configText(overrides: Record<string, unknown> = {}): string {
  const config: Record<string, unknown> = {
    ansible_playbook: '/usr/local/bin/ansible-playbook',
    keep_runs: 50,
    log_dir: '/var/log/pull-trigger',
    playbook: 'ansible/playbooks/edge1.yml',
    playbooks: ['ansible/playbooks/edge1.yml'],
    remote_url: 'https://github.com/branchLeft/shared-infra.git',
    signers: [{ format: 'openpgp', key: PGP_PUBLIC_KEY }],
    state_dir: '/var/lib/pull-trigger',
    timeout_seconds: 3600,
    ...overrides,
  };
  for (const [key, value] of Object.entries(config)) {
    if (value === undefined) {
      delete config[key];
    }
  }
  return JSON.stringify(config, null, 4) + '\n';
}

export function bootstrap(overrides: Record<string, unknown> = {}): PullBootstrap {
  const entry = (name: keyof typeof PATHS, pin: string) => ({
    pin,
    sha256: sha256(SERVED[name]),
    url: `${REPOSITORY_RAW}/${pin}/${PATHS[name]}`,
  });
  return {
    schema: 1,
    wrapper: entry('wrapper', '1'.repeat(40)),
    program: entry('program', '2'.repeat(40)),
    lock: entry('lock', '3'.repeat(40)),
    config: configText(),
    ...overrides,
  } as PullBootstrap;
}

export function enrolment(overrides: Partial<Enrolment> = {}): Enrolment {
  return {
    applyPublicKey: APPLY_KEY,
    checkPublicKey: CHECK_KEY,
    bootstrap: bootstrap(),
    ...overrides,
  };
}
