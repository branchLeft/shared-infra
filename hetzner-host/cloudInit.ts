import * as pulumi from '@pulumi/pulumi';

import fixed from './pullBootstrapFixed.json';

/**
 * The first-boot user-data every platform host is created with.
 *
 * **Cloud-init runs once, on first boot, and never again.** Nothing that has
 * to stay true over the host's life belongs here — it belongs in
 * `provision/`, whose scripts are idempotent and re-runnable. This file's
 * only job is to make the host reachable by the two identities that do the
 * rest: the platform owner's key on `root`, and the CI deploy key on
 * `deploy`.
 *
 * One deliberate exception: a private-only host's `bootcmd` entries (see
 * `PRIVATE_ONLY_BOOTCMD` below) re-run on every boot, not once. `bootcmd`
 * is the only cloud-init stage early enough to matter here, and re-running
 * is also the point of putting them there — it covers the window between
 * first boot and `provision/05-configure-host-egress.sh` (and the systemd
 * unit it installs) actually taking over the same job permanently. Both
 * commands are idempotent, so the repetition costs nothing once that unit
 * exists.
 *
 * The image is Debian, whose cloud image ships cloud-init with the standard
 * modules; nothing here depends on a Hetzner-specific datasource.
 */
export interface CloudInitArgs {
  /** Becomes both the system hostname and the name used in
   * `/etc/branchleft/` paths, so it must match the Hetzner server name. */
  hostname: pulumi.Input<string>;
  /** OpenSSH public key of the CI deploy keypair for this host. Public half
   * only — the private half exists solely as a GitHub Actions secret and
   * must never reach this repository. A distinct keypair per host keeps a
   * compromised runner secret scoped to one machine.
   *
   * Required unless `enrolment` is set, and refused when it is: an enrolled
   * host is deployed by the pull, so it has no `deploy` account (see
   * `Enrolment`). */
  deployPublicKey?: pulumi.Input<string>;
  /**
   * Whether this host has no public interface at all. A plain boolean, not
   * an `Input`: it comes from `HostArgs.publicNetworking`, itself a plain
   * boolean because the networking shape is a creation-time decision, never
   * a stack output.
   *
   * A private-only host's only route off the subnet is the network's own
   * gateway, and Hetzner's DHCP delivers the subnet route but never a
   * default (`hetzner/egress.ts`). Left false, `package_update` below is the
   * first thing on such a host with nowhere to reach, and every apt mirror
   * fails "temporary failure resolving" for the rest of first boot.
   */
  privateOnly: boolean;
  /**
   * Bring the host under the gated pull at first boot. Absent, the document is
   * exactly what it was before this field existed.
   */
  enrolment?: Enrolment;
}

/** One file the host fetches at first boot, pinned to a commit of `main`. */
export interface PullBootstrapFile {
  /** The raw address of the file at `pin`. It must name exactly `pin`. */
  url: string;
  /** The full commit id: the last commit that changed the file. */
  pin: string;
  /** SHA-256 of the file's bytes, 64 lowercase hex digits. */
  sha256: string;
}

/**
 * The record `ansible/tools/pull_bootstrap.py` builds from `main` at publish
 * time. The package does not carry a copy of it: the stack passes the record
 * it was given with the package, and `assertPullBootstrap` refuses anything
 * that is not exactly the shape the tool writes. It cannot tell whether a pin
 * is a commit of `main`: only the tool can, because `generate` refuses unless
 * HEAD is the tip of a freshly fetched `main` and `verify` refuses a pin that
 * is not an ancestor of it. A record that did not come from the tool, or that
 * `verify` has not accepted, is not known to name reviewed code.
 */
export interface PullBootstrap {
  schema: 1;
  /** The pull program (`pull_trigger.py`). */
  wrapper: PullBootstrapFile;
  /** The program that installs the pinned, hash-locked Ansible. */
  program: PullBootstrapFile;
  /** The hash-locked requirements of the pinned Ansible. */
  lock: PullBootstrapFile;
  /** The exact text of the pull program's `config.json`. */
  config: string;
}

/**
 * What it takes to bring a new edge host under the pull at first boot.
 *
 * The host's root account gets two `authorized_keys` lines, each restricted to
 * one command of the pull program: one applies, one checks. Their private
 * halves are the owner's to generate and hold; only the public halves are
 * stack config. The lines do nothing until the pull program exists, because a
 * `command=` that names a missing path fails closed.
 */
export interface Enrolment {
  /** OpenSSH public key allowed to run `pull-trigger --mode apply`. */
  applyPublicKey: string;
  /** OpenSSH public key allowed to run `pull-trigger --mode check`. Must differ from the apply key. */
  checkPublicKey: string;
  /** The bootstrap record (see `PullBootstrap`). */
  bootstrap: PullBootstrap;
}

/**
 * Options on the **host-level** deploy key — the one this document installs at
 * first boot. `restrict` is the whole-set deny (no agent forwarding, no port
 * forwarding, no X11, no pty, no user-rc), with nothing added back.
 *
 * Deliberately no forced command here, and that is now a scoping decision
 * rather than a deferral. This key is the platform's own and names the stack it
 * deploys, so it reaches every stack on the host; per-stack keys carry
 * `restrict` **plus** a `command=` naming one stack, and are added after first
 * boot by `hetzner/provision/provision_deploy_slot.py`, which is the only
 * writer of `authorized_keys` thereafter. Cloud-init cannot install them: it
 * runs once, and slots are granted per tenant over the host's life.
 */
const AUTHORIZED_KEY_OPTIONS = 'restrict';

/**
 * `deploy` gets no shell privileges and no membership of the `docker` group.
 * Docker group membership is root-equivalent — the socket will build a
 * container that mounts the host filesystem — so a deploy user placed in it
 * is unrestricted however carefully its sudoers entry is written.
 *
 * Instead the one privileged action CI needs runs through a single root-owned
 * wrapper, and the sudoers entry names that binary with **no wildcard**. A
 * wildcard in a sudoers command matches spaces, which turns any
 * `systemctl restart something@*` style entry into arbitrary argument
 * injection. Argument validation is the wrapper's job, where it can be
 * tested, not sudoers'.
 */
const DEPLOY_SUDOERS = 'deploy ALL=(root) NOPASSWD: /usr/local/sbin/branchleft-deploy';

/**
 * OpenSSH public key, one line: type, base64 blob, optional comment.
 *
 * The type list is closed rather than `[a-z0-9-]+` because this value is
 * substituted into a `#cloud-config` document, so what is being validated is
 * not really "is this a key" but "can this end the line it is on". Anchored
 * with `\A`/`\z`-equivalents (`^`/`$` without `m`) so a trailing newline is a
 * rejection: in JavaScript `$` matches before a final `\n` unless the pattern
 * says otherwise, which is exactly the character that matters here.
 */
const OPENSSH_PUBLIC_KEY =
  /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/]+={0,3}( [^\n\r]*)?$/;

/**
 * Rejects anything that is not a single-line OpenSSH public key.
 *
 * This is the only validation between stack config and a document that grants
 * `deploy` an `authorized_keys` entry and a sudoers rule, and a newline in the
 * value appends arbitrary cloud-config to it — a second `users:` entry, a
 * `runcmd`, a `write_files` overwriting the sudoers drop-in. Three properties
 * make that worth failing closed over rather than trusting the input:
 * cloud-init runs once and cannot be re-run, `userData` is create-time-only at
 * the provider, and it is in the component's `ignoreChanges`, so an injected
 * document is permanent and absent from every later diff.
 *
 * Throwing here fails the preview, before anything is created.
 */
export function assertDeployPublicKey(key: string): string {
  if (!OPENSSH_PUBLIC_KEY.test(key)) {
    throw new Error(
      'deployPublicKey must be a single-line OpenSSH public key (for example the whole contents of an `id_ed25519.pub`). ' +
        'It is substituted into a cloud-config document that also grants sudo, so a value spanning more than one line is rejected rather than escaped.'
    );
  }
  return key;
}

/**
 * `bootcmd` entries that give a private-only host a working default route
 * and resolver before `package_update`/`packages` below installs anything.
 *
 * This has to be `bootcmd`, not `runcmd`, and the distinction is not
 * cosmetic. `runcmd`'s own module only *writes* the command list to a script
 * on disk during cloud-init's config stage; that script is not actually
 * *executed* until the `scripts-user` module, which sits near the end of the
 * later final stage -- and `package-update-upgrade-install` (the module
 * behind `package_update`/`packages`) is at the *start* of that same final
 * stage. A `runcmd` entry here would therefore still run after package
 * installation has already failed, which is the exact bug this block exists
 * to fix. `bootcmd` is a separate, earlier module in cloud-init's very first
 * (init) stage, which precedes the config stage entirely -- config, in turn,
 * precedes final -- so this is the one placement that actually lands ahead
 * of `package_update`.
 *
 * The trade-off named at the top of this file: `bootcmd` re-runs on every
 * boot, not once, which is why both commands below are written to be safe
 * to repeat (`ip route replace`, and a plain overwrite-and-`resolvconf -u`
 * with no compare-first check, since bootcmd has no equivalent of a
 * provisioning log to skip redundant work against).
 *
 * Exec form is avoided here (unlike the plain commands below) because the
 * gateway has to be derived from the routing table, which needs a shell.
 * Every string literal in the embedded awk/shell is double-quoted rather
 * than single-quoted so that wrapping the whole command in a YAML
 * double-quoted scalar needs no nested-quote gymnastics beyond escaping
 * those doubles for YAML itself.
 */
const PRIVATE_ONLY_BOOTCMD = `
bootcmd:
  # A private-only host has no public interface, so its only route off the
  # subnet is the network's own gateway -- and Hetzner's DHCP delivers the
  # subnet route but never a default (hetzner/egress.ts). Every boot, until
  # provision/05-configure-host-egress.sh (and the systemd unit it installs)
  # has taken over the same job permanently.
  - [ sh, -c, "GW=$(ip -4 route show | awk '$1 != \\"default\\" && $1 != \\"169.254.169.254\\" { for (i=1;i<=NF;i++) if ($i==\\"via\\") { print $(i+1); exit } }'); [ -n \\"$GW\\" ] && ip route replace default via \\"$GW\\" || true" ]
  - [ sh, -c, "mkdir -p /etc/resolvconf/resolv.conf.d && { echo 'nameserver 185.12.64.1'; echo 'nameserver 185.12.64.2'; } > /etc/resolvconf/resolv.conf.d/head && resolvconf -u || true" ]
`;

// The pieces below are shared by the deploy-key document and the enrolment
// document, so that neither can drift from the other. They are the text the
// deploy-key document has always had, and `cloudInit.test.ts` holds that
// document byte for byte against what `origin/main` rendered before this
// change.

/**
 * The default entry comes first in `users`, always. Both documents carry it,
 * and the enrolment document's root entry goes beside it, never in its place.
 */
const USERS_DEFAULT_ENTRY = `  # The default entry comes first, always. A users block that omits it
  # replaces the image's default account rather than adding to it, and the
  # keys Hetzner injects through the datasource follow that default account.
  # Omitting it produces a host with the deploy key installed and no owner
  # access at all.
  - default`;

/**
 * The hardening drop-in. Every document carries it: it is what closes the
 * password-auth window during first boot.
 */
const HARDENING_ENTRY = `  # Duplicated by provision/00-harden-ssh.sh on purpose, not by oversight.
  # This copy closes the password-auth window during first boot, before the
  # host has ever been reachable for a provisioning run; the script is what
  # keeps the file true afterwards.
  #
  # The 01- prefix is load-bearing. OpenSSH keeps the first value it obtains
  # for a keyword and the Include glob expands in sort order, so the
  # lowest-sorting drop-in wins -- including over the 50-cloud-init.conf
  # cloud-init writes for itself whenever ssh_pwauth is set.
  - path: /etc/ssh/sshd_config.d/01-branchleft-hardening.conf
    owner: root:root
    permissions: '0644'
    content: |
      PasswordAuthentication no
      KbdInteractiveAuthentication no
      PermitRootLogin prohibit-password
      PubkeyAuthentication yes`;

const BASE_PACKAGES = ['ca-certificates', 'curl', 'gnupg'] as const;

/**
 * What an enrolled host needs on it before the pull can run: `git`, `gpg` and
 * `gpgconf` and `openssh-client` for the pull program (the `pull_trigger_packages`
 * of that role), and `python3` and `python3-venv` for the Ansible install (the
 * `ansible_runtime_packages` of that role). `curl` and `ca-certificates` are in the
 * base list. `ansible/tools/test_pull_bootstrap.py` holds this list equal to the
 * two roles' lists, so a package added to a role fails there until it is added
 * here.
 *
 * The engine itself is never in this list: it is installed by the pinned,
 * hash-checked program, and by nothing that resolves its own version.
 */
export const ENROLMENT_PACKAGES = [
  'git',
  'gpg',
  'gpgconf',
  'openssh-client',
  'python3',
  'python3-venv',
] as const;

const RUNCMD_BASE = `  - [ install, -d, -m, '0755', -o, root, -g, root, /etc/branchleft ]
  - [ install, -d, -m, '0755', -o, root, -g, root, /opt/branchleft ]
  # Absolute path: runcmd's exec form does not go through a login shell, and
  # sbin is not on the PATH cloud-init runs with on Debian.
  - [ /usr/sbin/sshd, -t ]
  - [ systemctl, reload, ssh ]`;

function packageLines(packages: readonly string[]): string {
  return packages.map((name) => `  - ${name}`).join('\n');
}

// ---------------------------------------------------------------------------
// Enrolment
// ---------------------------------------------------------------------------

/** Where an enrolled host puts things. Production uses `PRODUCTION_LAYOUT`; the tests use a temporary one. */
export interface EnrolmentLayout {
  markerDir: string;
  workDir: string;
  failureMarker: string;
  doneMarker: string;
  wrapperPath: string;
  configDir: string;
  configPath: string;
  stateDir: string;
  logDir: string;
  runtimeRoot: string;
  runtimeLink: string;
  python: string;
  /** `-o root -g root` on a host; empty only where a test cannot be root. */
  ownerFlags: string;
}

// The paths the two roles keep (pull_trigger's vars, ansible_runtime's defaults) are written
// here as well, because a first boot has no Ansible to read them from.
// `ansible/tools/test_pull_bootstrap.py` holds each equal to the role variable that owns it, so
// a role path that moves fails there until it is changed here.
export const PRODUCTION_LAYOUT: EnrolmentLayout = {
  markerDir: '/var/lib/branchleft',
  workDir: '/var/lib/branchleft/pull-enrolment',
  failureMarker: '/var/lib/branchleft/pull-enrolment.failed',
  doneMarker: '/var/lib/branchleft/pull-enrolment.done',
  wrapperPath: '/usr/local/sbin/pull-trigger',
  configDir: '/etc/pull-trigger',
  configPath: '/etc/pull-trigger/config.json',
  stateDir: '/var/lib/pull-trigger',
  logDir: '/var/log/pull-trigger',
  runtimeRoot: '/opt/ansible-runtime',
  runtimeLink: '/usr/local/bin/ansible-playbook',
  python: '/usr/bin/python3',
  ownerFlags: '-o root -g root',
};

// The values the record's checks hold fixed live once, in `pullBootstrapFixed.json`.
// `ansible/tools/pull_bootstrap.py` reads the same file to build the record, so a
// path that moves is changed in one place and not in two languages.
const REPOSITORY_RAW = fixed.rawBase;
const REMOTE_URL = fixed.remoteUrl;
const EDGE_PLAYBOOK = fixed.playbook;
const FETCHED_PATHS = fixed.fetched;
const COMMIT_HEX = /^[0-9a-f]{40}$/;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const CONFIG_HEREDOC = 'BRANCHLEFT_CONFIG_EOF';
const MAX_CONFIG_CHARS = 16_384;
const PGP_BEGIN = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
const PGP_END = '-----END PGP PUBLIC KEY BLOCK-----';
const PGP_PUBLIC_KEY_TAG = 6;
// The packets a public key block is made of (RFC 4880, section 4.3): signature (2),
// public key (6), user id (13), public subkey (14) and user attribute (17). The secret
// key (5) and secret subkey (7) packets are not among them, nor is anything else.
const PGP_PUBLIC_PACKET_TAGS: ReadonlySet<number> = new Set([2, PGP_PUBLIC_KEY_TAG, 13, 14, 17]);
const LAYOUT_VALUE = /^[A-Za-z0-9_./-]+$/;
const REQUIRED_CONFIG_KEYS: readonly string[] = fixed.requiredConfigKeys;

type PlainRecord = Record<string, unknown>;

function isRecord(value: unknown): value is PlainRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function assertExactKeys(record: PlainRecord, keys: readonly string[], what: string): void {
  const actual = Object.keys(record).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${what} must have exactly the keys ${expected.join(', ')}.`);
  }
}

function packetByte(bytes: Buffer, at: number): number {
  const byte = bytes[at];
  if (byte === undefined) {
    throw new Error('A signer key block ends in the middle of an OpenPGP packet.');
  }
  return byte;
}

/**
 * The type of every packet in a block's data, read by walking each packet's own
 * header and length to the next, so that the whole of the data is accounted for
 * and a packet is never skipped over.
 *
 * Partial and indeterminate lengths belong to streamed data and not to a key, so
 * both are refused: with either, where the next packet starts could not be known
 * without trusting the data.
 */
function pgpPacketTags(bytes: Buffer): number[] {
  const tags: number[] = [];
  let at = 0;
  while (at < bytes.length) {
    const header = packetByte(bytes, at);
    at += 1;
    if ((header & 0x80) === 0) {
      throw new Error('A signer key block must start with an OpenPGP packet.');
    }
    let tag: number;
    let length = 0;
    if ((header & 0x40) !== 0) {
      tag = header & 0x3f;
      const first = packetByte(bytes, at);
      at += 1;
      if (first < 192) {
        length = first;
      } else if (first < 224) {
        length = ((first - 192) << 8) + packetByte(bytes, at) + 192;
        at += 1;
      } else if (first === 255) {
        for (let index = 0; index < 4; index += 1) {
          length = length * 256 + packetByte(bytes, at + index);
        }
        at += 4;
      } else {
        throw new Error('A signer key block must not use a partial packet length.');
      }
    } else {
      tag = (header >> 2) & 0x0f;
      const lengthType = header & 0x03;
      if (lengthType === 3) {
        throw new Error('A signer key block must not use an indeterminate packet length.');
      }
      const width = 1 << lengthType;
      for (let index = 0; index < width; index += 1) {
        length = length * 256 + packetByte(bytes, at + index);
      }
      at += width;
    }
    if (at + length > bytes.length) {
      throw new Error('A signer key block ends in the middle of an OpenPGP packet.');
    }
    at += length;
    tags.push(tag);
  }
  return tags;
}

/**
 * Refuses anything but an armoured OpenPGP **public** key block.
 *
 * The signer block ends up in user-data, which is readable by anything on the
 * host and by whoever can read the Hetzner project. The checks are an allowlist
 * and not a scan for the word PRIVATE: exactly one public header and one public
 * footer, nothing else that looks like an armour line, a first packet that is a
 * public key (tag 6), and then every packet of the data, walked header by header,
 * of a type that a public key is made of (public key, public subkey, user id,
 * user attribute, signature). A secret key (tag 5) or a secret subkey (tag 7)
 * anywhere in the data, after a public key or not, does not pass.
 */
export function assertPgpPublicKeyBlock(block: string): string {
  const lines = block.endsWith('\n') ? block.slice(0, -1).split('\n') : block.split('\n');
  if (lines[0] !== PGP_BEGIN || lines[lines.length - 1] !== PGP_END) {
    throw new Error('A signer key must be one armoured OpenPGP public key block and nothing else.');
  }
  const inner = lines.slice(1, -1);
  if (inner.some((line) => line.includes('-----'))) {
    throw new Error('A signer key block must not contain any other armour line.');
  }
  const blank = inner.indexOf('');
  if (blank < 0) {
    throw new Error('A signer key block must have a blank line before its data.');
  }
  const data = inner.slice(blank + 1).filter((line) => !line.startsWith('='));
  if (data.length === 0 || !data.every((line) => /^[A-Za-z0-9+/]+={0,2}$/.test(line))) {
    throw new Error('A signer key block must hold base64 data.');
  }
  const tags = pgpPacketTags(Buffer.from(data.join(''), 'base64'));
  if (tags[0] === undefined) {
    throw new Error('A signer key block must start with an OpenPGP packet.');
  }
  if (tags[0] !== PGP_PUBLIC_KEY_TAG) {
    throw new Error('The first packet of a signer key must be a public key, not a secret key.');
  }
  const stray = tags.find((tag) => !PGP_PUBLIC_PACKET_TAGS.has(tag));
  if (stray !== undefined) {
    throw new Error(
      `A signer key block holds an OpenPGP packet of type ${stray}, which is not part of a public key.`
    );
  }
  return block;
}

function assertConfig(config: unknown): string {
  if (typeof config !== 'string' || config.length === 0 || config.length > MAX_CONFIG_CHARS) {
    throw new Error('The bootstrap config must be a non-empty string of bounded size.');
  }
  if (!/^[\x20-\x7e\n]+$/.test(config) || !config.endsWith('\n')) {
    throw new Error('The bootstrap config must be printable ASCII and end with a newline.');
  }
  if (config.split('\n').includes(CONFIG_HEREDOC)) {
    throw new Error('The bootstrap config must not contain the line that ends its heredoc.');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(config);
  } catch {
    throw new Error('The bootstrap config must be JSON.');
  }
  if (!isRecord(parsed)) {
    throw new Error('The bootstrap config must be a JSON object.');
  }
  for (const key of REQUIRED_CONFIG_KEYS) {
    if (!(key in parsed)) {
      throw new Error(`The bootstrap config has no ${key}.`);
    }
  }
  const fixed: Record<string, string> = {
    remote_url: REMOTE_URL,
    playbook: EDGE_PLAYBOOK,
    ansible_playbook: PRODUCTION_LAYOUT.runtimeLink,
    state_dir: PRODUCTION_LAYOUT.stateDir,
    log_dir: PRODUCTION_LAYOUT.logDir,
  };
  for (const [key, expected] of Object.entries(fixed)) {
    if (parsed[key] !== expected) {
      throw new Error(`The bootstrap config's ${key} must be ${expected}.`);
    }
  }
  const playbooks = parsed.playbooks;
  if (!Array.isArray(playbooks) || playbooks.length !== 1 || playbooks[0] !== EDGE_PLAYBOOK) {
    throw new Error(`The bootstrap config's playbooks must be exactly ${EDGE_PLAYBOOK}.`);
  }
  const signers = parsed.signers;
  if (!Array.isArray(signers) || signers.length === 0) {
    throw new Error('The bootstrap config must name at least one signer.');
  }
  for (const signer of signers) {
    if (!isRecord(signer)) {
      throw new Error('Each signer must be an object.');
    }
    assertExactKeys(signer, ['format', 'key'], 'A signer');
    if (signer.format !== 'openpgp' || typeof signer.key !== 'string') {
      throw new Error('Each signer must be an OpenPGP key; no other format is enrolled yet.');
    }
    assertPgpPublicKeyBlock(signer.key);
  }
  for (const key of ['timeout_seconds', 'keep_runs'] as const) {
    const value = parsed[key];
    if (typeof value !== 'number' || !Number.isInteger(value) || value <= 0) {
      throw new Error(`The bootstrap config's ${key} must be a positive integer.`);
    }
  }
  return config;
}

/**
 * Refuses a bootstrap record that is not exactly what `pull_bootstrap.py` writes.
 *
 * Each file's address must name the pin recorded beside it and the file's own
 * path, so a record cannot fetch a different commit's file than the one whose
 * hash it holds.
 */
export function assertPullBootstrap(value: unknown): PullBootstrap {
  if (!isRecord(value)) {
    throw new Error('The bootstrap record must be an object.');
  }
  assertExactKeys(
    value,
    ['schema', 'wrapper', 'program', 'lock', 'config'],
    'The bootstrap record'
  );
  if (value.schema !== 1) {
    throw new Error('The bootstrap record must be schema 1.');
  }
  for (const name of ['wrapper', 'program', 'lock'] as const) {
    const entry = value[name];
    if (!isRecord(entry)) {
      throw new Error(`The bootstrap ${name} must be an object.`);
    }
    assertExactKeys(entry, ['pin', 'sha256', 'url'], `The bootstrap ${name}`);
    if (typeof entry.pin !== 'string' || !COMMIT_HEX.test(entry.pin)) {
      throw new Error(`The bootstrap ${name} pin must be a full commit id.`);
    }
    if (typeof entry.sha256 !== 'string' || !SHA256_HEX.test(entry.sha256)) {
      throw new Error(`The bootstrap ${name} sha256 must be 64 lowercase hex digits.`);
    }
    if (entry.url !== `${REPOSITORY_RAW}/${entry.pin}/${FETCHED_PATHS[name]}`) {
      throw new Error(
        `The bootstrap ${name} url must name its own pin and ${FETCHED_PATHS[name]}.`
      );
    }
  }
  assertConfig(value.config);
  return value as unknown as PullBootstrap;
}

function assertEnrolmentKey(name: string, key: unknown): string {
  if (typeof key !== 'string') {
    throw new Error(`${name} must be a string.`);
  }
  try {
    return assertDeployPublicKey(key);
  } catch {
    throw new Error(
      `${name} must be a single-line OpenSSH public key. It is substituted into a cloud-config document, so a value spanning more than one line is rejected rather than escaped.`
    );
  }
}

/** Checks an enrolment before anything is rendered or created. */
export function assertEnrolment(enrolment: Enrolment): Enrolment {
  const apply = assertEnrolmentKey('enrolment.applyPublicKey', enrolment.applyPublicKey);
  const check = assertEnrolmentKey('enrolment.checkPublicKey', enrolment.checkPublicKey);
  if (apply === check) {
    throw new Error(
      'enrolment.applyPublicKey and enrolment.checkPublicKey must be different keys: the check key must not be able to apply.'
    );
  }
  assertPullBootstrap(enrolment.bootstrap);
  return enrolment;
}

function authorizedLine(key: string, mode: 'apply' | 'check', layout: EnrolmentLayout): string {
  return `restrict,command="${layout.wrapperPath} --mode ${mode}" ${key}`;
}

/**
 * The shell script that brings a host under the pull. It is one `sh -c`
 * entry of `runcmd`, and it is the last one.
 *
 * Order matters and is the whole control. All three files are fetched and each
 * is checked against its recorded SHA-256 first; only then does the install
 * program run; after it has succeeded the state directories and the
 * configuration are put in place; the pull program is placed last of all, as
 * the final step before the done marker. A failure anywhere writes the step it
 * failed at to a marker file and stops.
 *
 * What a failure leaves depends on where it happened, and each state is safe:
 * before `install-engine` the host has nothing installed; at or after it the
 * host may have the `ansible-playbook` link, which is the hash-locked engine
 * and never another, and possibly the directories and the configuration, but
 * never the pull program unless every earlier step succeeded. The two
 * command-restricted keys name the pull program's path, so while it is absent
 * they run nothing, and the owner's keys are the only way in. There is no
 * fallback that installs an engine that is not hash-locked.
 */
export function renderEnrolmentScript(
  bootstrap: PullBootstrap,
  layout: EnrolmentLayout = PRODUCTION_LAYOUT
): string {
  assertPullBootstrap(bootstrap);
  for (const value of Object.values(layout)) {
    if (!(value === '' || LAYOUT_VALUE.test(value) || value === '-o root -g root')) {
      throw new Error(`The enrolment layout holds a value that is not a plain path: ${value}`);
    }
  }
  const owner = layout.ownerFlags === '' ? '' : ` ${layout.ownerFlags}`;
  const check = (name: keyof typeof FETCHED_PATHS, file: string): string =>
    `step=check-${name}; check ${file} '${bootstrap[name].sha256}'`;
  const fetch = (name: keyof typeof FETCHED_PATHS, file: string): string =>
    `step=fetch-${name}; fetch '${bootstrap[name].url}' "$work/${file}"`;
  return [
    'set -eu',
    `work='${layout.workDir}'`,
    `failed='${layout.failureMarker}'`,
    `finished='${layout.doneMarker}'`,
    'step=start',
    `install -d -m 0755${owner} '${layout.markerDir}'`,
    'on_exit() {',
    '  status=$?',
    '  if [ "$status" -ne 0 ]; then',
    '    printf "failed at %s\\n" "$step" > "$failed" || true',
    '  fi',
    '}',
    'trap on_exit EXIT',
    'rm -f "$failed" "$finished"',
    `install -d -m 0700${owner} "$work"`,
    'fetch() {',
    '  curl --fail --silent --show-error --proto \'=https\' --tlsv1.2 --retry 3 --max-time 120 --output "$2" "$1"',
    '}',
    'check() {',
    '  printf "%s  %s\\n" "$2" "$1" | (cd "$work" && sha256sum -c --strict -)',
    '}',
    fetch('wrapper', 'pull_trigger.py'),
    fetch('program', 'install_runtime.py'),
    fetch('lock', 'requirements.txt'),
    check('wrapper', 'pull_trigger.py'),
    check('program', 'install_runtime.py'),
    check('lock', 'requirements.txt'),
    'step=install-engine',
    `'${layout.python}' -I "$work/install_runtime.py" --lock "$work/requirements.txt" --lock-sha256 '${bootstrap.lock.sha256}' --root '${layout.runtimeRoot}' --link '${layout.runtimeLink}'`,
    'step=write-config',
    `install -d -m 0755${owner} '${layout.configDir}'`,
    `install -d -m 0700${owner} '${layout.stateDir}' '${layout.logDir}'`,
    `cat > "$work/config.json" <<'${CONFIG_HEREDOC}'`,
    `${bootstrap.config}${CONFIG_HEREDOC}`,
    `install -m 0644${owner} "$work/config.json" '${layout.configPath}'`,
    'step=install-trigger',
    `install -m 0755${owner} "$work/pull_trigger.py" '${layout.wrapperPath}'`,
    'step=done',
    'printf "ok\\n" > "$finished"',
    '',
  ].join('\n');
}

const ENROLMENT_RUNCMD_COMMENT = `  # Last, and on its own: runcmd is one shell script with no errexit, so a
  # failure here cannot skip the lines above it, and it stops at its own first
  # failure. It brings the host under the gated pull (see renderEnrolmentScript).`;

function renderEnrolment(args: CloudInitArgs, enrolment: Enrolment): pulumi.Output<string> {
  const applyLine = authorizedLine(enrolment.applyPublicKey, 'apply', PRODUCTION_LAYOUT);
  const checkLine = authorizedLine(enrolment.checkPublicKey, 'check', PRODUCTION_LAYOUT);
  const script = renderEnrolmentScript(enrolment.bootstrap);
  const packages = [...BASE_PACKAGES, ...ENROLMENT_PACKAGES];
  return pulumi.interpolate`#cloud-config
hostname: ${args.hostname}
preserve_hostname: false
fqdn: ${args.hostname}
${args.privateOnly ? PRIVATE_ONLY_BOOTCMD : ''}
disable_root: false

users:
${USERS_DEFAULT_ENTRY}
  # Root's keys are written here and not through write_files, so the key the
  # datasource injects for the owner stays: write_files would replace the file.
  #
  # lock_passwd defaults to true in cloud-init and is applied to an account
  # that already exists, which would lock root's password. Key access is not
  # affected, but the provider console login is the break-glass way in when
  # sshd is down, so this entry leaves the password as the image has it.
  - name: root
    lock_passwd: false
    ssh_authorized_keys:
      - ${JSON.stringify(applyLine)}
      - ${JSON.stringify(checkLine)}

write_files:
${HARDENING_ENTRY}

package_update: true
packages:
${packageLines(packages)}

runcmd:
${RUNCMD_BASE}
${ENROLMENT_RUNCMD_COMMENT}
  - [ sh, -c, ${JSON.stringify(script)} ]
`;
}

export function renderCloudInit(args: CloudInitArgs): pulumi.Output<string> {
  if (args.enrolment !== undefined) {
    if (args.deployPublicKey !== undefined) {
      throw new Error(
        'A host with an enrolment has no deploy account: remove deployPublicKey or remove the enrolment. ' +
          'The pull is the deploy path for an enrolled host, and a deploy key beside it would be a second way in with root-equivalent reach.'
      );
    }
    return renderEnrolment(args, assertEnrolment(args.enrolment));
  }
  if (args.deployPublicKey === undefined) {
    throw new Error(
      'deployPublicKey is required unless the host has an enrolment: without either it has no automated way in.'
    );
  }
  // Checked twice, and the eager half is the one that behaves well. In
  // practice this value is a plain string from stack config, and validating it
  // here throws from the constructor — the program stops with the message
  // above and nothing is created. Inside an `apply` the same throw surfaces
  // during resource serialization instead, which Pulumi reports as an
  // unhandled rejection attached to a different property's name. The apply is
  // kept for the case where a caller genuinely passes an `Output`.
  if (typeof args.deployPublicKey === 'string') {
    assertDeployPublicKey(args.deployPublicKey);
  }
  const deployPublicKey = pulumi.output(args.deployPublicKey).apply(assertDeployPublicKey);
  return pulumi.interpolate`#cloud-config
hostname: ${args.hostname}
preserve_hostname: false
fqdn: ${args.hostname}
${args.privateOnly ? PRIVATE_ONLY_BOOTCMD : ''}
disable_root: false

users:
${USERS_DEFAULT_ENTRY}
  - name: deploy
    gecos: CI deploy account
    shell: /bin/bash
    lock_passwd: true
    sudo: false
    ssh_authorized_keys:
      - ${AUTHORIZED_KEY_OPTIONS} ${deployPublicKey}

write_files:
  - path: /etc/sudoers.d/50-branchleft-deploy
    owner: root:root
    permissions: '0440'
    content: |
      ${DEPLOY_SUDOERS}
${HARDENING_ENTRY}

package_update: true
packages:
${packageLines(BASE_PACKAGES)}

runcmd:
${RUNCMD_BASE}
`;
}
