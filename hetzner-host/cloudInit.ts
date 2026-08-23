import * as pulumi from '@pulumi/pulumi';

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
   * compromised runner secret scoped to one machine. */
  deployPublicKey: pulumi.Input<string>;
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
}

/**
 * `restrict` is the whole-set deny (no agent forwarding, no port forwarding,
 * no X11, no pty, no user-rc), with nothing added back. A forced command is
 * the tighter option and is not used yet because the deploy verb set is
 * still moving; the sudo allow-list below is what bounds the key's power in
 * the meantime, and it grants exactly one binary.
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
 * Two `runcmd` entries that give a private-only host a working default route
 * and resolver before `package_update` below runs.
 *
 * `runcmd`'s own module runs ahead of package installation in cloud-init's
 * default module ordering, which is what makes this placement work at all --
 * moving these into `write_files`/`bootcmd` territory is not needed and
 * `bootcmd` would be wrong regardless, since it re-runs on every boot and
 * this file's whole premise is that nothing here survives past first boot.
 * Durable persistence across every later reboot is
 * `provision/05-configure-host-egress.sh`'s job, once it has been run.
 *
 * Exec form is avoided here (unlike the plain commands below) because the
 * gateway has to be derived from the routing table, which needs a shell.
 * Every string literal in the embedded awk/shell is double-quoted rather
 * than single-quoted so that wrapping the whole command in a YAML
 * double-quoted scalar needs no nested-quote gymnastics beyond escaping
 * those doubles for YAML itself.
 */
const PRIVATE_ONLY_RUNCMD = `
  # A private-only host has no public interface, so its only route off the
  # subnet is the network's own gateway -- and Hetzner's DHCP delivers the
  # subnet route but never a default (hetzner/egress.ts). First boot only:
  # provision/05-configure-host-egress.sh (and the systemd unit it installs)
  # is what keeps this true across every later reboot.
  - [ sh, -c, "GW=$(ip -4 route show | awk '$1 != \\"default\\" && $1 != \\"169.254.169.254\\" { for (i=1;i<=NF;i++) if ($i==\\"via\\") { print $(i+1); exit } }'); [ -n \\"$GW\\" ] && ip route replace default via \\"$GW\\" || true" ]
  - [ sh, -c, "mkdir -p /etc/resolvconf/resolv.conf.d && { echo 'nameserver 185.12.64.1'; echo 'nameserver 185.12.64.2'; } > /etc/resolvconf/resolv.conf.d/head && resolvconf -u || true" ]`;

export function renderCloudInit(args: CloudInitArgs): pulumi.Output<string> {
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

disable_root: false

users:
  # The default entry comes first, always. A users block that omits it
  # replaces the image's default account rather than adding to it, and the
  # keys Hetzner injects through the datasource follow that default account.
  # Omitting it produces a host with the deploy key installed and no owner
  # access at all.
  - default
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
  # Duplicated by provision/00-harden-ssh.sh on purpose, not by oversight.
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
      PubkeyAuthentication yes

package_update: true
packages:
  - ca-certificates
  - curl
  - gnupg

runcmd:${args.privateOnly ? PRIVATE_ONLY_RUNCMD : ''}
  - [ install, -d, -m, '0755', -o, root, -g, root, /etc/branchleft ]
  - [ install, -d, -m, '0755', -o, root, -g, root, /opt/branchleft ]
  # Absolute path: runcmd's exec form does not go through a login shell, and
  # sbin is not on the PATH cloud-init runs with on Debian.
  - [ /usr/sbin/sshd, -t ]
  - [ systemctl, reload, ssh ]
`;
}
