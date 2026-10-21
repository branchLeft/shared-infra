import * as hcloud from '@pulumi/hcloud';
import * as pulumi from '@pulumi/pulumi';

import type { EuCentralLocation } from './addressPlan';
import { renderCloudInit } from './cloudInit';
import type { Enrolment } from './cloudInit';
import { EDGE_RULES, INTERNAL_RULES } from './firewalls';

/**
 * The create pattern for a platform host: server, firewall, private-network attachment
 * at a fixed address. Per-role host stacks consume it; this project creates no host.
 */

export type HostRole = 'edge' | 'app' | 'db' | 'mon';

export interface HostArgs {
  /** Hetzner server name, the hostname, and the prefix of every resource
   * name this component creates. */
  name: string;
  role: HostRole;
  /** Hetzner server type. Not defaulted per role: the type is a cost and
   * capacity decision that belongs in the consuming stack's config where a
   * change to it is visible in that stack's diff. */
  serverType: pulumi.Input<string>;
  /** Hetzner location. Narrowed to the subnet's own network zone: a location
   * outside it produces a server the attachment below cannot reach, and the
   * provider reports that at apply time rather than at preview. As a union it
   * is a compile error, which is only true while nothing widens it back to
   * `string` between here and `hcloud.Server`. */
  location: pulumi.Input<EuCentralLocation>;
  image: pulumi.Input<string>;
  /** Names of SSH keys already registered in the hcloud project. These land
   * on `root` and are the platform owner's provisioning access; the CI
   * deploy key is a separate, non-root identity injected through cloud-init
   * and must never appear in this list. */
  ownerSshKeyNames: pulumi.Input<pulumi.Input<string>[]>;
  /**
   * The CI deploy key's public half. Required unless `enrolment` is set, and
   * refused when it is: an enrolled host is deployed by the pull and has no
   * `deploy` account, so the two never exist together.
   */
  deployPublicKey?: pulumi.Input<string>;
  /**
   * Bring the host under the gated pull at first boot (an `edge` host only).
   * Absent, the first-boot document is exactly what it was before this
   * field. See `Enrolment`.
   */
  enrolment?: Enrolment;
  networkId: pulumi.Input<string>;
  /** Fixed private address from the estate's address plan. */
  privateIp: pulumi.Input<string>;
  /**
   * Defaults on: deploy is SSH from GitHub-hosted runners. Set `false` only on a host no
   * deploy path touches. Choose at creation: flipping it on a live host wedges the stack.
   * To change it later, apply with `protection: false`, then with `publicNetworking: false`.
   */
  publicNetworking?: boolean;
  /**
   * Which estate the host belongs to. Drives the `env` label, so a lab host
   * is not labelled as production — cost attribution and any label-selector
   * firewall rule both read that label, and a lying one is worse than a
   * missing one.
   */
  environment?: 'production' | 'lab';
  /**
   * Delete and rebuild protection, at the API and on the primary IPs.
   *
   * Defaulted on, and must stay on for anything in the production estate.
   * Lab and scratch hosts set it to `false`: with it on, `pulumi destroy`
   * cannot tear a spike down without an edit to this component, which turns
   * every throwaway host into a manual cleanup.
   */
  protection?: boolean;
  /** Hetzner's own daily snapshots. Off by default because they cost 20% of
   * the server price and are not the backup story for anything holding
   * state. Decide the backup story for a stateful host before reaching for
   * this. */
  backups?: pulumi.Input<boolean>;
}

export class Host extends pulumi.ComponentResource {
  public readonly server: hcloud.Server;
  public readonly firewall: hcloud.Firewall;
  /**
   * Present only when the host has public networking. A private-only host
   * carries its network inline on the server (see the `networks` input
   * below), so there is no separate attachment resource to expose.
   */
  public readonly networkAttachment?: hcloud.ServerNetwork;
  public readonly primaryIpv4?: hcloud.PrimaryIp;
  public readonly primaryIpv6?: hcloud.PrimaryIp;
  /**
   * Present only when the host has public networking. Optional rather than
   * an empty string, so a consumer wiring DNS or an SSH target off it fails
   * to compile against a private-only host instead of silently emitting "".
   */
  public readonly publicIpv4?: pulumi.Output<string>;

  constructor(args: HostArgs, opts?: pulumi.ComponentResourceOptions) {
    super('branchleft:hetzner:Host', args.name, {}, opts);

    const rules = args.role === 'edge' ? EDGE_RULES : INTERNAL_RULES;
    const wantsPublicNetworking = args.publicNetworking ?? true;
    const protection = args.protection ?? true;
    const labels = {
      role: args.role,
      env: args.environment ?? 'production',
      'managed-by': 'pulumi',
    };

    // Rendered before any resource is declared. A refused key, a refused
    // enrolment or a role that cannot be enrolled stops the program here, with
    // nothing created: `userData` is create-time-only, so a document accepted
    // by mistake is permanent.
    if (args.enrolment !== undefined && args.role !== 'edge') {
      throw new Error(
        `Only an edge host can be enrolled in the pull; ${args.name} is a ${args.role} host. ` +
          "The pull's playbook is edge1's, and no other role has one."
      );
    }
    const userData = renderCloudInit({
      hostname: args.name,
      deployPublicKey: args.deployPublicKey,
      privateOnly: !wantsPublicNetworking,
      enrolment: args.enrolment,
    });

    this.firewall = new hcloud.Firewall(
      `${args.name}-firewall`,
      {
        name: `${args.name}`,
        rules,
        labels,
      },
      { parent: this }
    );

    /**
     * Declared as their own resources: Hetzner's server-creation allocation releases the
     * address when the server goes, and a changed address breaks HTTP-01 issuance and
     * mail reputation for every hostname that names it.
     */
    if (wantsPublicNetworking) {
      this.primaryIpv4 = new hcloud.PrimaryIp(
        `${args.name}-ipv4`,
        {
          name: `${args.name}-ipv4`,
          type: 'ipv4',
          location: args.location,
          assigneeType: 'server',
          autoDelete: false,
          deleteProtection: protection,
          labels,
        },
        { parent: this }
      );

      this.primaryIpv6 = new hcloud.PrimaryIp(
        `${args.name}-ipv6`,
        {
          name: `${args.name}-ipv6`,
          type: 'ipv6',
          location: args.location,
          assigneeType: 'server',
          autoDelete: false,
          deleteProtection: protection,
          labels,
        },
        { parent: this }
      );
    }

    this.server = new hcloud.Server(
      args.name,
      {
        name: args.name,
        serverType: args.serverType,
        location: args.location,
        image: args.image,
        backups: args.backups ?? false,
        sshKeys: args.ownerSshKeyNames,
        userData,
        // Declared on the server rather than through a separate attachment
        // resource: this is the only place the provider treats the firewall
        // as being in effect from the moment the server first boots. An
        // attachment applied afterwards leaves a window in which a
        // freshly created host is on the public internet unfiltered.
        firewallIds: [this.firewall.id.apply((id) => Number(id))],
        publicNets: [
          wantsPublicNetworking
            ? {
                ipv4Enabled: true,
                ipv4: this.primaryIpv4?.id.apply((id) => Number(id)),
                ipv6Enabled: true,
                ipv6: this.primaryIpv6?.id.apply((id) => Number(id)),
              }
            : { ipv4Enabled: false, ipv6Enabled: false },
        ],
        // A private-only host attaches its network inline: Hetzner refuses to start a server
        // with no interface, and the separate attachment comes too late. `aliasIps: []` is
        // required, or the provider reattaches the network on every apply.
        networks: wantsPublicNetworking
          ? undefined
          : [
              {
                networkId: pulumi.output(args.networkId).apply((id) => Number(id)),
                ip: args.privateIp,
                aliasIps: [],
              },
            ],
        deleteProtection: protection,
        rebuildProtection: protection,
        labels,
      },
      {
        parent: this,
        // Not `protect: true`, which is right for the imported mail host and
        // wrong here: these hosts are cattle whose whole value is that the
        // create pattern can rebuild them. `deleteProtection` makes a destroy
        // a two-step, deliberate act wherever it is on, and the CI apply path
        // carries a plan gate that refuses a destroying preview.
        ignoreChanges: [
          // Changing user-data after creation cannot affect a running host —
          // cloud-init has already run — but the provider treats the field as
          // replacing. Without this, an edit to the cloud-init template
          // proposes rebuilding every host in the estate for no effect.
          'userData',
          // Hetzner reuses an image name across point releases, so the value
          // the API reports drifts on a server that was never rebuilt.
          'image',
          // Create-time only at the provider, which proposes a destroy and
          // recreate for any change. Adding a second owner key would
          // otherwise plan a replacement of every host, which a protected
          // host's API then refuses — leaving the stack wedged mid-update.
          // Keys are added to a running host by writing authorized_keys over
          // SSH; RUNBOOK-provision-host.md carries the procedure, and it is
          // the only path that works on a host this component created.
          'sshKeys',
        ],
      }
    );

    if (wantsPublicNetworking) {
      this.networkAttachment = new hcloud.ServerNetwork(
        `${args.name}-network`,
        {
          serverId: this.server.id.apply((id) => Number(id)),
          networkId: pulumi.output(args.networkId).apply((id) => Number(id)),
          ip: args.privateIp,
        },
        { parent: this }
      );
    }

    // The primary IP's own value where one is declared: it outlives the
    // server, so a consumer that reads it from the server would see it
    // change across a rebuild that does not in fact change the address.
    this.publicIpv4 = this.primaryIpv4?.ipAddress;

    this.registerOutputs({
      serverId: this.server.id,
      firewallId: this.firewall.id,
      privateIp: args.privateIp,
      publicIpv4: this.publicIpv4,
    });
  }
}
