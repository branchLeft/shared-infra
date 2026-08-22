import * as hcloud from '@pulumi/hcloud';
import * as pulumi from '@pulumi/pulumi';

import type { EuCentralLocation } from './addressPlan';
import { renderCloudInit } from './cloudInit';
import { EDGE_RULES, INTERNAL_RULES } from './firewalls';

/**
 * The create pattern for a platform host: server, firewall, private-network
 * attachment at a fixed address.
 *
 * This is the piece the mx1 stack does not provide. That stack *imports* a
 * hand-built server and is written to never create or replace it, and its
 * `ignoreChanges` on `publicNets` and `firewallIds` exists to make a
 * pre-existing machine reconcile cleanly — neither generalises to a machine
 * this program creates, where both are inputs rather than facts to be
 * tolerated. `sshKeys` and `image` are different: they are create-time-only
 * at the provider regardless of how the server came to exist, and both are
 * ignored here for that reason rather than by inheritance.
 *
 * Consumed by the per-role host stacks rather than instantiated here: the
 * network must never share a stack with anything applied on a delivery
 * cadence, so this project declares the pattern and creates no host with it.
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
  deployPublicKey: pulumi.Input<string>;
  networkId: pulumi.Input<string>;
  /** Fixed private address from the estate's address plan. */
  privateIp: pulumi.Input<string>;
  /**
   * Whether the host gets public addresses at all. Defaulted on because the
   * deploy path is SSH from GitHub-hosted runners, and a host CI must reach
   * needs a public address to reach.
   *
   * A host no deploy path touches should set this to `false` and be reached
   * over the private network from a host that does. Only the hosts that
   * terminate public traffic need an address of their own; every other public
   * address that exists is a standing exception to that. Doing so means accepting that recovery is the Hetzner console.
   *
   * **Choose this at creation.** Flipping it from `true` to `false` on a
   * live host removes two delete-protected primary IPs from the program, and
   * the API refuses to delete them — which wedges the stack mid-update. To
   * change it later, apply once with `protection: false` so the protection
   * comes off, then apply again with `publicNetworking: false`.
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
     * Declared as their own resources rather than left to Hetzner's
     * server-creation allocation, which sets `auto_delete` and releases the
     * address back to the pool when the server goes.
     *
     * That is not survivable here. The DNS zone is manual at a registrar with
     * no API, and certificate issuance is HTTP-01, so an address that changes
     * cannot be repaired by a program: every record has to be hand-edited and
     * propagate before any hostname can reissue. The rebuild that this
     * component deliberately permits would otherwise take the whole estate's
     * public reachability with it.
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
        userData: renderCloudInit({
          hostname: args.name,
          deployPublicKey: args.deployPublicKey,
        }),
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
        // A private-only host must carry its network interface at first
        // boot: with no public interface and no inline network, Hetzner
        // refuses to start the server at all ("no public or private network
        // interfaces found"). The separate ServerNetwork attachment below is
        // created only after the server exists, which is too late for that
        // case — so a private-only host attaches inline here and skips the
        // separate resource. A public host keeps the separate attachment:
        // moving a live host between the two shapes plans a detach/attach,
        // so the shape is fixed at creation. `aliasIps: []` is required —
        // left undefined, the provider detaches and reattaches the network
        // on every apply (upstream provider issue #650).
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
