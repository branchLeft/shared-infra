import * as hcloud from '@pulumi/hcloud';
import * as pulumi from '@pulumi/pulumi';

import type { EuCentralLocation } from './addressPlan';
import { renderCloudInit } from './cloudInit';
import type { Enrolment } from './cloudInit';
import { EDGE_RULES, INTERNAL_RULES, sshRestrictedRules } from './firewalls';

/**
 * The create pattern for a platform host: server, firewall, private-network attachment
 * at a fixed address. Per-role host stacks consume it; this project creates no host.
 * The reasoning: hetzner-host/README.md, "Notes kept from the source".
 */

export type HostRole = 'edge' | 'app' | 'db' | 'mon';

/**
 * Adopt a server the owner made by hand instead of creating one.
 *
 * Adoption is two stages, because Pulumi refuses an import whose inputs differ
 * from the live resource, and a console-made server differs from this component's
 * declaration in exactly the properties the component sets itself (protection,
 * labels, address names). `import` imports with those properties left alone;
 * `converge` is the same program with them declared, an ordinary in-place update.
 * `publicNets` is the exception: ignored at both stages, because the provider never
 * reads it into state and would power the server off and delete its primary IP.
 * Stay on `converge` for the life of the host: the ids stay, and the firewall
 * attachment below is part of how the host is held, so removing adoption config
 * would detach the firewall.
 */
export interface AdoptArgs {
  /** The live Hetzner server's numeric id, as a string: Pulumi's `import` takes a literal, never an output. */
  serverId: string;
  /** The live primary IPv4's id. Required with public networking, refused without it. */
  ipv4Id?: string;
  /** The live primary IPv6's id. Required with public networking, refused without it. */
  ipv6Id?: string;
  /** Defaults to `import`. */
  stage?: 'import' | 'converge';
}

const HETZNER_ID = /^[1-9][0-9]{0,15}$/;

/**
 * Properties a console-made server or primary IP differs on, and which the
 * `converge` stage then updates in place. Ignored while importing, so the import
 * is checked against identity (name, type, location, addresses) and nothing the
 * component merely sets.
 */
const IMPORT_STAGE_IGNORED_SERVER = ['deleteProtection', 'rebuildProtection', 'labels'] as const;
/** A private-only host's network is left to the owner's console steps until `converge`. */
const IMPORT_STAGE_IGNORED_PRIVATE_SERVER = ['networks'] as const;
const IMPORT_STAGE_IGNORED_PRIMARY_IP = [
  'name',
  'autoDelete',
  'deleteProtection',
  'labels',
] as const;

function adoptionId(host: string, field: string, value: unknown): string {
  const id = typeof value === 'number' ? String(value) : value;
  if (typeof id !== 'string' || !HETZNER_ID.test(id)) {
    throw new Error(
      `${host}: adopt.${field} must be the numeric Hetzner id (digits only, no leading zero); got ${JSON.stringify(value)}.`
    );
  }
  return id;
}

/** Checks the adoption input before any resource exists, and returns it with plain-string ids. */
export function assertAdoption(
  host: string,
  adopt: AdoptArgs,
  publicNetworking: boolean
): AdoptArgs {
  const stage = adopt.stage ?? 'import';
  if (stage !== 'import' && stage !== 'converge') {
    throw new Error(
      `${host}: adopt.stage must be "import" or "converge"; got ${JSON.stringify(stage)}.`
    );
  }
  const serverId = adoptionId(host, 'serverId', adopt.serverId);
  if (!publicNetworking) {
    if (adopt.ipv4Id !== undefined || adopt.ipv6Id !== undefined) {
      throw new Error(
        `${host} has no public networking, so it declares no primary IP for adopt.ipv4Id or adopt.ipv6Id to import. ` +
          'A public address left on the live server is removed by hand and deleted, not adopted.'
      );
    }
    return { serverId, stage };
  }
  if (adopt.ipv4Id === undefined || adopt.ipv6Id === undefined) {
    throw new Error(
      `${host} has public networking, so adopting it needs adopt.ipv4Id and adopt.ipv6Id: ` +
        'without them the component would create a second pair of addresses beside the live ones.'
    );
  }
  return {
    serverId,
    ipv4Id: adoptionId(host, 'ipv4Id', adopt.ipv4Id),
    ipv6Id: adoptionId(host, 'ipv6Id', adopt.ipv6Id),
    stage,
  };
}

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
  /**
   * Narrows the role's SSH rule to this one public IPv4 address (as a /32).
   * Absent, the rule set is the role's own, byte for byte. Present, it is the
   * same set with the SSH source replaced and nothing else changed: the input
   * can narrow SSH and cannot widen a source or add a port, which is why it is
   * a typed address and not a free list of rules. A bare dotted-quad only; a
   * CIDR, an IPv6 address, a hostname or a private, loopback, link-local,
   * shared or reserved address is refused. A plain string is refused before any
   * resource exists; an output (another stack's value) is checked when it
   * resolves. Refused on a host with no public networking, which has no public
   * SSH rule to narrow.
   */
  sshSourceIp?: pulumi.Input<string>;
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
  /**
   * Adopt a server (and, for a public host, its two primary IPs) that already
   * exists, instead of creating them. See `AdoptArgs`. Absent, every resource is
   * created exactly as before. `userData`, `sshKeys` and `image` are ignored
   * either way, so cloud-init does not run on an adopted host: whatever it would
   * have done is the owner's hand bootstrap.
   */
  adopt?: AdoptArgs;
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

    const roleRules = args.role === 'edge' ? EDGE_RULES : INTERNAL_RULES;
    const wantsPublicNetworking = args.publicNetworking ?? true;
    if (args.sshSourceIp !== undefined && !wantsPublicNetworking) {
      throw new Error(
        `${args.name} has no public networking, so it has no public SSH rule for sshSourceIp to narrow.`
      );
    }
    const adopt =
      args.adopt === undefined
        ? undefined
        : assertAdoption(args.name, args.adopt, wantsPublicNetworking);
    const importing = adopt !== undefined && adopt.stage === 'import';
    let rules: pulumi.Input<hcloud.types.input.FirewallRule[]> = roleRules;
    if (typeof args.sshSourceIp === 'string') {
      rules = sshRestrictedRules(roleRules, args.sshSourceIp);
    } else if (args.sshSourceIp !== undefined) {
      rules = pulumi.output(args.sshSourceIp).apply((ip) => sshRestrictedRules(roleRules, ip));
    }
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
          autoDelete: false,
          deleteProtection: protection,
          labels,
        },
        {
          parent: this,
          import: adopt?.ipv4Id,
          ignoreChanges: importing ? [...IMPORT_STAGE_IGNORED_PRIMARY_IP] : undefined,
        }
      );

      this.primaryIpv6 = new hcloud.PrimaryIp(
        `${args.name}-ipv6`,
        {
          name: `${args.name}-ipv6`,
          type: 'ipv6',
          location: args.location,
          autoDelete: false,
          deleteProtection: protection,
          labels,
        },
        {
          parent: this,
          import: adopt?.ipv6Id,
          ignoreChanges: importing ? [...IMPORT_STAGE_IGNORED_PRIMARY_IP] : undefined,
        }
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
        //
        // An adopted server is the exception: its firewalls were attached when the
        // owner made it, `firewallIds` is create-time intent at the provider, and
        // the firewall of a public adopted server is attached by `FirewallAttachment`
        // below instead, in addition to the owner's no-inbound one, which the owner
        // detaches only afterwards. A private-only host gets no attachment (see below).
        firewallIds: adopt === undefined ? [this.firewall.id.apply((id) => Number(id))] : undefined,
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
        import: adopt?.serverId,
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
          // An adopted server keeps whatever firewalls the console attached to it, and the
          // owner detaches the holding one by hand. Not declared above, so there is nothing
          // for this to ignore until a refresh reads the live set; the entry is what keeps
          // the stack from ever planning to rewrite it.
          ...(adopt === undefined ? [] : ['firewallIds']),
          // An adopted server never has a public interface in state: the provider's read
          // does not set it, so the first apply sees the declared `publicNets` as changed
          // and runs its public-interface update. That update powers the server off, then
          // unassigns the primary IP on it and, because the old set held no address id,
          // deletes that primary IP before trying to assign the id it just deleted. It
          // would take a live address from a running host, at either stage and on a
          // private-only host too. The addresses are held by the imported `PrimaryIp`
          // resources above, which is where they are checked and updated.
          ...(adopt === undefined ? [] : ['publicNets']),
          ...(importing ? IMPORT_STAGE_IGNORED_SERVER : []),
          ...(importing && !wantsPublicNetworking ? IMPORT_STAGE_IGNORED_PRIVATE_SERVER : []),
        ],
      }
    );

    // The firewall of an adopted public server. Attached in addition to the firewalls already
    // on the server, never in place of them, so the server is filtered at every moment: the
    // owner's holding firewall (no inbound rule at all) stays on until this one is attached
    // and checked, and is detached by hand after.
    //
    // A private-only host gets no attachment at any stage. A Hetzner Cloud Firewall filters
    // only a server's public interface, and a private-only host has none, so the provider
    // refuses the attachment: "no public network interfaces found, firewall cannot be attached
    // to server with ID ... (private_net_only_server...)". The stack's own Firewall for the
    // host is still declared, since it costs nothing and keeps its live object from being
    // deleted. The owner's `hold-no-inbound` stays on the host as an inert second line: it
    // filters nothing now, and would again if a public interface were ever added.
    if (adopt !== undefined && wantsPublicNetworking) {
      new hcloud.FirewallAttachment(
        `${args.name}-firewall-attachment`,
        {
          firewallId: this.firewall.id.apply((id) => Number(id)),
          serverIds: [this.server.id.apply((id) => Number(id))],
        },
        { parent: this }
      );
    }

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
