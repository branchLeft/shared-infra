import * as pulumi from '@pulumi/pulumi';
import { beforeAll, describe, expect, it } from 'vitest';

import { bootstrap, enrolment } from './enrolment.fixtures';
import {
  EDGE_RULES,
  edgeRulesSshFrom,
  INTERNAL_RULES,
  sshFromOneAddressViolations,
  sshRestrictedRules,
} from './firewalls';
import { Host } from './host';

/**
 * `Host` has three branches that fail silently at apply time: the firewall rule set,
 * the primary IPs of `publicNetworking`, and the firewall declared on the server.
 * The reasoning: hetzner-host/README.md, "Notes kept from the source".
 */

type Created = { type: string; name: string; inputs: Record<string, unknown> };

const created: Created[] = [];

beforeAll(() => {
  pulumi.runtime.setMocks(
    {
      newResource(args: pulumi.runtime.MockResourceArgs) {
        created.push({ type: args.type, name: args.name, inputs: args.inputs });
        return { id: `${args.name}-id`, state: { ...args.inputs, ipAddress: '203.0.113.10' } };
      },
      call() {
        return {};
      },
    },
    'estate-test',
    'test',
    false
  );
});

const BASE = {
  serverType: 'cx23',
  location: 'nbg1' as const,
  image: 'debian-13',
  ownerSshKeyNames: ['owner'],
  deployPublicKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLE deploy@test',
  networkId: '4242',
};

async function build(args: Record<string, unknown>) {
  const before = created.length;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const host = new Host({ ...BASE, ...args } as any);
  await new Promise((resolve) => setTimeout(resolve, 0));
  return { host, resources: created.slice(before) };
}

const resolve = <T>(output: pulumi.Output<T> | undefined): Promise<T | undefined> =>
  output === undefined ? Promise.resolve(undefined) : new Promise((r) => output.apply(r as never));

describe('Host', () => {
  it('declares the firewall on the server rather than attaching it afterwards', async () => {
    // An attachment applied as a following step leaves a window in which a
    // freshly created host is on the public internet with no filter. There is
    // no ServerNetwork-style attachment resource for firewalls here by design.
    const { resources } = await build({ name: 'fw1', role: 'edge' });
    const server = resources.find((r) => r.type === 'hcloud:index/server:Server');
    expect(server).toBeDefined();
    expect(server?.inputs.firewallIds).toBeDefined();
    expect((server?.inputs.firewallIds as unknown[]).length).toBe(1);
  });

  it('gives an edge host the public rule set', async () => {
    const { resources } = await build({ name: 'edgeX', role: 'edge' });
    const firewall = resources.find((r) => r.type === 'hcloud:index/firewall:Firewall');
    const ports = (firewall?.inputs.rules as { port?: string; protocol: string }[]).map(
      (r) => r.port ?? r.protocol
    );
    expect(ports.sort()).toEqual(['22', '443', '80', 'icmp']);
  });

  it.each(['app', 'db', 'mon'] as const)('gives a %s host the internal rule set', async (role) => {
    const { resources } = await build({ name: `int-${role}`, role });
    const firewall = resources.find((r) => r.type === 'hcloud:index/firewall:Firewall');
    const ports = (firewall?.inputs.rules as { port?: string; protocol: string }[]).map(
      (r) => r.port ?? r.protocol
    );
    expect(ports.sort()).toEqual(['22', 'icmp']);
    expect(ports).not.toContain('80');
    expect(ports).not.toContain('443');
  });

  it('creates two non-auto-delete primary IPs when public networking is on', async () => {
    // auto_delete would release the address on a rebuild, and with a manual
    // DNS zone and HTTP-01 issuance a changed address cannot be repaired by
    // any program.
    const { host, resources } = await build({ name: 'pub1', role: 'edge' });
    const ips = resources.filter((r) => r.type === 'hcloud:index/primaryIp:PrimaryIp');
    expect(ips.map((i) => i.inputs.type).sort()).toEqual(['ipv4', 'ipv6']);
    expect(ips.every((i) => i.inputs.autoDelete === false)).toBe(true);
    expect(ips.every((i) => i.inputs.deleteProtection === true)).toBe(true);
    expect(await resolve(host.publicIpv4)).toBe('203.0.113.10');
  });

  it('creates no primary IPs at all when public networking is off', async () => {
    // Not "a filtered public address" — none. This is the control that keeps a
    // database host off the public internet.
    const { host, resources } = await build({
      name: 'priv1',
      role: 'db',
      publicNetworking: false,
      privateIp: '10.20.1.20',
    });
    expect(resources.filter((r) => r.type === 'hcloud:index/primaryIp:PrimaryIp')).toHaveLength(0);
    const server = resources.find((r) => r.type === 'hcloud:index/server:Server');
    expect(server?.inputs.publicNets).toEqual([{ ipv4Enabled: false, ipv6Enabled: false }]);
    expect(host.publicIpv4).toBeUndefined();
  });

  it('gives a private-only host its network inline, so it has an interface at first boot', async () => {
    // With no public interface and no inline network, Hetzner refuses to
    // start the server ("no public or private network interfaces found") —
    // the separate attachment resource lands after creation, which is too
    // late. The empty aliasIps is load-bearing: left undefined, the provider
    // detaches and reattaches the network on every apply.
    const { host, resources } = await build({
      name: 'priv2',
      role: 'db',
      publicNetworking: false,
      privateIp: '10.20.1.20',
    });
    const server = resources.find((r) => r.type === 'hcloud:index/server:Server');
    expect(server?.inputs.networks).toEqual([{ networkId: 4242, ip: '10.20.1.20', aliasIps: [] }]);
    expect(
      resources.filter((r) => r.type === 'hcloud:index/serverNetwork:ServerNetwork')
    ).toHaveLength(0);
    expect(host.networkAttachment).toBeUndefined();
  });

  it('threads privateOnly into cloud-init so a private-only host boots with a route', async () => {
    // A private-only host's DHCP lease never carries a default route
    // (hetzner/egress.ts), so first-boot package installation has nowhere to
    // reach unless cloud-init's userData carries the bootstrap
    // renderCloudInit adds for `privateOnly: true`. This is the only thing
    // wiring `publicNetworking` on `Host` to that flag; a regression here is
    // silent until a private-only host's first apt run fails.
    const { resources } = await build({
      name: 'priv3',
      role: 'db',
      publicNetworking: false,
      privateIp: '10.20.1.21',
    });
    const server = resources.find((r) => r.type === 'hcloud:index/server:Server');
    expect(server?.inputs.userData as string).toContain('ip route replace default via');
  });

  it('does not add the private-only bootstrap to a public host', async () => {
    const { resources } = await build({ name: 'pub2', role: 'app', privateIp: '10.20.1.101' });
    const server = resources.find((r) => r.type === 'hcloud:index/server:Server');
    expect(server?.inputs.userData as string).not.toContain('ip route replace');
  });

  it('attaches a public host to the private network at the address it was given', async () => {
    // The separate-attachment shape stays for public hosts: moving a live
    // host between the two shapes plans a detach/attach, so the shape is
    // fixed at creation and edge1/app1 keep the one they were created with.
    const { resources } = await build({ name: 'net1', role: 'app', privateIp: '10.20.1.100' });
    const attachment = resources.find((r) => r.type === 'hcloud:index/serverNetwork:ServerNetwork');
    expect(attachment?.inputs.ip).toBe('10.20.1.100');
    const server = resources.find((r) => r.type === 'hcloud:index/server:Server');
    expect(server?.inputs.networks).toBeUndefined();
  });

  it('protects a production host from delete and rebuild by default', async () => {
    const { resources } = await build({ name: 'prot1', role: 'edge' });
    const server = resources.find((r) => r.type === 'hcloud:index/server:Server');
    expect(server?.inputs.deleteProtection).toBe(true);
    expect(server?.inputs.rebuildProtection).toBe(true);
    expect(server?.inputs.backups).toBe(false);
    expect(server?.inputs.labels).toMatchObject({ env: 'production', 'managed-by': 'pulumi' });
  });

  it('drops protection and labels a lab host as lab', async () => {
    // With protection on, `pulumi destroy` cannot tear a spike down without
    // editing the component; and a lab host labelled production corrupts cost
    // attribution and any label-selector rule that reads it.
    const { resources } = await build({
      name: 'lab1',
      role: 'app',
      environment: 'lab',
      protection: false,
    });
    const server = resources.find((r) => r.type === 'hcloud:index/server:Server');
    expect(server?.inputs.deleteProtection).toBe(false);
    expect(server?.inputs.rebuildProtection).toBe(false);
    expect(server?.inputs.labels).toMatchObject({ env: 'lab', role: 'app' });
  });

  describe('enrolment in the pull', () => {
    const hcloudTypes = (before: number) =>
      created.slice(before).filter((r) => r.type.startsWith('hcloud:'));

    it('puts the enrolment document on an edge host, and no deploy account', async () => {
      const { resources } = await build({
        name: 'enrol1',
        role: 'edge',
        deployPublicKey: undefined,
        enrolment: enrolment(),
      });
      const server = resources.find((r) => r.type === 'hcloud:index/server:Server');
      const userData = server?.inputs.userData as string;
      expect(userData).toContain('--mode apply');
      expect(userData).not.toContain('name: deploy');
    });

    it('leaves the document of a host with no enrolment alone', async () => {
      const { resources } = await build({ name: 'enrol2', role: 'edge' });
      const server = resources.find((r) => r.type === 'hcloud:index/server:Server');
      expect(server?.inputs.userData as string).not.toContain('pull-trigger');
    });

    it.each(['app', 'db', 'mon'] as const)(
      'refuses to enrol a %s host, before creating anything',
      (role) => {
        const before = created.length;
        expect(
          () =>
            new Host({
              ...BASE,
              name: `enrol-${role}`,
              role,
              privateIp: '10.20.1.150',
              deployPublicKey: undefined,
              enrolment: enrolment(),
            })
        ).toThrow(/Only an edge host can be enrolled/);
        expect(hcloudTypes(before)).toEqual([]);
      }
    );

    it('refuses an enrolment and a deploy key together, before creating anything', () => {
      const before = created.length;
      expect(
        () =>
          new Host({
            ...BASE,
            name: 'enrol3',
            role: 'edge',
            privateIp: '10.20.1.151',
            enrolment: enrolment(),
          })
      ).toThrow(/no deploy account/);
      expect(hcloudTypes(before)).toEqual([]);
    });

    it('refuses neither a deploy key nor an enrolment, before creating anything', () => {
      const before = created.length;
      expect(
        () =>
          new Host({
            ...BASE,
            name: 'enrol4',
            role: 'edge',
            privateIp: '10.20.1.152',
            deployPublicKey: undefined,
          })
      ).toThrow(/required unless the host has an enrolment/);
      expect(hcloudTypes(before)).toEqual([]);
    });

    it('refuses a bad bootstrap record, before creating anything', () => {
      const before = created.length;
      expect(
        () =>
          new Host({
            ...BASE,
            name: 'enrol5',
            role: 'edge',
            privateIp: '10.20.1.153',
            deployPublicKey: undefined,
            enrolment: enrolment({ bootstrap: bootstrap({ schema: 2 }) }),
          })
      ).toThrow(/schema 1/);
      expect(hcloudTypes(before)).toEqual([]);
    });
  });

  it('refuses a deploy key that could inject cloud-config, before creating anything', async () => {
    // The validation lives in cloudInit.ts and is unit-tested there. This
    // asserts the component routes through it rather than interpolating the
    // raw value, and that it does so synchronously — a throw from inside an
    // `apply` would surface as an unhandled rejection during serialization,
    // after the firewall and the primary IPs had already been registered.
    const before = created.length;
    expect(
      () =>
        new Host({
          ...BASE,
          name: 'bad1',
          role: 'app',
          privateIp: '10.20.1.199',
          deployPublicKey: 'ssh-ed25519 AAAA\nruncmd:\n  - [ sh, -c, "id" ]',
        })
    ).toThrow(/single-line OpenSSH public key/);
    expect(created.slice(before).some((r) => r.type === 'hcloud:index/server:Server')).toBe(false);
  });
});

describe('sshSourceIp', () => {
  const EDGE1_PUBLIC = '203.0.113.10';
  const rulesOf = (resources: Created[]) =>
    resources.find((r) => r.type === 'hcloud:index/firewall:Firewall')?.inputs.rules;

  it('leaves a role-edge host with no sshSourceIp with exactly EDGE_RULES', async () => {
    // edge1 and ops1 pass no sshSourceIp: their firewalls must not move.
    const { resources } = await build({ name: 'ssh-none-edge', role: 'edge' });
    expect(rulesOf(resources)).toEqual(EDGE_RULES);
  });

  it('leaves a non-edge host with no sshSourceIp with exactly INTERNAL_RULES', async () => {
    const { resources } = await build({ name: 'ssh-none-app', role: 'app' });
    expect(rulesOf(resources)).toEqual(INTERNAL_RULES);
  });

  it('narrows an edge host to SSH from one /32, with 80, 443 and ICMP still open', async () => {
    const { resources } = await build({
      name: 'ssh-one-edge',
      role: 'edge',
      sshSourceIp: EDGE1_PUBLIC,
    });
    const rules = rulesOf(resources) as Parameters<typeof sshFromOneAddressViolations>[0];
    expect(rules).toEqual(edgeRulesSshFrom(EDGE1_PUBLIC));
    expect(sshFromOneAddressViolations(rules, EDGE1_PUBLIC)).toEqual([]);
  });

  it('accepts the address as an output, as another stack supplies it', async () => {
    const { resources } = await build({
      name: 'ssh-output-edge',
      role: 'edge',
      sshSourceIp: pulumi.output(EDGE1_PUBLIC),
    });
    expect(rulesOf(resources)).toEqual(edgeRulesSshFrom(EDGE1_PUBLIC));
  });

  it('narrows the SSH rule of a public non-edge host too, and nothing else', async () => {
    const { resources } = await build({
      name: 'ssh-one-app',
      role: 'app',
      sshSourceIp: EDGE1_PUBLIC,
    });
    expect(rulesOf(resources)).toEqual(sshRestrictedRules(INTERNAL_RULES, EDGE1_PUBLIC));
  });

  it.each(['0.0.0.0', '203.0.113.0/24', '10.20.1.10', 'edge1.example.com', ''])(
    'refuses %j before creating anything',
    (value) => {
      const before = created.length;
      expect(
        () => new Host({ ...BASE, name: 'ssh-bad', role: 'edge', sshSourceIp: value } as never)
      ).toThrow();
      expect(created.slice(before)).toEqual([]);
    }
  );

  it('refuses on a host with no public networking, before creating anything', () => {
    const before = created.length;
    expect(
      () =>
        new Host({
          ...BASE,
          name: 'ssh-private',
          role: 'db',
          privateIp: '10.20.1.160',
          publicNetworking: false,
          sshSourceIp: EDGE1_PUBLIC,
        } as never)
    ).toThrow(/no public networking/);
    expect(created.slice(before)).toEqual([]);
  });
});

describe('adopting a server made by hand', () => {
  // What the engine is asked to do, not what the provider mock returns: the
  // `ignoreChanges` list and the import id are request fields the mocks never
  // see, so they are read where the SDK hands the request to the monitor.
  type Registration = {
    type: string;
    name: string;
    importId: string;
    ignoreChanges: string[];
    inputs: Record<string, unknown>;
  };
  type RegisterRequest = {
    getType(): string;
    getName(): string;
    getImportid(): string;
    getIgnorechangesList(): string[];
    getObject(): { toJavaScript(): unknown };
  };
  const registrations: Registration[] = [];

  beforeAll(() => {
    const monitor = pulumi.runtime.getMonitor() as unknown as {
      registerResource(req: RegisterRequest, callback: (err: unknown, resp: unknown) => void): void;
    };
    const register = monitor.registerResource.bind(monitor);
    monitor.registerResource = (req, callback) => {
      registrations.push({
        type: req.getType(),
        name: req.getName(),
        importId: req.getImportid(),
        ignoreChanges: req.getIgnorechangesList(),
        inputs: req.getObject().toJavaScript() as Record<string, unknown>,
      });
      register(req, callback);
    };
  });

  const SERVER = 'hcloud:index/server:Server';
  const PRIMARY_IP = 'hcloud:index/primaryIp:PrimaryIp';
  const FIREWALL_ATTACHMENT = 'hcloud:index/firewallAttachment:FirewallAttachment';

  async function adopt(args: Record<string, unknown>) {
    const before = registrations.length;
    await build(args);
    await new Promise((resolve) => setTimeout(resolve, 0));
    const made = registrations.slice(before);
    const find = (type: string, name?: string) =>
      made.find((r) => r.type === type && (name === undefined || r.name === name));
    return { made, find };
  }

  const PUBLIC = {
    role: 'edge',
    privateIp: '10.20.1.210',
    adopt: { serverId: '1001', ipv4Id: '2001', ipv6Id: '2002' },
  };
  const PRIVATE = { role: 'db', privateIp: '10.20.1.200', publicNetworking: false };

  it('leaves a host with no adopt input exactly as it was: no import, the same three ignored fields', async () => {
    const { made, find } = await adopt({ name: 'plain1', role: 'edge' });
    expect(made.every((r) => r.importId === '')).toBe(true);
    expect(find(SERVER)?.ignoreChanges).toEqual(['userData', 'image', 'sshKeys']);
    expect(find(FIREWALL_ATTACHMENT)).toBeUndefined();
    expect(find(SERVER)?.inputs.firewallIds).toBeDefined();
  });

  // A server this program creates has its public interface set at creation, so a
  // change to the declared publicNets is a real change to apply, never to hide.
  it.each([
    ['public', { name: 'plain-pub', role: 'edge' }],
    ['private-only', { name: 'plain-priv', ...PRIVATE }],
  ] as const)(
    'declares and does not ignore publicNets on a created %s host',
    async (_label, args) => {
      const { find } = await adopt(args);
      expect(find(SERVER)?.ignoreChanges).not.toContain('publicNets');
      expect(find(SERVER)?.inputs.publicNets).toBeDefined();
    }
  );

  it('imports the server and both primary IPs by id, and creates no second pair', async () => {
    const { made, find } = await adopt({ name: 'adopt-ids', ...PUBLIC });
    expect(find(SERVER)?.importId).toBe('1001');
    expect(find(PRIMARY_IP, 'adopt-ids-ipv4')?.importId).toBe('2001');
    expect(find(PRIMARY_IP, 'adopt-ids-ipv6')?.importId).toBe('2002');
    expect(made.filter((r) => r.type === PRIMARY_IP)).toHaveLength(2);
  });

  // The replacement control. userData, sshKeys and image are create-time-only at
  // the provider: a console-made server differs from the component on all three,
  // and a diff on any of them proposes destroying a live host. Red when any is
  // dropped from the list; firewallIds is the fourth, because the owner's own
  // firewall is on the server and the component must never plan to rewrite the set.
  it.each(['import', 'converge'] as const)(
    'never lets a create-time-only field plan a replacement, at the %s stage',
    async (stage) => {
      const { find } = await adopt({
        name: `adopt-ignore-${stage}`,
        ...PUBLIC,
        adopt: { ...PUBLIC.adopt, stage },
      });
      const ignored = find(SERVER)?.ignoreChanges ?? [];
      for (const field of ['userData', 'sshKeys', 'image', 'firewallIds']) {
        expect(ignored, field).toContain(field);
      }
    }
  );

  // The power-off-and-delete control. The provider reads a server without ever
  // setting its public_net, so an adopted server has none in state and the first
  // apply sees the declared publicNets as changed. It then powers the server off,
  // unassigns the primary IP on it and, because the old set held no id, deletes
  // that primary IP before trying to assign the id it just deleted. Red when
  // publicNets is dropped from the list for an adopted server at either stage.
  it.each(['import', 'converge'] as const)(
    'never lets publicNets power off the server and delete its primary IP, at the %s stage',
    async (stage) => {
      const { find } = await adopt({
        name: `adopt-pubnets-${stage}`,
        ...PUBLIC,
        adopt: { ...PUBLIC.adopt, stage },
      });
      expect(find(SERVER)?.ignoreChanges).toContain('publicNets');
    }
  );

  it('still declares the primary IPs as separate resources and the address ids on publicNets', async () => {
    const { made, find } = await adopt({ name: 'adopt-pubnets-decl', ...PUBLIC });
    expect(made.filter((r) => r.type === PRIMARY_IP)).toHaveLength(2);
    const nets = find(SERVER)?.inputs.publicNets as { ipv4Enabled: boolean }[] | undefined;
    expect(nets?.[0]?.ipv4Enabled).toBe(true);
  });

  it('declares no firewallIds on an adopted server, so its live set is never rewritten', async () => {
    const { find } = await adopt({ name: 'adopt-fwids', ...PUBLIC });
    expect(find(SERVER)?.inputs.firewallIds).toBeUndefined();
  });

  it('attaches its own firewall by attachment, which adds to the live set and removes nothing', async () => {
    const { find } = await adopt({ name: 'adopt-fw', ...PUBLIC });
    const attachment = find(FIREWALL_ATTACHMENT, 'adopt-fw-firewall-attachment');
    expect(attachment).toBeDefined();
    expect(attachment?.inputs.serverIds).toHaveLength(1);
    expect(attachment?.inputs.firewallId).toBeDefined();
  });

  it('while importing, leaves alone only what the owner and the next stage settle', async () => {
    const { find } = await adopt({ name: 'adopt-stage1', ...PUBLIC });
    expect(find(SERVER)?.ignoreChanges).toEqual(
      expect.arrayContaining(['deleteProtection', 'rebuildProtection', 'labels'])
    );
    for (const name of ['adopt-stage1-ipv4', 'adopt-stage1-ipv6']) {
      expect(find(PRIMARY_IP, name)?.ignoreChanges).toEqual(
        expect.arrayContaining(['name', 'autoDelete', 'deleteProtection', 'labels'])
      );
    }
    // The addresses are imported by id as PrimaryIp resources, which is where they are
    // checked; the server's own publicNets is ignored (see the control above).
    expect(find(SERVER)?.ignoreChanges).toContain('publicNets');
    expect(find(SERVER)?.ignoreChanges).not.toContain('networks');
  });

  it('at converge, declares protection, labels and address settings, so they are updated in place', async () => {
    const { find } = await adopt({
      name: 'adopt-stage2',
      ...PUBLIC,
      adopt: { ...PUBLIC.adopt, stage: 'converge' },
    });
    const ignored = [
      ...(find(SERVER)?.ignoreChanges ?? []),
      ...(find(PRIMARY_IP, 'adopt-stage2-ipv4')?.ignoreChanges ?? []),
      ...(find(PRIMARY_IP, 'adopt-stage2-ipv6')?.ignoreChanges ?? []),
    ];
    for (const field of ['deleteProtection', 'rebuildProtection', 'labels', 'autoDelete', 'name']) {
      expect(ignored, field).not.toContain(field);
    }
    expect(find(PRIMARY_IP, 'adopt-stage2-ipv4')?.inputs.autoDelete).toBe(false);
    expect(find(PRIMARY_IP, 'adopt-stage2-ipv4')?.inputs.deleteProtection).toBe(true);
  });

  describe('a private-only host', () => {
    it('imports the server alone and declares no primary IP', async () => {
      const { made, find } = await adopt({
        name: 'adopt-priv1',
        ...PRIVATE,
        adopt: { serverId: '1002' },
      });
      expect(find(SERVER)?.importId).toBe('1002');
      expect(made.filter((r) => r.type === PRIMARY_IP)).toHaveLength(0);
    });

    it('leaves its network and public interface to the console steps while importing', async () => {
      const { find } = await adopt({
        name: 'adopt-priv2',
        ...PRIVATE,
        adopt: { serverId: '1002' },
      });
      expect(find(SERVER)?.ignoreChanges).toEqual(
        expect.arrayContaining(['networks', 'publicNets'])
      );
    });

    it('checks its network again at converge, but never rewrites its public interface', async () => {
      const { find } = await adopt({
        name: 'adopt-priv3',
        ...PRIVATE,
        adopt: { serverId: '1002', stage: 'converge' },
      });
      expect(find(SERVER)?.ignoreChanges).not.toContain('networks');
      expect(find(SERVER)?.ignoreChanges).toContain('publicNets');
      expect(find(SERVER)?.inputs.publicNets).toEqual([{ ipv4Enabled: false, ipv6Enabled: false }]);
    });

    // Its firewall allows SSH from anywhere, so attached while a leftover public
    // IPv6 address is still on the server it would open that address. Red when the
    // attachment is declared at the import stage.
    it('attaches its firewall only at converge, after the leftover public address is gone', async () => {
      const early = await adopt({ name: 'adopt-priv4', ...PRIVATE, adopt: { serverId: '1002' } });
      expect(early.find(FIREWALL_ATTACHMENT)).toBeUndefined();
      const late = await adopt({
        name: 'adopt-priv5',
        ...PRIVATE,
        adopt: { serverId: '1002', stage: 'converge' },
      });
      expect(late.find(FIREWALL_ATTACHMENT)).toBeDefined();
    });
  });

  describe('refuses a bad input before creating anything', () => {
    it.each([
      ['a non-numeric server id', { ...PUBLIC, adopt: { ...PUBLIC.adopt, serverId: 'edge-t' } }],
      ['a zero-led server id', { ...PUBLIC, adopt: { ...PUBLIC.adopt, serverId: '0123' } }],
      ['a public host with no IPv4 id', { ...PUBLIC, adopt: { serverId: '1001', ipv6Id: '2002' } }],
      ['a public host with no IPv6 id', { ...PUBLIC, adopt: { serverId: '1001', ipv4Id: '2001' } }],
      ['an unknown stage', { ...PUBLIC, adopt: { ...PUBLIC.adopt, stage: 'later' } }],
      [
        'a private-only host given a primary IP id',
        { ...PRIVATE, adopt: { serverId: '1002', ipv6Id: '2002' } },
      ],
    ])('%s', (_label, args) => {
      const before = created.length;
      expect(() => new Host({ ...BASE, name: 'adopt-bad', ...args } as never)).toThrow(
        /adopt|adopting/
      );
      expect(created.slice(before)).toEqual([]);
    });
  });
});
