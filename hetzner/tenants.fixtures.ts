import * as pulumi from '@pulumi/pulumi';

/**
 * The mocks the tenants program tests share: what the program registers is read
 * from the requests the SDK sends the engine, and nothing leaves the process.
 * The config is supplied in the shape the stack file carries, so a key the
 * program requires and the stack file lacks fails the test.
 */

export interface Created {
  type: string;
  name: string;
  id: string;
  inputs: Record<string, unknown>;
}

/** What the estate stack's `edge1PublicIpv4` output reads as in these tests. */
export const EDGE1_PUBLIC_IPV4 = '198.51.100.7';

export const TENANTS_MARKER = 'project-marker-tenants';

const DEPLOY_KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLE deploy@test';

export const BASE_CONFIG: Record<string, string> = {
  'branchleft-hetzner-tenants:image': 'debian-13',
  'branchleft-hetzner-tenants:dbt1ServerType': 'cx23',
  'branchleft-hetzner-tenants:edgetServerType': 'cx23',
  'branchleft-hetzner-tenants:ownerSshKeyNames': '["rob@branchleft.co.uk"]',
  'branchleft-hetzner-tenants:dbt1DeployPublicKey': DEPLOY_KEY,
  'branchleft-hetzner-tenants:edgetDeployPublicKey': DEPLOY_KEY,
};

export interface TenantsMockOptions {
  /** Config added to or overriding BASE_CONFIG. */
  config?: Record<string, string>;
  /** What the project check reads: the servers and firewalls the token sees. */
  servers?: { name: string }[];
  firewalls?: { name: string }[];
  /** The value of the estate stack's `edge1PublicIpv4` output. */
  edge1PublicIpv4?: string;
}

/**
 * Installs the config and the mocks, and returns the registrations the program
 * makes as it runs. Network and subnet ids are numeric strings, because the
 * program converts them with `Number`.
 */
export function installTenantsMocks(options: TenantsMockOptions = {}): Created[] {
  const created: Created[] = [];
  let sequence = 4000;
  process.env.PULUMI_CONFIG = JSON.stringify({ ...BASE_CONFIG, ...options.config });
  pulumi.runtime.setMocks(
    {
      newResource(args: pulumi.runtime.MockResourceArgs) {
        sequence += 1;
        const id = String(sequence);
        created.push({ type: args.type, name: args.name, id, inputs: args.inputs });
        if (args.type === 'pulumi:pulumi:StackReference') {
          return {
            id: args.name,
            state: {
              ...args.inputs,
              outputs: { edge1PublicIpv4: options.edge1PublicIpv4 ?? EDGE1_PUBLIC_IPV4 },
              secretOutputNames: [],
            },
          };
        }
        return { id, state: { ...args.inputs, ipAddress: '203.0.113.20' } };
      },
      call(args: pulumi.runtime.MockCallArgs) {
        if (args.token === 'hcloud:index/getServers:getServers') {
          return { servers: options.servers ?? [] };
        }
        if (args.token === 'hcloud:index/getFirewalls:getFirewalls') {
          return { firewalls: options.firewalls ?? [{ name: TENANTS_MARKER }] };
        }
        return {};
      },
    },
    'branchleft-hetzner-tenants',
    'production',
    false
  );
  return created;
}

/** Lets the program's pending applies run before a test reads what was registered. */
export async function settle(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

export const ofType = (created: readonly Created[], type: string): Created[] =>
  created.filter((resource) => resource.type === type);

export const TYPES = {
  server: 'hcloud:index/server:Server',
  firewall: 'hcloud:index/firewall:Firewall',
  primaryIp: 'hcloud:index/primaryIp:PrimaryIp',
  serverNetwork: 'hcloud:index/serverNetwork:ServerNetwork',
  network: 'hcloud:index/network:Network',
  subnet: 'hcloud:index/networkSubnet:NetworkSubnet',
  route: 'hcloud:index/networkRoute:NetworkRoute',
};
