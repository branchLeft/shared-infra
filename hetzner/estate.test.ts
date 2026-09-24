import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import * as pulumi from '@pulumi/pulumi';
import { beforeAll, describe, expect, it } from 'vitest';

/**
 * What the estate program registers, read from the requests Pulumi's SDK sends
 * the engine — including the alias URNs, which the SDK's own mocks never pass
 * to `newResource`.
 *
 * The monitor is told it does not support structured alias specs, so the SDK
 * resolves every alias to a full URN itself, children's inherited ones
 * included. The engine does the same resolution from specs in a real preview,
 * by the same rule (a child whose name starts with its parent's has that
 * prefix swapped for the parent's alias). Resolving it here is what lets a
 * test compare against the literal URNs in the production stack's state.
 *
 * The config is the committed `estate/Pulumi.production.yaml`, not a copy, so
 * a key the program requires and the file lacks fails here rather than in the
 * CI plan job after a merge.
 */

const PROJECT = 'branchleft-hetzner-estate';
const STACK = 'production';
const URN_PREFIX = `urn:pulumi:${STACK}::${PROJECT}::`;

/** The URNs the production state holds for the host, as created. */
const STATE_URNS = {
  host: `${URN_PREFIX}branchleft:hetzner:Host::nextcloud1`,
  server: `${URN_PREFIX}branchleft:hetzner:Host$hcloud:index/server:Server::nextcloud1`,
  firewall: `${URN_PREFIX}branchleft:hetzner:Host$hcloud:index/firewall:Firewall::nextcloud1-firewall`,
};

interface Registration {
  type: string;
  name: string;
  urn: string;
  aliases: string[];
  inputs: Record<string, unknown>;
}

const registrations: Registration[] = [];

/**
 * `Pulumi.production.yaml`'s `config:` block, in the one shape it uses:
 * `project:key: scalar`, or a key with no value followed by `- item` lines.
 * A shape this does not recognise throws rather than being skipped, so the
 * file cannot grow a key this test silently omits.
 */
function readStackConfig(): Record<string, string> {
  const lines = readFileSync(join(__dirname, 'estate', 'Pulumi.production.yaml'), 'utf8').split(
    '\n'
  );
  const start = lines.indexOf('config:');
  if (start === -1) {
    throw new Error('Pulumi.production.yaml has no config: block');
  }
  const config: Record<string, string> = {};
  let listKey: string | undefined;
  let list: string[] = [];
  const flush = () => {
    if (listKey !== undefined) {
      config[listKey] = JSON.stringify(list);
      listKey = undefined;
      list = [];
    }
  };
  for (const line of lines.slice(start + 1)) {
    if (line.trim() === '' || line.trim().startsWith('#')) {
      continue;
    }
    const item = /^ {4}- (.+)$/.exec(line);
    if (item && listKey !== undefined) {
      list.push(item[1]);
      continue;
    }
    const entry = /^ {2}([\w-]+:\w+):(?: (.+))?$/.exec(line);
    if (!entry) {
      throw new Error(`unrecognised line in Pulumi.production.yaml: ${line}`);
    }
    flush();
    if (entry[2] === undefined) {
      listKey = entry[1];
    } else {
      config[entry[1]] = entry[2];
    }
  }
  flush();
  return config;
}

let estate: typeof import('./estate.js');

beforeAll(async () => {
  const stackConfig = readStackConfig();
  pulumi.runtime.setAllConfig(stackConfig);

  pulumi.runtime.setMocks(
    {
      newResource(args: pulumi.runtime.MockResourceArgs) {
        if (args.type === 'pulumi:pulumi:StackReference') {
          return { id: args.name, state: { outputs: { networkId: '4242' } } };
        }
        return { id: `${args.name}-id`, state: args.inputs };
      },
      call(args: pulumi.runtime.MockCallArgs) {
        if (args.token === 'hcloud:index/getServers:getServers') {
          return { servers: [] };
        }
        return {};
      },
    },
    PROJECT,
    STACK,
    false
  );

  const state = (await import('@pulumi/pulumi/runtime/state.js')) as unknown as {
    getStore(): { supportsAliasSpecs: boolean };
  };
  state.getStore().supportsAliasSpecs = false;

  const monitor = pulumi.runtime.getMonitor() as unknown as {
    registerResource(req: RegisterRequest, callback: (err: unknown, resp: unknown) => void): void;
  };
  const register = monitor.registerResource.bind(monitor);
  monitor.registerResource = (req, callback) => {
    register(req, (err, resp) => {
      if (!err && resp) {
        registrations.push({
          type: req.getType(),
          name: req.getName(),
          urn: (resp as { getUrn(): string }).getUrn(),
          aliases: req.getAliasurnsList(),
          inputs: req.getObject().toJavaScript() as Record<string, unknown>,
        });
      }
      callback(err, resp);
    });
  };

  estate = await import('./estate.js');
  await new Promise<void>((resolve) =>
    pulumi.all([estate.ops1.server.urn, estate.edge1.server.urn]).apply(() => resolve())
  );
  // Registrations complete asynchronously after the URN resolves for the
  // component's own children; one more turn lets the last callback land.
  await new Promise((resolve) => setTimeout(resolve, 50));
});

interface RegisterRequest {
  getType(): string;
  getName(): string;
  getAliasurnsList(): string[];
  getObject(): { toJavaScript(): unknown };
}

function registered(type: string, name: string): Registration {
  const found = registrations.filter((r) => r.type === type && r.name === name);
  expect(found, `${type} ${name} registered once`).toHaveLength(1);
  return found[0];
}

describe('the ops1 rename, as the engine will be asked to plan it', () => {
  it('names the host ops1 and nothing registers under the old name', () => {
    const names = registrations.map((r) => r.name);
    expect(names).toContain('ops1');
    expect(names).toContain('ops1-firewall');
    expect(names.filter((name) => name.startsWith('nextcloud1'))).toEqual([]);
  });

  it('aliases the component to the URN it holds in state', async () => {
    // Read from the component rather than the request: under mocks there is
    // no root stack resource to parent it, so the SDK leaves a top-level
    // resource's alias as a spec for the engine. `__aliases` is the resolved
    // URN the SDK derives the children's inherited aliases from.
    const own = (estate.ops1 as unknown as { __aliases: pulumi.Output<string>[] }).__aliases;
    const urns = await new Promise<string[]>((resolve) => pulumi.all(own).apply(resolve));
    expect(urns).toContain(STATE_URNS.host);
  });

  it('carries the alias down to the server, so it updates in place rather than replacing', () => {
    expect(registered('hcloud:index/server:Server', 'ops1').aliases).toContain(STATE_URNS.server);
  });

  it('carries the alias down to the firewall', () => {
    expect(registered('hcloud:index/firewall:Firewall', 'ops1-firewall').aliases).toContain(
      STATE_URNS.firewall
    );
  });

  it('gives every resource under the host an alias to its state URN, not only the two named above', () => {
    const underHost = registrations.filter((r) => r.urn.includes('branchleft:hetzner:Host$'));
    const ops1Children = underHost.filter((r) => r.name === 'ops1' || r.name.startsWith('ops1-'));
    expect(ops1Children.length).toBeGreaterThan(0);
    for (const child of ops1Children) {
      const stateName = child.name.replace(/^ops1/, 'nextcloud1');
      const stateUrn = child.urn.replace(/::ops1(-[\w-]+)?$/, `::${stateName}`);
      expect(child.aliases, child.urn).toContain(stateUrn);
    }
  });

  it('changes only the name on the server: same address, type, network and protection', () => {
    const inputs = registered('hcloud:index/server:Server', 'ops1').inputs;
    expect(inputs.name).toBe('ops1');
    expect(inputs.serverType).toBe('cx23');
    expect(inputs.location).toBe('nbg1');
    expect(inputs.networks).toEqual([{ networkId: 4242, ip: '10.20.1.50', aliasIps: [] }]);
    expect(inputs.deleteProtection).toBe(true);
    expect(inputs.rebuildProtection).toBe(true);
    expect(inputs.publicNets).toEqual([{ ipv4Enabled: false, ipv6Enabled: false }]);
  });

  it('reads the host config under the new name only', () => {
    const keys = Object.keys(readStackConfig());
    expect(keys).toEqual(
      expect.arrayContaining([`${PROJECT}:ops1ServerType`, `${PROJECT}:ops1DeployPublicKey`])
    );
    expect(keys.filter((key) => key.includes('nextcloud1'))).toEqual([]);
  });

  it('keeps the private address the Nextcloud stack and the edge upstream are bound to', () => {
    expect(estate.ops1PrivateIp).toBe('10.20.1.50');
  });

  it('leaves edge1 unaliased: the rename touches one host', () => {
    const edge = registrations.filter((r) => r.name === 'edge1' || r.name.startsWith('edge1-'));
    expect(edge.length).toBeGreaterThan(0);
    for (const resource of edge) {
      expect(
        resource.aliases.filter((alias) => !alias.includes('::edge1')),
        resource.urn
      ).toEqual([]);
    }
  });
});
