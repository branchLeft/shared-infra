import * as pulumi from '@pulumi/pulumi';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  defaultHcloudProviderDisabled,
  projectProvider,
  providerResourceName,
} from './projectProvider';

interface Visible {
  servers: string[];
  firewalls: string[];
}

let visible: Visible = { servers: [], firewalls: [] };
const calls: { token: string; provider?: string }[] = [];
const providers: { name: string; inputs: Record<string, unknown> }[] = [];

function resolve<T>(output: pulumi.Output<T>): Promise<T> {
  return new Promise((done) => output.apply((value) => done(value)));
}

/** An apply callback that throws rejects the output's internal promise. */
function resolveOrError<T>(output: pulumi.Output<T>): Promise<T | Error> {
  const internal = output as unknown as Record<string, unknown>;
  // The same rejection is also carried by the output's own bookkeeping
  // promises; leaving those unobserved reports as unhandled rejections.
  for (const key of ['isKnown', 'isSecret']) {
    const value = internal[key];
    if (value instanceof Promise) {
      value.catch(() => undefined);
    }
  }
  return (output as unknown as { promise(): Promise<T> }).promise().then(
    (value) => value,
    (error: Error) => error
  );
}

function setConfig(entries: Record<string, string>): void {
  pulumi.runtime.setAllConfig(entries, ['hcloud-projects:tenantsToken']);
}

const DISABLED = { 'pulumi:disable-default-providers': '["hcloud"]' };

beforeAll(() => {
  pulumi.runtime.setMocks(
    {
      newResource(args: pulumi.runtime.MockResourceArgs) {
        if (args.type === 'pulumi:providers:hcloud') {
          providers.push({ name: args.name, inputs: args.inputs });
        }
        return { id: `${args.name}-id`, state: args.inputs };
      },
      call(args: pulumi.runtime.MockCallArgs) {
        calls.push({ token: args.token, provider: args.provider });
        if (args.token === 'hcloud:index/getServers:getServers') {
          return { servers: visible.servers.map((name) => ({ name })) };
        }
        if (args.token === 'hcloud:index/getFirewalls:getFirewalls') {
          return { firewalls: visible.firewalls.map((name) => ({ name })) };
        }
        throw new Error(`unexpected invoke ${args.token}`);
      },
    },
    'project-provider-test',
    'test',
    false
  );
});

beforeEach(() => {
  calls.length = 0;
  providers.length = 0;
  visible = { servers: [], firewalls: [] };
});

describe('defaultHcloudProviderDisabled', () => {
  it('accepts hcloud or the wildcard', () => {
    expect(defaultHcloudProviderDisabled(['hcloud'])).toBe(true);
    expect(defaultHcloudProviderDisabled(['random', '*'])).toBe(true);
  });

  it('rejects an absent, empty or unrelated setting', () => {
    expect(defaultHcloudProviderDisabled(undefined)).toBe(false);
    expect(defaultHcloudProviderDisabled([])).toBe(false);
    expect(defaultHcloudProviderDisabled(['random'])).toBe(false);
    expect(defaultHcloudProviderDisabled('hcloud')).toBe(false);
  });
});

describe('projectProvider', () => {
  it('refuses the existing projects, whose stacks stay on the default provider', () => {
    setConfig({ ...DISABLED });
    expect(() => projectProvider('org')).toThrow(/default hcloud provider/);
    expect(() => projectProvider('mail')).toThrow(/default hcloud provider/);
  });

  it('refuses a stack that has not disabled the default hcloud provider', () => {
    setConfig({ 'hcloud-projects:tenantsToken': 'T' });
    expect(() => projectProvider('tenants')).toThrow(/disable-default-providers/);
  });

  it('refuses a stack whose own token key is unset, rather than reading any other', () => {
    setConfig({ ...DISABLED, 'hcloud-projects:demosToken': 'D' });
    expect(() => projectProvider('tenants')).toThrow(/tenantsToken/);
  });

  it('builds a provider under a fixed name, from the project token only', async () => {
    setConfig({ ...DISABLED, 'hcloud-projects:tenantsToken': 'TENANTS-TOKEN' });
    visible = { servers: [], firewalls: ['project-marker-tenants'] };
    const { provider, verified } = projectProvider('tenants');
    expect(await resolve(verified)).toBe(true);
    expect(await resolve(provider.urn)).toContain(`::${providerResourceName('tenants')}`);
    expect(providers.map((p) => p.name)).toEqual(['hcloud-tenants']);
    // The provider receives the token as a secret, so it is encrypted in state.
    expect(providers[0].inputs.token).toEqual({
      '4dabf18193072939515e22adb298388d': '1b47061264138c4ac30d75fd1eb44270',
      value: 'TENANTS-TOKEN',
    });
  });

  it('routes both guard reads through the explicit provider, never the default', async () => {
    setConfig({ ...DISABLED, 'hcloud-projects:tenantsToken': 'T' });
    visible = { servers: [], firewalls: ['project-marker-tenants'] };
    const { verified } = projectProvider('tenants');
    await resolve(verified);
    expect(calls.map((call) => call.token).sort()).toEqual([
      'hcloud:index/getFirewalls:getFirewalls',
      'hcloud:index/getServers:getServers',
    ]);
    for (const call of calls) {
      expect(call.provider).toContain('hcloud-tenants');
    }
  });

  it('fails the program when the token sees another project', async () => {
    setConfig({ ...DISABLED, 'hcloud-projects:tenantsToken': 'T' });
    visible = { servers: ['demo1'], firewalls: ['project-marker-demos'] };
    const result = await resolveOrError(projectProvider('tenants').verified);
    expect(result).toBeInstanceOf(Error);
    expect((result as Error).message).toMatch(/addresses the demos project/);
    expect((result as Error).message).toMatch(/hcloud-projects:tenantsToken/);
  });

  it('fails the program when the token sees no marker at all', async () => {
    setConfig({ ...DISABLED, 'hcloud-projects:tenantsToken': 'T' });
    visible = { servers: [], firewalls: [] };
    const result = await resolveOrError(projectProvider('tenants').verified);
    expect(result).toBeInstanceOf(Error);
    expect((result as Error).message).toMatch(/project-marker-tenants/);
  });
});
