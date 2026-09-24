import * as pulumi from '@pulumi/pulumi';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

/**
 * `dns.ts` under Pulumi's mock runtime, proving the project-marker guard is
 * wired into the *program*, not only true as a function. `dnsZone.test.ts`
 * proves `assertDnsOnlyProject`'s decision in isolation; this file proves the
 * decision actually reaches the engine -- a program that stopped calling the
 * guard, read the wrong data-source field, or dropped `getFirewalls` would
 * still pass every one of `dnsZone.test.ts`'s tests, and did: sabotaging
 * `verifyDnsOnlyProject`'s `.apply(...)` into `.apply(() => true)` left the
 * whole suite green (review cycle 1, finding 1).
 *
 * Each scenario re-imports `dns.ts` fresh, with a distinct query string, so
 * Vite treats it as a new module and re-runs its top-level code (including
 * the `dnsOnlyProjectVerified` and `zone` assignments) against that
 * scenario's own mocks rather than the previous scenario's cached exports.
 */

interface Registered {
  type: string;
  name: string;
}

/**
 * The underlying promise every `Output` carries, cast past the public
 * `Output<T>` type (which does not declare it) because a rejected input must
 * be observable as a rejection here, not silently swallowed by `.apply`,
 * which never runs its callback against a rejected antecedent.
 */
function promiseOf<T>(value: pulumi.Output<T>): Promise<T> {
  return (value as unknown as { promise(): Promise<T> }).promise();
}

/**
 * Every rrset takes `zone: zone.name` as an input, so a rejected guard
 * rejects all seventeen of them too -- proving the point, but leaving their
 * promises unobserved otherwise, which Node reports as an unhandled
 * rejection per rrset. `allSettled` observes each one without caring which
 * way it settled; the actual assertion is `zone.urn` and the empty
 * `registered` list above.
 */
async function drainRrsets(program: typeof import('./dns.js')): Promise<void> {
  await Promise.allSettled(program.rrsets.map((rrset) => promiseOf(rrset.urn)));
}

/**
 * Every rrset resource carries several other property Outputs (`id`, `name`,
 * `type`, `ttl`, `records`) beyond `urn`, each with its own internal promise
 * derived from the same rejected registration; none of them is read by name
 * anywhere in this file. `drainRrsets` above observes `urn`, but that still
 * leaves the rest as unhandled rejections that would otherwise fail the
 * whole file (an unhandled rejection is a process-level event, not scoped to
 * one `it`). This absorbs exactly the guard's own two messages and nothing
 * else -- `afterEach` fails the test if anything unrelated turns up here,
 * so a real defect cannot hide behind this handler.
 */
const GUARD_REJECTION =
  /addresses the .+ project, not the dns project|cannot see the firewall project-marker-dns/;
let unexpectedRejections: unknown[] = [];

function onUnhandledRejection(reason: unknown): void {
  const message = reason instanceof Error ? reason.message : String(reason);
  if (!GUARD_REJECTION.test(message)) {
    unexpectedRejections.push(reason);
  }
}

beforeEach(() => {
  unexpectedRejections = [];
  process.on('unhandledRejection', onUnhandledRejection);
});

afterEach(() => {
  process.off('unhandledRejection', onUnhandledRejection);
  expect(unexpectedRejections).toEqual([]);
});

let scenario = 0;

async function loadWithFirewalls(firewalls: { name: string }[]) {
  const registered: Registered[] = [];
  pulumi.runtime.setMocks(
    {
      newResource(args: pulumi.runtime.MockResourceArgs) {
        registered.push({ type: args.type, name: args.name });
        return { id: `${args.name}-id`, state: args.inputs };
      },
      call(args: pulumi.runtime.MockCallArgs) {
        if (args.token === 'hcloud:index/getServers:getServers') return { servers: [] };
        if (args.token === 'hcloud:index/getFirewalls:getFirewalls') return { firewalls };
        return {};
      },
    },
    'branchleft-hetzner-dns',
    'test',
    false
  );
  scenario += 1;
  // @vite-ignore -- deliberately dynamic: each scenario needs its own copy of
  // the module, evaluated fresh against that scenario's mocks, not the
  // memoised export from a previous scenario in this same file.
  const program = (await import(
    /* @vite-ignore */ `./dns.js?guard-scenario=${scenario}`
  )) as typeof import('./dns.js');
  return { program, registered };
}

describe('dns.ts, wired to the project-marker guard', () => {
  it("refuses to build when the token shows another project's marker, not its own", async () => {
    const { program, registered } = await loadWithFirewalls([{ name: 'project-marker-demo-dns' }]);

    await expect(promiseOf(program.dnsOnlyProjectVerified)).rejects.toThrow(
      /addresses the demo-dns project, not the dns project/
    );
    // The zone's own name is derived from the guard's output (dns.ts), so a
    // rejected guard must make the zone resource itself unregisterable --
    // not just leave a sibling output unread.
    await expect(promiseOf(program.zone.urn)).rejects.toThrow(
      /addresses the demo-dns project, not the dns project/
    );
    await drainRrsets(program);
    expect(registered.filter((r) => r.type.startsWith('hcloud:index/'))).toEqual([]);
  });

  it('refuses to build when no project marker is visible at all', async () => {
    const { program, registered } = await loadWithFirewalls([]);

    await expect(promiseOf(program.dnsOnlyProjectVerified)).rejects.toThrow(
      /cannot see the firewall project-marker-dns/
    );
    await expect(promiseOf(program.zone.urn)).rejects.toThrow(
      /cannot see the firewall project-marker-dns/
    );
    await drainRrsets(program);
    expect(registered.filter((r) => r.type.startsWith('hcloud:index/'))).toEqual([]);
  });

  it("builds normally when the token shows the dns project's own marker", async () => {
    const { program, registered } = await loadWithFirewalls([{ name: 'project-marker-dns' }]);

    await expect(promiseOf(program.dnsOnlyProjectVerified)).resolves.toBe(true);
    await expect(promiseOf(program.zone.urn)).resolves.toMatch(/branchleft-co-uk/);
    expect(registered.some((r) => r.type === 'hcloud:index/zone:Zone')).toBe(true);
  });
});
