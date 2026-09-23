import { describe, expect, it } from 'vitest';

import {
  assertEstateProject,
  assertProject,
  checkProjectResults,
  checkServersResult,
  foreignSightings,
  mailProjectServersIn,
} from './projectGuard';

/**
 * What is not covered here is one line — handing `hcloud.getServers()` to
 * `checkServersResult` — because it needs a live token, which is the one thing
 * CI never has. Everything either side of it is: the decision itself, and the
 * shape-reading that feeds it.
 */
describe('mailProjectServersIn', () => {
  it('finds nothing in an empty project', () => {
    expect(mailProjectServersIn([])).toEqual([]);
  });

  it('finds nothing in a project holding only estate hosts', () => {
    expect(mailProjectServersIn(['edge1', 'app1', 'db1', 'mon1'])).toEqual([]);
  });

  it('finds the mail host among estate hosts', () => {
    expect(mailProjectServersIn(['edge1', 'mx1', 'db1'])).toEqual(['mx1']);
  });

  it('matches the name exactly, not as a substring', () => {
    expect(mailProjectServersIn(['mx10', 'mx1-old', 'not-mx1'])).toEqual([]);
  });

  it('is case-sensitive, because hcloud server names are', () => {
    expect(mailProjectServersIn(['MX1'])).toEqual([]);
  });
});

describe('assertEstateProject', () => {
  it('passes an empty project, which is the estate project before its first apply', () => {
    expect(() => assertEstateProject([])).not.toThrow();
  });

  it('passes a project holding the estate', () => {
    expect(() => assertEstateProject(['edge1', 'app1', 'db1'])).not.toThrow();
  });

  it('refuses a project holding the mail host', () => {
    expect(() => assertEstateProject(['mx1'])).toThrow(/addresses the mail project/);
  });

  it('names the sentinel it matched, so the operator knows which check fired', () => {
    expect(() => assertEstateProject(['edge1', 'mx1'])).toThrow(/it can see mx1/);
  });

  /**
   * The list the guard is handed is the mail project's inventory, and a failed
   * preview is the kind of output that gets pasted into an issue. Only the
   * sentinel names — already public in this repository — may appear.
   */
  it('never repeats the other servers it was shown', () => {
    let message = '';
    try {
      assertEstateProject(['mx1', 'some-unrelated-host', 'another-one']);
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).not.toContain('some-unrelated-host');
    expect(message).not.toContain('another-one');
  });

  it('points at the command that fixes it', () => {
    expect(() => assertEstateProject(['mx1'])).toThrow(/pulumi config set --secret hcloud:token/);
  });
});

/**
 * The seam between the provider's result shape and the decision. A guard that
 * reads the wrong field does not fail loudly — it passes everything, which is
 * indistinguishable from a correct guard right up until it matters.
 */
describe('checkServersResult', () => {
  it('accepts a project with no servers at all', () => {
    expect(checkServersResult({ servers: [] })).toBe(true);
  });

  it('reads names out of the result the provider actually returns', () => {
    expect(checkServersResult({ servers: [{ name: 'edge1' }, { name: 'db1' }] })).toBe(true);
  });

  it('refuses when the mail host is among them', () => {
    expect(() => checkServersResult({ servers: [{ name: 'mx1' }] })).toThrow(
      /addresses the mail project/
    );
  });
});

describe('foreignSightings', () => {
  it('sees nothing foreign in a project holding only its own servers and marker', () => {
    expect(
      foreignSightings('tenants', {
        servers: ['edge-t', 'app-t1', 'db-t1'],
        firewalls: ['project-marker-tenants'],
      })
    ).toEqual([]);
  });

  it("names every other project's server it can see", () => {
    expect(foreignSightings('tenants', { servers: ['edge1', 'demo1', 'mx1'] })).toEqual([
      { project: 'mail', name: 'mx1' },
      { project: 'org', name: 'edge1' },
      { project: 'demos', name: 'demo1' },
    ]);
  });

  it("names another project's marker, which is what separates two empty projects", () => {
    expect(
      foreignSightings('tenants', { servers: [], firewalls: ['project-marker-demos'] })
    ).toEqual([{ project: 'demos', name: 'project-marker-demos' }]);
  });

  it('holds across the nextcloud1 rename', () => {
    expect(foreignSightings('demos', { servers: ['ops1'] })).toEqual([
      { project: 'org', name: 'ops1' },
    ]);
    expect(foreignSightings('demos', { servers: ['nextcloud1'] })).toEqual([
      { project: 'org', name: 'nextcloud1' },
    ]);
  });

  it('matches markers exactly, not as a prefix', () => {
    expect(
      foreignSightings('tenants', { servers: [], firewalls: ['project-marker-demos-old'] })
    ).toEqual([]);
  });
});

describe('assertProject with the own-marker requirement', () => {
  const options = { requireOwnMarker: true, fix: 'FIX' };

  it('passes an empty project that carries its own marker', () => {
    expect(() =>
      assertProject('dns', { servers: [], firewalls: ['project-marker-dns'] }, options)
    ).not.toThrow();
  });

  it('refuses an empty project with no marker, because it could be any empty project', () => {
    expect(() => assertProject('dns', { servers: [], firewalls: [] }, options)).toThrow(
      /cannot see the firewall project-marker-dns/
    );
  });

  it('refuses a swapped token even when the own marker is somehow also present', () => {
    expect(() =>
      assertProject(
        'tenants',
        { servers: [], firewalls: ['project-marker-tenants', 'project-marker-demos'] },
        options
      )
    ).toThrow(/addresses the demos project, not the tenants project/);
  });

  it('refuses outright when it was not given the firewall list', () => {
    expect(() => assertProject('tenants', { servers: [] }, options)).toThrow(
      /needs the firewall list/
    );
  });

  it('never repeats unrelated names it was shown', () => {
    let message = '';
    try {
      assertProject(
        'tenants',
        { servers: ['mx1', 'private-host'], firewalls: ['private-fw'] },
        options
      );
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toContain('mx1');
    expect(message).not.toContain('private-host');
    expect(message).not.toContain('private-fw');
  });
});

describe('checkProjectResults', () => {
  it('reads names out of both results the provider returns', () => {
    expect(
      checkProjectResults(
        'demos',
        { servers: [{ name: 'demo1' }] },
        { firewalls: [{ name: 'project-marker-demos' }] },
        'FIX'
      )
    ).toBe(true);
  });

  it('refuses when the marker is missing from the firewall result', () => {
    expect(() =>
      checkProjectResults('demos', { servers: [] }, { firewalls: [{ name: 'other' }] }, 'FIX')
    ).toThrow(/project-marker-demos/);
  });

  it('refuses when the firewall result carries another project marker', () => {
    expect(() =>
      checkProjectResults(
        'demos',
        { servers: [] },
        { firewalls: [{ name: 'project-marker-demos' }, { name: 'project-marker-org' }] },
        'FIX'
      )
    ).toThrow(/addresses the org project/);
  });
});
