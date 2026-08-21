import { describe, expect, it } from 'vitest';

import { assertEstateProject, checkServersResult, mailProjectServersIn } from './projectGuard';

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
