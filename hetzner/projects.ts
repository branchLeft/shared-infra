/**
 * The estate's Hetzner projects, as data.
 *
 * A project is the only credential boundary Hetzner offers: a Cloud API token
 * reaches everything in the project that minted it and nothing outside it, and
 * no finer scope exists below "Read" or "Read & Write". So this table is the
 * security model, not a naming convenience. The project guard, the isolation
 * probe (`scripts/probe-project-isolation.py`, which carries its own copy of
 * this table and a test that keeps the two equal) and
 * `RUNBOOK-five-projects.md` all follow it.
 *
 * The API cannot say which project a token belongs to, so every project is
 * identified by what is visible inside it:
 *
 * - `marker` is a firewall with no rules and nothing attached, created by hand
 *   once per project. Firewalls cost nothing, and an unattached one changes no
 *   traffic. It is the only way to tell two *empty* projects apart, which is
 *   the state tenants, demos and dns are in before their first apply.
 * - `servers` are the hosts that live there. They are sentinels for the
 *   *other* projects: seeing one proves the token is in the wrong place.
 */

export type ProjectName = 'mail' | 'org' | 'tenants' | 'demos' | 'dns';

export interface HetznerProject {
  readonly name: ProjectName;
  /** The name to give the project in the Hetzner Console. */
  readonly consoleName: string;
  readonly marker: string;
  readonly servers: readonly string[];
}

export const MARKER_PREFIX = 'project-marker-';

function project(
  name: ProjectName,
  consoleName: string,
  servers: readonly string[]
): HetznerProject {
  return { name, consoleName, marker: `${MARKER_PREFIX}${name}`, servers };
}

export const PROJECTS: Readonly<Record<ProjectName, HetznerProject>> = {
  mail: project('mail', 'branchLeft mail', ['mx1']),
  // `nextcloud1` and `ops1` are both listed across the rename, so the guard
  // holds on either side of it.
  org: project('org', 'branchLeft estate', ['edge1', 'nextcloud1', 'ops1', 'app1', 'db1']),
  tenants: project('tenants', 'branchLeft tenants', ['edge-t', 'app-t1', 'db-t1']),
  demos: project('demos', 'branchLeft demos', ['demo1']),
  // Holds the DNS zone and no hosts. A stolen token here reaches no data outside
  // DNS, but a Read & Write one can still create billable resources in this
  // project and use up the account-wide server cap.
  dns: project('dns', 'branchLeft dns', []),
};

export const PROJECT_NAMES = Object.keys(PROJECTS) as ProjectName[];
