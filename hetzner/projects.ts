/**
 * The estate's Hetzner projects, as data.
 *
 * A project is the only credential boundary Hetzner offers: a Cloud API token
 * reaches everything in the project that minted it and nothing outside it, and
 * no finer scope exists below "Read" or "Read & Write". So this table is the
 * security model, not a naming convenience. The project guard, the isolation
 * probe (`scripts/probe-project-isolation.py`, which carries its own copy of
 * this table and a test that keeps the two equal) and
 * `RUNBOOK-seven-projects.md` all follow it.
 *
 * The API cannot say which project a token belongs to, so every project is
 * identified by what is visible inside it:
 *
 * - `marker` is a firewall with no rules and nothing attached, created by hand
 *   once per project. Firewalls cost nothing, and an unattached one changes no
 *   traffic. It is the only way to tell two *empty* projects apart, which is
 *   the state tenants, demos, dns, backup and demo-dns are in before their
 *   first apply (backup and demo-dns never hold servers at all — the marker
 *   is their only identity, permanently, not only until a first apply).
 * - `servers` are the hosts that live there. They are sentinels for the
 *   *other* projects: seeing one proves the token is in the wrong place.
 */

export type ProjectName = 'mail' | 'org' | 'tenants' | 'demos' | 'dns' | 'backup' | 'demo-dns';

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
  // Holds the branchleft.co.uk DNS zone and no hosts. A stolen token here
  // reaches no data outside DNS, but a Read & Write one can still create
  // billable resources in this project and use up the account-wide server cap.
  dns: project('dns', 'branchLeft dns', []),
  // Backup-only: holds the Hetzner Object Storage backup bucket and no hosts,
  // ever. A bucket's S3 credential is a separate credential type from a Cloud
  // API token (RUNBOOK-new-stack.md "Before you start"), so this project's
  // marker is the only thing a Cloud API token ever proves about it.
  backup: project('backup', 'branchLeft backup', []),
  // The demo domain's own DNS zone, apart from branchleft.co.uk's. Holds no
  // hosts, ever, for the same reason `dns` does not: a stolen token here
  // reaches no data outside that one zone.
  'demo-dns': project('demo-dns', 'branchLeft demo dns', []),
};

export const PROJECT_NAMES = Object.keys(PROJECTS) as ProjectName[];
