import * as hcloud from '@pulumi/hcloud';
import * as pulumi from '@pulumi/pulumi';

import { PROJECT_NAMES, PROJECTS, type ProjectName } from './projects';

/**
 * Fails a preview whose token addresses a different project from the one the
 * program is written for.
 *
 * hcloud has no fine-grained IAM: a token has full power over everything in
 * its project, and nothing in the API tells a caller which project it is
 * holding — there is no project endpoint to ask. So the guard reads what the
 * token can *see* and compares it with `projects.ts`:
 *
 * - any other project's server or marker in view is a refusal;
 * - where the project is one of the new, initially empty ones, the project's
 *   own marker must also be in view. Without that, an empty tenants project
 *   and an empty demos project are indistinguishable, and a demos token in a
 *   tenants stack would plan a clean create of the tenant estate inside the
 *   demos project — every create succeeding.
 *
 * The existing mail and org stacks keep the narrower, servers-only form below
 * (`verifyEstateProject`). Their state already names their resources by id, so
 * a wrong token there plans replacements, which no operator confirms by
 * accident; the silent case is only ever a stack whose state is still empty.
 *
 * It has no bypass. `RUNBOOK-estate-project-move.md` sequenced the one
 * operation that needed one before this guard existed.
 */

export interface ProjectView {
  readonly servers: readonly string[];
  /** `undefined` when the caller did not read firewalls at all. */
  readonly firewalls?: readonly string[];
}

export interface Sighting {
  readonly project: ProjectName;
  readonly name: string;
}

/**
 * Everything in `view` that belongs to a project other than `expected`.
 * Exact, case-sensitive matches only: hcloud names are case-sensitive, and a
 * substring match would make `mx10` a sentinel for `mx1`.
 */
export function foreignSightings(expected: ProjectName, view: ProjectView): Sighting[] {
  const servers = new Set(view.servers);
  const firewalls = new Set(view.firewalls ?? []);
  const found: Sighting[] = [];
  for (const name of PROJECT_NAMES) {
    if (name === expected) {
      continue;
    }
    const other = PROJECTS[name];
    for (const server of other.servers) {
      if (servers.has(server)) {
        found.push({ project: name, name: server });
      }
    }
    if (firewalls.has(other.marker)) {
      found.push({ project: name, name: other.marker });
    }
  }
  return found;
}

/** The mail-project servers visible to whichever token is in use. */
export function mailProjectServersIn(serverNames: readonly string[]): string[] {
  return foreignSightings('org', { servers: serverNames })
    .filter((sighting) => sighting.project === 'mail')
    .map((sighting) => sighting.name);
}

/**
 * Throws unless `view` is consistent with the token addressing `expected`.
 *
 * The message names only the sentinels it matched, never the rest of what it
 * was shown: that is another project's inventory, and a failed preview is the
 * kind of output that gets pasted into an issue.
 */
export function assertProject(
  expected: ProjectName,
  view: ProjectView,
  options: { requireOwnMarker: boolean; fix: string }
): void {
  const foreign = foreignSightings(expected, view);
  if (foreign.length > 0) {
    const owners = [...new Set(foreign.map((sighting) => sighting.project))].join(', ');
    throw new Error(
      `the hcloud token addresses the ${owners} project, not the ${expected} project — ` +
        `it can see ${foreign.map((sighting) => sighting.name).join(', ')}. ` +
        `Applying with it would create ${expected} resources in the wrong project. ` +
        `${options.fix} and re-run; see hetzner/README.md, "Seven projects, and why the boundary matters".`
    );
  }
  if (!options.requireOwnMarker) {
    return;
  }
  const marker = PROJECTS[expected].marker;
  if (view.firewalls === undefined) {
    throw new Error(`the ${expected} project guard needs the firewall list and was not given one`);
  }
  if (!view.firewalls.includes(marker)) {
    throw new Error(
      `the hcloud token cannot see the firewall ${marker}, so nothing shows it addresses the ` +
        `${expected} project. Either the token belongs to another project or the marker was never ` +
        `created — RUNBOOK-seven-projects.md creates it. ${options.fix} and re-run.`
    );
  }
}

/** The existing estate stacks' check: servers only, no marker required. */
export function assertEstateProject(serverNames: readonly string[]): void {
  assertProject(
    'org',
    { servers: serverNames },
    {
      requireOwnMarker: false,
      fix: "Set the estate project's token with `pulumi config set --secret hcloud:token`",
    }
  );
}

/**
 * The assertion as the data source hands it over. Split out so the
 * shape-reading — which field holds the list, which field holds the name — is
 * covered by a test: getting it wrong reads as a guard that passes everything.
 */
export function checkServersResult(result: { servers: { name: string }[] }): boolean {
  assertEstateProject(result.servers.map((server) => server.name));
  return true;
}

export function checkProjectResults(
  expected: ProjectName,
  servers: { servers: { name: string }[] },
  firewalls: { firewalls: { name: string }[] },
  fix: string
): boolean {
  assertProject(
    expected,
    {
      servers: servers.servers.map((server) => server.name),
      firewalls: firewalls.firewalls.map((firewall) => firewall.name),
    },
    { requireOwnMarker: true, fix }
  );
  return true;
}

/**
 * Exported as a stack output by both existing callers rather than left as a
 * loose `apply`: an output is awaited by construction and survives a refactor
 * that stops importing the module for its side effect. A constant `true`, so
 * it never adds a diff.
 */
export function verifyEstateProject(): pulumi.Output<boolean> {
  return pulumi.output(hcloud.getServers()).apply(checkServersResult);
}
