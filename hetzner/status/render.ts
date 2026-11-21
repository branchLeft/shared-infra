import type { EdgeSite } from '../../siteTypes';
import { blackboxTargets } from '../monitoring/render';
import { STATUS_TEST_COMPONENT, type StatusComponent } from '../monitoring/statusIncidents';
import { type Postmortem, renderAnnouncements } from './postmortems';

/**
 * Renders the Gatus config of the status page on ops1 from the hostname
 * registry in `sites.ts` and the probe-to-incident rule in
 * `../monitoring/statusIncidents.ts`. Pure string building, kept in step with
 * the committed output by `render.test.ts`. See render.md for the rest.
 */

const GENERATED_BANNER = [
  '# Generated from sites.ts and hetzner/status/render.ts.',
  '# Regenerate with `npm run render` in hetzner/. Hand edits are overwritten.',
];

/** The port Gatus listens on inside its container; the host publishes it on loopback only. */
export const GATUS_CONTAINER_PORT = 8080;

/** The compose service that stands in for the TEST component, and the name the page reaches it by. */
export const TEST_TARGET_SERVICE = 'status-test-target';

/** One probe per minute: the INTERVAL `statusIncidents.test.ts` assumes. */
export const PROBE_INTERVAL = '60s';
export const PROBE_TIMEOUT = '10s';

/**
 * A probe that cannot connect (DNS failure, refused connection, timeout) has the
 * status 0 in Gatus, which `[STATUS] < 300` alone would read as a pass. So the
 * connection is a condition of its own: for HTTP, `[CONNECTED]` is true only
 * when a status code above 0 came back.
 */
export const CONNECTED_CONDITION = '[CONNECTED] == true';

/** The blackbox `http_2xx` module's status rule: any final status below 300. */
export const STATUS_CONDITION = '[STATUS] < 300';

/** The pass rule of every page probe: connected, and then a status below 300. */
export const PASS_CONDITIONS: readonly string[] = [CONNECTED_CONDITION, STATUS_CONDITION];

const SITES_GROUP = 'sites';
const TEST_GROUP = 'TEST';

/** The TEST component of the rule, pointed at the compose service that can be stopped on demand. */
export const STATUS_TEST_TARGET_COMPONENT: StatusComponent = {
  ...STATUS_TEST_COMPONENT,
  probeUrl: `http://${TEST_TARGET_SERVICE}:${GATUS_CONTAINER_PORT}/health`,
};

interface Probe {
  name: string;
  group: string;
  url: string;
  conditions: readonly string[];
}

function renderProbe(probe: Probe): string[] {
  return [
    `  - name: ${probe.name}`,
    `    group: ${probe.group}`,
    `    url: ${probe.url}`,
    `    interval: ${PROBE_INTERVAL}`,
    '    client:',
    `      timeout: ${PROBE_TIMEOUT}`,
    '    conditions:',
    ...probe.conditions.map((condition) => `      - '${condition}'`),
  ];
}

function renderConfig(storage: string[], probes: Probe[], announcements: string[] = []): string {
  const lines = [
    ...GENERATED_BANNER,
    'web:',
    `  port: ${GATUS_CONTAINER_PORT}`,
    ...storage,
    ...announcements,
    'endpoints:',
    ...probes.flatMap(renderProbe),
  ];
  return `${lines.join('\n')}\n`;
}

/**
 * The page: one probe per registry hostname, plus TEST, with its history in the sqlite
 * volume, and a link for each merged, resolved post-mortem.
 */
export function renderStatusConfig(
  sites: readonly EdgeSite[],
  postmortems: readonly Postmortem[] = []
): string {
  const hostnameProbes: Probe[] = blackboxTargets(sites).map((target) => ({
    name: target.replace('https://', ''),
    group: SITES_GROUP,
    url: target,
    conditions: PASS_CONDITIONS,
  }));
  const testProbe: Probe = {
    name: STATUS_TEST_TARGET_COMPONENT.name,
    group: TEST_GROUP,
    url: STATUS_TEST_TARGET_COMPONENT.probeUrl,
    conditions: PASS_CONDITIONS,
  };
  return renderConfig(
    ['storage:', '  type: sqlite', '  path: /data/data.db'],
    [...hostnameProbes, testProbe],
    renderAnnouncements(postmortems)
  );
}

/** The TEST target: a second Gatus that answers /health, with one probe because Gatus needs one. */
export function renderTargetConfig(): string {
  return renderConfig(
    [],
    [
      {
        name: 'SELF',
        group: 'test-target',
        url: `http://127.0.0.1:${GATUS_CONTAINER_PORT}/health`,
        conditions: [CONNECTED_CONDITION, '[STATUS] == 200'],
      },
    ]
  );
}
