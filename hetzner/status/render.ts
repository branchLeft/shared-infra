import type { EdgeSite } from '../../siteTypes';
import { blackboxTargets } from '../monitoring/render';
import { STATUS_TEST_COMPONENT, type StatusComponent } from '../monitoring/statusIncidents';

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

/** The same pass rule as the blackbox `http_2xx` module: any final status below 300. */
export const PASS_CONDITION = '[STATUS] < 300';

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
  condition: string;
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
    `      - '${probe.condition}'`,
  ];
}

function renderConfig(storage: string[], probes: Probe[]): string {
  const lines = [
    ...GENERATED_BANNER,
    'web:',
    `  port: ${GATUS_CONTAINER_PORT}`,
    ...storage,
    'endpoints:',
    ...probes.flatMap(renderProbe),
  ];
  return `${lines.join('\n')}\n`;
}

/** The page: one probe per registry hostname, plus TEST, with its history in the sqlite volume. */
export function renderStatusConfig(sites: readonly EdgeSite[]): string {
  const hostnameProbes: Probe[] = blackboxTargets(sites).map((target) => ({
    name: target.replace('https://', ''),
    group: SITES_GROUP,
    url: target,
    condition: PASS_CONDITION,
  }));
  const testProbe: Probe = {
    name: STATUS_TEST_TARGET_COMPONENT.name,
    group: TEST_GROUP,
    url: STATUS_TEST_TARGET_COMPONENT.probeUrl,
    condition: PASS_CONDITION,
  };
  return renderConfig(
    ['storage:', '  type: sqlite', '  path: /data/data.db'],
    [...hostnameProbes, testProbe]
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
        condition: '[STATUS] == 200',
      },
    ]
  );
}
