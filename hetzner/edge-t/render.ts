import type { EdgePosture } from '../edge/posture';
import {
  ACCESS_LOG,
  EVERY_HOST,
  GENERATED_BANNER,
  PROBE_HOSTNAME,
  PROBE_MARKER_BARE,
  PROBE_MARKER_HOST,
  PROBE_PORT,
  globalOptions,
  logDirective,
  metricsBlock,
  probeBlock,
  protectionChain,
  renderAppsecAcquisition,
  renderBlock,
  renderCaddyLogAcquisition,
  renderGhostAdminAppsecConfig,
  renderGhostAdminPostoverflow,
  renderGhostBruteForceScenario,
  renderProfiles,
  renderSimulation,
  type Block,
} from '../edge/render';
import {
  MEDIA_SHARDS,
  mediaGlobalOptions,
  renderMediaCaddyfileSections,
  type MediaShard,
} from './media';

// Why: the tenant edge's profile of the estate renderer. Pure strings, committed to
// stack/. It takes no hostname and no registry: every name it serves is a tenant's and
// is data this repository does not hold. See render.md §"The tenant profile".

/**
 * The tenant edge's posture, spelled out and not borrowed from the estate's
 * `POSTURE`: an incident that puts the estate edge back to detect-only must not
 * move this one, and the reverse. The values are the estate's today.
 */
export const TENANT_POSTURE: EdgePosture = {
  crowdsec: 'enforcing',
  rateLimit: 'enforcing',
  membersMagicLinkRateLimit: 'enforcing',
};

/** What an unknown Host on port 80 is answered with, and the one status this edge gives it. */
export const UNKNOWN_HOST_STATUS = 503;
const UNKNOWN_HOST_BODY = 'No site is served at this name.';

/** The one catch-all's throttle zone, named so no tenant site can share its counter. */
const UNKNOWN_HOST_ZONE = 'unknown_host_per_ip';

const ESTATE_BANNER = GENERATED_BANNER.join('\n');
const TENANT_BANNER = [
  '# Generated from hetzner/edge-t/render.ts and hetzner/edge-t/render.md.',
  '# Regenerate with `npm run render` in hetzner/. Hand edits are overwritten.',
].join('\n');

/**
 * Puts this profile's banner on a file the estate renderer made. It refuses a
 * file that does not begin with the estate's banner, so a change to that banner
 * fails here and is never carried onto this edge by accident.
 */
function tenantBanner(text: string): string {
  if (!text.startsWith(`${ESTATE_BANNER}\n`)) {
    throw new Error('the estate renderer no longer begins its files with its banner');
  }
  return `${TENANT_BANNER}\n${text.slice(ESTATE_BANNER.length + 1)}`;
}

/**
 * The tenant edge's Caddyfile: the estate's global options and its two probe
 * listeners, one metrics listener, and the one catch-all. The catch-all answers
 * every request whose Host no tenant block claims with `UNKNOWN_HOST_STATUS`,
 * behind the throttle and the CrowdSec bouncer so a scanner walking names is
 * counted and banned, and not behind AppSec, which has nothing to inspect on a
 * request that is refused. Tenant site blocks are data the edge reconciles
 * (ISSUE branchLeft/workspace#1802) and are not rendered here.
 */
export function renderTenantCaddyfile(
  posture: EdgePosture = TENANT_POSTURE,
  shards: readonly MediaShard[] = MEDIA_SHARDS
): string {
  const catchAll: Block = {
    addresses: [':80'],
    body: [
      ...logDirective(ACCESS_LOG),
      'route {',
      ...protectionChain(posture, UNKNOWN_HOST_ZONE, { appsec: 'none' }).map((line) => `\t${line}`),
      `\trespond "${UNKNOWN_HOST_BODY}" ${UNKNOWN_HOST_STATUS}`,
      '}',
    ],
  };
  const blocks: Block[] = [
    catchAll,
    probeBlock(
      posture,
      `http://${PROBE_HOSTNAME}:${PROBE_PORT}`,
      'probe_host_per_ip',
      PROBE_MARKER_HOST
    ),
    probeBlock(posture, `:${PROBE_PORT}`, 'probe_per_ip', PROBE_MARKER_BARE),
    metricsBlock(),
  ];
  const options = globalOptions();
  const lines = [
    ...TENANT_BANNER.split('\n'),
    ...options.slice(0, -1),
    ...mediaGlobalOptions(),
    ...options.slice(-1),
  ];
  for (const block of blocks) {
    lines.push('', ...renderBlock(block));
  }
  lines.push('', ...renderMediaCaddyfileSections(shards, posture));
  return `${lines.join('\n')}\n`;
}

/** The AppSec acquisition file, as the estate's, which names no hostname. */
export function renderTenantAppsecAcquisition(posture: EdgePosture = TENANT_POSTURE): string {
  return tenantBanner(renderAppsecAcquisition(posture));
}

/** Caddy's access-log acquisition, as the estate's, which names no hostname. */
export function renderTenantCaddyLogAcquisition(): string {
  return tenantBanner(renderCaddyLogAcquisition());
}

/**
 * The Ghost admin preview exclusion, with no hostname list: every site this edge
 * serves is a tenant's Ghost (`render.md`, "Host scope of the Ghost files").
 */
export function renderTenantGhostAdminAppsecConfig(): string {
  return tenantBanner(renderGhostAdminAppsecConfig(EVERY_HOST));
}

/** The admin API post-overflow whitelist, with no hostname list, for the same reason. */
export function renderTenantGhostAdminPostoverflow(): string {
  return tenantBanner(renderGhostAdminPostoverflow(EVERY_HOST));
}

/** The admin brute-force scenario, with no hostname list, for the same reason. */
export function renderTenantGhostBruteForceScenario(): string {
  return tenantBanner(renderGhostBruteForceScenario(EVERY_HOST));
}

/** The ban ladder, as the estate's, which names no hostname. */
export function renderTenantProfiles(): string {
  return tenantBanner(renderProfiles());
}

/** The watch-only list, as the estate's, which names no hostname. */
export function renderTenantSimulation(): string {
  return tenantBanner(renderSimulation());
}

/**
 * Every generated file of the tenant stack, by its path under `stack/`. The
 * hand-written files (`compose.yml`, `crowdsec/config.yaml.local`) are not here.
 * `ansible/roles/edge_stack` classifies the same paths
 * (`edge_stack_tenant_crowdsec_files`), and its unit test holds the two lists equal.
 */
export function renderTenantStack(
  posture: EdgePosture = TENANT_POSTURE
): ReadonlyMap<string, string> {
  return new Map<string, string>([
    ['caddy/Caddyfile', renderTenantCaddyfile(posture)],
    ['crowdsec/acquis.d/appsec.yaml', renderTenantAppsecAcquisition(posture)],
    ['crowdsec/acquis.d/caddy.yaml', renderTenantCaddyLogAcquisition()],
    ['crowdsec/appsec-configs/ghost-admin-previews.yaml', renderTenantGhostAdminAppsecConfig()],
    [
      'crowdsec/postoverflows/ghost-admin-api-postoverflow.yaml',
      renderTenantGhostAdminPostoverflow(),
    ],
    ['crowdsec/scenarios/ghost-admin-login-bruteforce.yaml', renderTenantGhostBruteForceScenario()],
    ['crowdsec/remediation/profiles.yaml', renderTenantProfiles()],
    ['crowdsec/remediation/simulation.yaml', renderTenantSimulation()],
  ]);
}
