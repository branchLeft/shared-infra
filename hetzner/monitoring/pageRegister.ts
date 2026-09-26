/**
 * The page register: the single, committed list of what may page a phone.
 *
 * Adding an entry here is a decision, not a configuration change -- the
 * register exists to stay short, so it is reviewed by hand rather than
 * derived from anything else. `render.ts`'s `renderAlertmanagerTemplate`
 * renders the page route from this list and nothing else: a producer that
 * starts raising `severity: "page"` without an entry here must not reach a
 * phone by accident, and `findUnregisteredPageSeverityAlerts` below is what
 * makes that a build failure rather than a silent gap.
 *
 * Alerts group on the cause, not the entry -- the page route's `group_by`
 * is the `tenant` label, deliberately not `alertname`, so two different
 * entries firing for the same tenant collapse into one notification. An
 * entry with no tenant of its own (the estate-wide ones) still has a
 * `tenant` label of the empty string, which groups those alerts with each
 * other the same way.
 */

export type PageRegisterDeliveryPath = 'alertmanager' | 'healthchecks';

export interface PageRegisterEntry {
  /** Stable slug -- the identity a future change argues about, never renamed. */
  readonly id: string;
  /** One line, for a runbook or portal reader. */
  readonly name: string;
  /** The component that raises it, and why it cannot wait for the digest. */
  readonly reason: string;
  /**
   * The Prometheus alertname a producer raises, with `severity: "page"`, to
   * reach this entry's route. `null` when the entry's page never becomes an
   * Alertmanager alert at all -- see `deliveryPath`.
   */
  readonly alertName: string | null;
  /**
   * How this entry's page actually reaches a phone. Four entries route
   * through this stack's own Alertmanager; the drain worker's dead-man's
   * switch pages through its own Healthchecks.io check directly, so this
   * entry renders no Alertmanager route at all -- it is listed here only so
   * the register still names every path that can reach the phone.
   */
  readonly deliveryPath: PageRegisterDeliveryPath;
  /**
   * True while this entry has no target set and so must render no route --
   * appeal latency, until a target exists. Flipped by a reviewed change,
   * the same discipline `render.ts`'s `MonitoredHost.expectedUp` uses for
   * the same reason: a hand edit here is a claim about the present, not a
   * permanent property.
   */
  readonly dormant: boolean;
  /**
   * True when this entry's alerts carry a `tenant` label. The page route
   * groups on that label rather than on `alertname` for exactly this
   * reason -- see this file's own docstring.
   */
  readonly tenantScoped: boolean;
}

export const PAGE_REGISTER: readonly PageRegisterEntry[] = [
  {
    id: 'tier2-safety-match',
    name: 'A tier-two safety match',
    reason: 'A tier-two safety match is the class of finding the digest is too slow for -- LLD-7.',
    alertName: 'TierTwoSafetyMatch',
    deliveryPath: 'alertmanager',
    dormant: false,
    tenantScoped: true,
  },
  {
    id: 'tenant-failed-unsafe',
    name: 'A tenant in failed-unsafe',
    reason: 'A tenant stuck in failed-unsafe is blocked on a human, not on a retry -- LLD-4.',
    alertName: 'TenantFailedUnsafe',
    deliveryPath: 'alertmanager',
    dormant: false,
    tenantScoped: true,
  },
  {
    id: 'appeal-latency-breach',
    name: 'Appeal latency past its target',
    reason:
      'Dormant: no target is set yet for how long an appeal may wait. Flip `dormant` to ' +
      'false in the same change that sets one.',
    alertName: 'AppealLatencyBreach',
    deliveryPath: 'alertmanager',
    dormant: true,
    tenantScoped: true,
  },
  {
    id: 'readers-cannot-read',
    name: 'Readers cannot read',
    reason: "The reader-facing probe this entry's page route exists for is already live.",
    alertName: 'ReadersCannotRead',
    deliveryPath: 'alertmanager',
    dormant: false,
    tenantScoped: true,
  },
  {
    id: 'drain-worker-stopped',
    name: 'A stopped drain worker',
    reason:
      "Pages through its own Healthchecks.io dead-man's switch, never through this " +
      "stack's Alertmanager -- recorded here so the register still names every path " +
      'that can reach a phone.',
    alertName: null,
    deliveryPath: 'healthchecks',
    dormant: false,
    tenantScoped: false,
  },
] as const;

/** The name Alertmanager route-tree tests and CI's `amtool` step verify
 * against. ALL CAPS and `_TBD` on purpose: no supplier has been chosen for
 * this receiver, and this name must not be mistaken for a real one -- see
 * `renderPageReceiverBlock` below and `RUNBOOK-monitoring.md`. */
export const PAGE_RECEIVER_NAME = 'PAGE_RECEIVER_TBD';

/** The alertnames the page route actually matches: every entry that (a)
 * routes through Alertmanager and (b) is not dormant, in register order.
 * Exported so a cross-check can compare this exact set against what the
 * rules actually declare, rather than recomputing its own copy of the
 * filter. */
export function pageAlertNames(register: readonly PageRegisterEntry[]): string[] {
  return register
    .filter((entry) => entry.deliveryPath === 'alertmanager' && !entry.dormant)
    .map((entry) => entry.alertName)
    .filter((name): name is string => name !== null);
}

/**
 * The page route's `route.routes` entry, rendered from `register` and
 * nothing else. Empty alertname list renders no route at all -- Alertmanager
 * has no way to express "match nothing", and a regex that matched nothing
 * would still be a route entry sitting in the tree for no reason.
 */
export function renderPageRoute(register: readonly PageRegisterEntry[]): string {
  const names = pageAlertNames(register);
  if (names.length === 0) return '';
  return [
    '    - matchers:',
    '        - severity = "page"',
    `        - alertname =~ "^(${names.join('|')})$"`,
    `      receiver: ${PAGE_RECEIVER_NAME}`,
    "      group_by: ['tenant']",
  ].join('\n');
}

/**
 * The placeholder receiver block. No `*_configs` at all -- an Alertmanager
 * receiver with none is valid config and accepts every alert routed to it
 * silently, rather than refusing to start, which is what lets CI validate
 * this route before a supplier is chosen. Never add a real integration here
 * without renaming the receiver away from `_TBD`: the name is the signal
 * that nothing sent here today reaches anyone.
 */
export function renderPageReceiverBlock(): string {
  return [
    `  - name: ${PAGE_RECEIVER_NAME}`,
    '    # No supplier chosen for this receiver yet -- see RUNBOOK-monitoring.md.',
    '    # An empty receiver is valid Alertmanager config: every alert routed',
    '    # here is accepted and dropped, not refused, so this route validates',
    '    # in CI without paging anyone.',
  ].join('\n');
}

/**
 * The metric-crosscheck discipline applied to severity, not to a metric
 * name: every `alert:` block in `rulesYamlText` that carries `severity:
 * page` must name an alertname `pageAlertNames(register)` already covers,
 * or the route rendered from the register can never have been reachable by
 * it in the first place -- a producer that raises `severity: page` under an
 * alertname the register does not know is a page with nowhere to go, not a
 * page that reaches a phone by some other, unaudited route.
 *
 * A small hand-rolled reader over the rendered YAML text, matching
 * `metricCrosscheck.ts`'s own reasoning for not taking a YAML dependency:
 * the shape read here is exactly the shape `renderAlertRules` produces.
 */
export function findUnregisteredPageSeverityAlerts(
  rulesYamlText: string,
  register: readonly PageRegisterEntry[]
): string[] {
  const registered = new Set(pageAlertNames(register));
  const lines = rulesYamlText.split('\n');
  const unregistered: string[] = [];
  let currentAlert: string | null = null;
  for (const line of lines) {
    const alertMatch = /^\s*-\s*alert:\s*(\S+)/.exec(line);
    if (alertMatch) {
      currentAlert = alertMatch[1];
      continue;
    }
    const severityMatch = /^\s*severity:\s*(\S+)/.exec(line);
    if (severityMatch && currentAlert !== null) {
      const severity = severityMatch[1].replace(/^["']|["']$/g, '');
      if (severity === 'page' && !registered.has(currentAlert)) {
        unregistered.push(currentAlert);
      }
    }
  }
  return unregistered;
}
