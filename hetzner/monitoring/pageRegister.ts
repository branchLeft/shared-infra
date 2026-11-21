/**
 * The page register: the single, committed list of what may page a phone.
 * Adding an entry is a decision, not a configuration change. The reasoning,
 * and why alerts group on the cause, is in `pageRegister.md`.
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
   * How this entry's page actually reaches a phone. Six entries route
   * through this stack's own Alertmanager; the drain worker's dead-man's
   * switch pages through its own Healthchecks.io check directly, so this
   * entry renders no Alertmanager route at all -- it is listed here only so
   * the register still names every path that can reach the phone.
   */
  readonly deliveryPath: PageRegisterDeliveryPath;
  /**
   * True while this entry has no target set and so must render no route --
   * appeal latency, until a target exists; the stopped demo reaper, until the
   * reaper and its alert rule exist. Flipped by a reviewed change,
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
  /**
   * Why this live Alertmanager entry has no `severity: page` rule in the
   * rendered rules: who raises it instead. Absent means the entry claims a
   * rule exists, and `findLiveEntriesWithoutPageRule` refuses it if none
   * does. Only a live Alertmanager entry is checked; a dormant or
   * Healthchecks-delivered one needs none.
   */
  readonly ruleExemption?: string;
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
    ruleExemption:
      'No producer exists yet: nothing raises TierTwoSafetyMatch today. The platform is ' +
      'planned to raise it when a tier-two safety match is recorded, not through a ' +
      'Prometheus rule, since nothing this stack scrapes measures one; the rendered ' +
      'rules carry no rule for it.',
  },
  {
    id: 'tenant-failed-unsafe',
    name: 'A tenant in failed-unsafe',
    reason: 'A tenant stuck in failed-unsafe is blocked on a human, not on a retry -- LLD-4.',
    alertName: 'TenantFailedUnsafe',
    deliveryPath: 'alertmanager',
    dormant: false,
    tenantScoped: true,
    ruleExemption:
      'No producer exists yet: nothing raises TenantFailedUnsafe today. The platform is ' +
      'planned to raise it when a tenant enters failed-unsafe, not through a Prometheus ' +
      "rule: that state is the platform's own, and this stack scrapes no metric for it, " +
      'so the rendered rules carry no rule for it.',
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
    ruleExemption:
      'No producer exists yet: nothing raises ReadersCannotRead today. The external ' +
      'reader-facing probe is planned to raise it per tenant, not through a Prometheus ' +
      "rule: this stack's blackbox probes carry an instance label and no tenant label, so no " +
      'rule here can raise a tenant-labelled page. Until that producer exists, a failing ' +
      'probe reaches the phone through BlackboxProbeFailed at critical severity.',
  },
  {
    id: 'edge-ban',
    name: 'The edge banned an address',
    reason:
      'A CrowdSec ban refuses that address on every site behind edge1, the sign-in ' +
      'service included, and the owner has been banned by false alarms three times; the ' +
      'owner learns of each ban, and which scenario made it, as it happens.',
    alertName: 'EdgeBanIssued',
    deliveryPath: 'alertmanager',
    dormant: false,
    tenantScoped: false,
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
  {
    id: 'stopped-demo-reaper',
    name: 'A stopped demo reaper',
    reason:
      'Dormant: the demo reaper that ends a demo at the close of its lease does not ' +
      'exist yet, and neither does the threshold for how long it may stay silent. A ' +
      'silently stopped reaper leaves demos running past their lease. Flip `dormant` to ' +
      'false in the same change that builds the reaper and the alert rule that raises it.',
    alertName: 'StoppedDemoReaper',
    deliveryPath: 'alertmanager',
    dormant: true,
    tenantScoped: false,
  },
  {
    id: 'abuse-report',
    name: 'A report to the abuse mailbox',
    reason:
      'Dormant: a report of abusive or harmful material must reach the owner within ' +
      'minutes, not on the digest. The arrival producer on mx1 is an owner-authorised ' +
      'patch, so the entry stays dormant until that patch lands. Flip `dormant` to false ' +
      'in the same change that lands the producer.',
    alertName: 'AbuseReportReceived',
    deliveryPath: 'alertmanager',
    dormant: true,
    tenantScoped: false,
    ruleExemption:
      'Raised on mx1 when a message reaches the abuse role mailbox, not by a Prometheus ' +
      'rule: this stack scrapes no metric for a mailbox arrival, so the rendered rules ' +
      'carry no rule for it and cannot.',
  },
] as const;

/** The receiver Alertmanager route-tree tests and CI's `amtool` step verify
 * against: the self-hosted ntfy instance in this stack. */
export const PAGE_RECEIVER_NAME = 'ntfy-page';

/** The one topic pages are published to. Not a secret: the instance denies
 * all access by default, so knowing the name grants nothing -- only the
 * publisher token and the owner's login can write or read it. */
export const NTFY_PAGE_TOPIC = 'branchleft-pages';

/** The public status page. Tapping a page opens it, and the one action
 * button below opens it too. It is a public address and carries no secret,
 * so it costs no new credential; Alertmanager and Prometheus have no address
 * a phone can reach, so there is nothing more specific to link. */
export const NTFY_PAGE_CLICK_URL = 'https://status.branchleft.co.uk';

/** ntfy's `actions` value: one `view` button that opens the status page. No
 * action calls Alertmanager (an acknowledge or silence button): that API has
 * no address a phone can reach and a call to it would need a credential. */
export const NTFY_PAGE_ACTIONS = `view,Status page,${NTFY_PAGE_CLICK_URL}`;

/** Where Alertmanager reaches ntfy: the Compose service name on the stack's
 * own network, never the public hostname, so a page does not depend on the
 * edge or on DNS. `priority=5` is ntfy's maximum, the level that bypasses
 * do-not-disturb on the phone. `template=alertmanager` is ntfy's built-in
 * reader of Alertmanager's webhook payload. `click` and `actions` are ntfy's
 * own publish parameters; the CI ntfy step publishes to the pinned server
 * with exactly this URL, so a value the server refuses fails there and not
 * as a page that never arrives. */
export const NTFY_PAGE_URL =
  `http://ntfy:80/${NTFY_PAGE_TOPIC}?template=alertmanager&priority=5&tags=rotating_light` +
  `&click=${NTFY_PAGE_CLICK_URL}&actions=${NTFY_PAGE_ACTIONS.replace(/ /g, '%20')}`;

/**
 * How fast and how often a page is delivered, on every route that sends to
 * the page receiver (the critical route and the page route). The root route's
 * `group_interval: 1h` and `repeat_interval: 24h` are for email, whose
 * repeats spend the mail host's sending reputation; they must not reach a
 * page, which is the reverse case. Why each value:
 *
 * - `group_wait` is how long the first alert of a group waits for company.
 *   Ten seconds is enough to put alerts that start together in one message.
 * - `group_interval` bounds the wait before a group that already notified is
 *   notified again about a new alert in it, or about a resolved one. At one
 *   hour a second ban in the hour and a recovery notice both sat for up to an
 *   hour; at one minute they arrive within about that.
 * - `repeat_interval` re-pages an alert that is still firing, so a page that
 *   went unseen is sent again inside the hour rather than the next day.
 */
export const PAGE_GROUP_WAIT = '10s';
export const PAGE_GROUP_INTERVAL = '1m';
export const PAGE_REPEAT_INTERVAL = '30m';

/** The three timing keys as route lines at `indent` spaces, for a route node
 * that sends to the page receiver. One home, so the critical route and the
 * page route cannot drift apart. */
export function renderPageTimingLines(indent: number): string[] {
  const pad = ' '.repeat(indent);
  return [
    `${pad}group_wait: ${PAGE_GROUP_WAIT}`,
    `${pad}group_interval: ${PAGE_GROUP_INTERVAL}`,
    `${pad}repeat_interval: ${PAGE_REPEAT_INTERVAL}`,
  ];
}

/** The placeholder `render_alertmanager_config.py` fills with the
 * publisher's access token on the host. */
export const NTFY_PAGER_TOKEN_PLACEHOLDER = '__NTFY_PAGER_TOKEN__';

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
    ...renderPageTimingLines(6),
  ].join('\n');
}

/**
 * The page receiver: a webhook to the stack's own ntfy, authenticated with
 * the publisher's bearer token. `send_resolved: true` -- ntfy's alertmanager
 * template renders a resolved alert as "Alert resolved", so the owner sees
 * that an outage cleared rather than reading a stale open page.
 */
export function renderPageReceiverBlock(): string {
  return [
    `  - name: ${PAGE_RECEIVER_NAME}`,
    '    webhook_configs:',
    `      - url: '${NTFY_PAGE_URL}'`,
    '        send_resolved: true',
    '        http_config:',
    '          authorization:',
    '            type: Bearer',
    `            credentials: '${NTFY_PAGER_TOKEN_PLACEHOLDER}'`,
  ].join('\n');
}

/**
 * Every `alert:` block carrying `severity: page` must name an alertname the
 * register covers. The reasoning is in `pageRegister.md`.
 */
export function findUnregisteredPageSeverityAlerts(
  rulesYamlText: string,
  register: readonly PageRegisterEntry[]
): string[] {
  const registered = new Set(pageAlertNames(register));
  return pageSeverityAlertNames(rulesYamlText).filter((name) => !registered.has(name));
}

/**
 * The other direction: every live Alertmanager entry must have a rule that
 * can raise it, or say why none exists. A live entry whose alertname no
 * `severity: page` rule raises, and which names no `ruleExemption`, would
 * register a route for a page that silently never fires -- the failure a
 * later `dormant: false` flip could otherwise cause with no test going red.
 * Returns the offending alertnames, in register order.
 */
export function findLiveEntriesWithoutPageRule(
  rulesYamlText: string,
  register: readonly PageRegisterEntry[]
): string[] {
  const raised = new Set(pageSeverityAlertNames(rulesYamlText));
  return register
    .filter(
      (entry) =>
        entry.deliveryPath === 'alertmanager' &&
        !entry.dormant &&
        entry.alertName !== null &&
        (entry.ruleExemption ?? '').trim() === '' &&
        !raised.has(entry.alertName)
    )
    .map((entry) => entry.alertName)
    .filter((name): name is string => name !== null);
}

/** Every alertname in `rulesYamlText` whose `alert:` block carries
 * `severity: page`, in the order the rules appear. */
function pageSeverityAlertNames(rulesYamlText: string): string[] {
  const lines = rulesYamlText.split('\n');
  const names: string[] = [];
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
      if (severity === 'page') names.push(currentAlert);
    }
  }
  return names;
}
