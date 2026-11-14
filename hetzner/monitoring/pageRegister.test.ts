import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  NTFY_PAGE_TOPIC,
  NTFY_PAGE_URL,
  NTFY_PAGER_TOKEN_PLACEHOLDER,
  PAGE_REGISTER,
  PAGE_RECEIVER_NAME,
  findLiveEntriesWithoutPageRule,
  findUnregisteredPageSeverityAlerts,
  pageAlertNames,
  renderPageReceiverBlock,
  renderPageRoute,
  type PageRegisterEntry,
} from './pageRegister';
import { renderAlertmanagerTemplate, renderAlertRules } from './render';

describe('PAGE_REGISTER', () => {
  it('has exactly six entries -- five Alertmanager and the drain worker outside it', () => {
    expect(PAGE_REGISTER).toHaveLength(6);
    expect(PAGE_REGISTER.map((entry) => entry.id)).toEqual([
      'tier2-safety-match',
      'tenant-failed-unsafe',
      'appeal-latency-breach',
      'readers-cannot-read',
      'drain-worker-stopped',
      'stopped-demo-reaper',
    ]);
  });

  it('routes five entries through Alertmanager and the drain worker through Healthchecks.io instead', () => {
    const byPath = (path: PageRegisterEntry['deliveryPath']) =>
      PAGE_REGISTER.filter((entry) => entry.deliveryPath === path).map((entry) => entry.id);
    expect(byPath('alertmanager')).toEqual([
      'tier2-safety-match',
      'tenant-failed-unsafe',
      'appeal-latency-breach',
      'readers-cannot-read',
      'stopped-demo-reaper',
    ]);
    expect(byPath('healthchecks')).toEqual(['drain-worker-stopped']);
  });

  it('carries no Alertmanager alertname for the drain worker -- it never becomes an alert here', () => {
    const drainWorker = PAGE_REGISTER.find((entry) => entry.id === 'drain-worker-stopped');
    expect(drainWorker?.alertName).toBeNull();
  });

  it('marks exactly appeal-latency-breach and stopped-demo-reaper dormant', () => {
    const dormant = PAGE_REGISTER.filter((entry) => entry.dormant).map((entry) => entry.id);
    expect(dormant).toEqual(['appeal-latency-breach', 'stopped-demo-reaper']);
  });
});

/**
 * The stopped demo reaper is registered before the reaper exists, so its
 * entry must be dormant: a live entry would put its alertname in the page
 * route while no rule can ever raise it. These tests prove a dormant entry
 * does not page, and that dormancy alone is what keeps it off the route.
 */
describe('the stopped-demo-reaper entry', () => {
  const reaper = PAGE_REGISTER.find((entry) => entry.id === 'stopped-demo-reaper');

  it('is registered through Alertmanager, not tenant-scoped, and dormant', () => {
    expect(reaper).toBeDefined();
    expect(reaper?.alertName).toBe('StoppedDemoReaper');
    expect(reaper?.deliveryPath).toBe('alertmanager');
    expect(reaper?.tenantScoped).toBe(false);
    expect(reaper?.dormant).toBe(true);
  });

  it('is left out of the alertnames the page route matches', () => {
    expect(pageAlertNames(PAGE_REGISTER)).not.toContain('StoppedDemoReaper');
  });

  it('does not appear in the rendered page route or the rendered Alertmanager config', () => {
    expect(renderPageRoute(PAGE_REGISTER)).not.toContain('StoppedDemoReaper');
    expect(renderAlertmanagerTemplate()).not.toContain('StoppedDemoReaper');
  });

  it('would page if it were switched on -- dormancy alone is what keeps it off the route', () => {
    const live = PAGE_REGISTER.map((entry) =>
      entry.id === 'stopped-demo-reaper' ? { ...entry, dormant: false } : entry
    );
    expect(pageAlertNames(live)).toContain('StoppedDemoReaper');
    expect(renderPageRoute(live)).toContain('StoppedDemoReaper');
    expect(renderAlertmanagerTemplate(live)).toContain('StoppedDemoReaper');
  });

  it('refuses a severity: page rule under its alertname while it is dormant', () => {
    // A rule that raised this page today would reach no phone, so the
    // register's own check reports it rather than letting it ship.
    const rules = [
      'groups:',
      '  - name: g',
      '    rules:',
      '      - alert: StoppedDemoReaper',
      '        expr: vector(1)',
      '        labels:',
      '          severity: page',
      '',
    ].join('\n');
    expect(findUnregisteredPageSeverityAlerts(rules, PAGE_REGISTER)).toEqual(['StoppedDemoReaper']);
  });

  it('carries no work-item reference in its shipped text', () => {
    expect(`${reaper?.name} ${reaper?.reason}`).not.toMatch(/#\d|workspace/i);
  });
});

describe('pageAlertNames', () => {
  it('names every non-dormant Alertmanager entry, in register order, and nothing else', () => {
    expect(pageAlertNames(PAGE_REGISTER)).toEqual([
      'TierTwoSafetyMatch',
      'TenantFailedUnsafe',
      'ReadersCannotRead',
    ]);
  });

  it('excludes a dormant entry even when it names an alertname', () => {
    const register: PageRegisterEntry[] = [
      {
        id: 'x',
        name: 'x',
        reason: 'x',
        alertName: 'X',
        deliveryPath: 'alertmanager',
        dormant: true,
        tenantScoped: true,
      },
    ];
    expect(pageAlertNames(register)).toEqual([]);
  });

  it('excludes a Healthchecks-delivered entry even if it somehow named an alertname', () => {
    const register: PageRegisterEntry[] = [
      {
        id: 'x',
        name: 'x',
        reason: 'x',
        alertName: 'X',
        deliveryPath: 'healthchecks',
        dormant: false,
        tenantScoped: true,
      },
    ];
    expect(pageAlertNames(register)).toEqual([]);
  });
});

describe('renderPageRoute', () => {
  it('renders exactly the three live Alertmanager entries into the matcher, from the register and nothing else', () => {
    const route = renderPageRoute(PAGE_REGISTER);
    expect(route).toContain('severity = "page"');
    expect(route).toContain(
      'alertname =~ "^(TierTwoSafetyMatch|TenantFailedUnsafe|ReadersCannotRead)$"'
    );
    // Not present: the dormant entry, and the Healthchecks-delivered one.
    expect(route).not.toContain('AppealLatencyBreach');
    expect(route).not.toContain('drain-worker-stopped');
  });

  it('routes to the placeholder receiver and groups on tenant, not on alertname -- the cause, not the entry', () => {
    const route = renderPageRoute(PAGE_REGISTER);
    expect(route).toContain(`receiver: ${PAGE_RECEIVER_NAME}`);
    expect(route).toContain("group_by: ['tenant']");
  });

  it('renders no route at all once every Alertmanager entry is dormant', () => {
    const allDormant = PAGE_REGISTER.map((entry) =>
      entry.deliveryPath === 'alertmanager' ? { ...entry, dormant: true } : entry
    );
    expect(renderPageRoute(allDormant)).toBe('');
  });

  it('is derived from its argument, not from a hardcoded copy of PAGE_REGISTER', () => {
    // The wiring proof: a single custom entry, unrelated to the real
    // register, must show up verbatim. An implementation that ignored
    // `register` and re-read the module-level PAGE_REGISTER instead would
    // fail this on the alertname alone.
    const custom: readonly PageRegisterEntry[] = [
      {
        id: 'fixture-only',
        name: 'fixture only',
        reason: 'exists only to prove renderPageRoute reads its argument',
        alertName: 'FixtureOnlyPageAlert',
        deliveryPath: 'alertmanager',
        dormant: false,
        tenantScoped: true,
      },
    ];
    const route = renderPageRoute(custom);
    expect(route).toContain('alertname =~ "^(FixtureOnlyPageAlert)$"');
    expect(route).not.toContain('TierTwoSafetyMatch');
  });
});

describe('renderPageReceiverBlock', () => {
  it('is a webhook to the stack-internal ntfy, never the public hostname', () => {
    const block = renderPageReceiverBlock();
    expect(block).toContain(`name: ${PAGE_RECEIVER_NAME}`);
    expect(block).toContain('webhook_configs:');
    expect(block).toContain(`url: '${NTFY_PAGE_URL}'`);
    expect(NTFY_PAGE_URL.startsWith('http://ntfy:80/')).toBe(true);
    expect(NTFY_PAGE_URL).toContain(`/${NTFY_PAGE_TOPIC}?`);
    expect(NTFY_PAGE_URL).toContain('template=alertmanager');
    expect(NTFY_PAGE_URL).toContain('priority=5');
  });

  it('authenticates with the publisher token placeholder and carries no literal credential', () => {
    const block = renderPageReceiverBlock();
    expect(block).toContain('type: Bearer');
    expect(block).toContain(`credentials: '${NTFY_PAGER_TOKEN_PLACEHOLDER}'`);
    expect(block).not.toMatch(/tk_[a-z0-9]{29}/);
  });

  it('does not send a resolved notice -- a page that clears itself is not a second page', () => {
    expect(renderPageReceiverBlock()).toContain('send_resolved: false');
  });

  it('is no longer the placeholder receiver', () => {
    expect(PAGE_RECEIVER_NAME).not.toMatch(/TBD/);
    expect(renderAlertmanagerTemplate()).not.toContain('PAGE_RECEIVER_TBD');
  });
});

describe('the ntfy server config', () => {
  const template = readFileSync(join(__dirname, 'stack', 'ntfy', 'server.yml.tmpl'), 'utf8');
  const active = template
    .split('\n')
    .filter((line) => !line.trimStart().startsWith('#'))
    .join('\n');

  it('denies all access by default and has signup off', () => {
    expect(active).toMatch(/^auth-default-access: deny-all$/m);
    expect(active).toMatch(/^enable-signup: false$/m);
    expect(active).toMatch(/^auth-file: /m);
  });

  it('never sets upstream-base-url, so no message is relayed to a third-party server', () => {
    expect(active).not.toMatch(/upstream-base-url/);
  });

  it('grants the two publishers write-only and the owner read-only, on the one topic', () => {
    expect(active).toContain(`'alertmanager:${NTFY_PAGE_TOPIC}:write-only'`);
    expect(active).toContain(`'watcher:${NTFY_PAGE_TOPIC}:write-only'`);
    expect(active).toContain(`'owner:${NTFY_PAGE_TOPIC}:read-only'`);
    const grants = active.match(/^\s+- '[a-z]+:[^:']+:(read-only|write-only|read-write)'$/gm) ?? [];
    expect(grants).toHaveLength(3);
  });

  it('commits only placeholders for every secret', () => {
    expect(active).not.toMatch(/tk_[a-z0-9]{29}/);
    expect(active).not.toMatch(/\$2[aby]\$/);
    for (const token of [
      '__NTFY_PAGER_TOKEN__',
      '__NTFY_WATCHER_TOKEN__',
      '__NTFY_OWNER_PASSWORD_HASH__',
      '__NTFY_MACHINE_PASSWORD_HASH__',
    ]) {
      expect(active).toContain(token);
    }
  });

  it('serves behind the edge on the public hostname the registry names', () => {
    expect(active).toMatch(/^base-url: https:\/\/ntfy\.branchleft\.co\.uk$/m);
    expect(active).toMatch(/^behind-proxy: true$/m);
  });
});

describe('every critical alert pages the phone', () => {
  const rendered = renderAlertmanagerTemplate();
  const criticalRoute =
    '        - severity = "critical"\n      receiver: ntfy-page\n      continue: true';

  it('routes severity=critical to ntfy-page and continues to the later routes', () => {
    expect(rendered).toContain(criticalRoute);
  });

  it('keeps the off-host email for criticals, but never for the mail pair or on-host alerts', () => {
    expect(rendered).toContain(
      '        - severity = "critical"\n' +
        '        - alertname !~ "^(MailHostDown|AlertEmailDeliveryFailing)$"\n' +
        '        - notify != "on-host"\n' +
        '      receiver: email'
    );
  });

  it('puts the critical route after Watchdog and before every route that stops the walk', () => {
    const at = (needle: string) => rendered.indexOf(needle);
    expect(at('alertname = "Watchdog"')).toBeLessThan(at(criticalRoute));
    expect(at(criticalRoute)).toBeLessThan(at('notify = "on-host"'));
    expect(at(criticalRoute)).toBeLessThan(at('receiver: mailhost-deadman'));
  });

  it('does not page for warnings', () => {
    expect(rendered).not.toContain('severity = "warning"\n      receiver: ntfy-page');
  });
});

describe('renderAlertmanagerTemplate wired to the page register', () => {
  it('uses PAGE_REGISTER by default', () => {
    const rendered = renderAlertmanagerTemplate();
    expect(rendered).toContain(
      'alertname =~ "^(TierTwoSafetyMatch|TenantFailedUnsafe|ReadersCannotRead)$"'
    );
    expect(rendered).toContain(`name: ${PAGE_RECEIVER_NAME}`);
  });

  it("changes the rendered route when handed a different register -- proof the template's page route is not a hardcoded duplicate", () => {
    const custom: readonly PageRegisterEntry[] = [
      {
        id: 'fixture-only',
        name: 'fixture only',
        reason: 'wiring proof',
        alertName: 'FixtureOnlyPageAlert',
        deliveryPath: 'alertmanager',
        dormant: false,
        tenantScoped: true,
      },
    ];
    const rendered = renderAlertmanagerTemplate(custom);
    expect(rendered).toContain('alertname =~ "^(FixtureOnlyPageAlert)$"');
    expect(rendered).not.toContain('TierTwoSafetyMatch');
  });

  it('renders no page route section at all when the register has nothing left to page on', () => {
    const rendered = renderAlertmanagerTemplate([]);
    expect(rendered).not.toContain('severity = "page"');
    // The rest of the template (Watchdog, on-host, mailhost-deadman) must
    // still be there -- an empty register must not blank the whole file.
    expect(rendered).toContain('alertname = "Watchdog"');
  });
});

/**
 * The control sabotage the issue names: a page-severity alert with no
 * register entry must be a build failure. `findUnregisteredPageSeverityAlerts`
 * is the mechanism; these tests prove it catches the gap and, separately,
 * that it says nothing about the estate as the register stands today.
 */
describe('findUnregisteredPageSeverityAlerts', () => {
  it('says nothing about a properly registered page-severity alert', () => {
    const rules = [
      'groups:',
      '  - name: g',
      '    rules:',
      '      - alert: TierTwoSafetyMatch',
      '        expr: vector(1)',
      '        labels:',
      '          severity: page',
      '',
    ].join('\n');
    expect(findUnregisteredPageSeverityAlerts(rules, PAGE_REGISTER)).toEqual([]);
  });

  it('goes red on a page-severity alert the register has never heard of', () => {
    // The sabotage, reproduced mechanically: a producer starts raising
    // severity: page under a brand new alertname, forgetting the register
    // entry that is supposed to accompany it.
    const rules = [
      'groups:',
      '  - name: g',
      '    rules:',
      '      - alert: SomeNewPagingAlert',
      '        expr: vector(1)',
      '        labels:',
      '          severity: page',
      '',
    ].join('\n');
    expect(findUnregisteredPageSeverityAlerts(rules, PAGE_REGISTER)).toEqual([
      'SomeNewPagingAlert',
    ]);
  });

  it('does not flag a non-page severity, however unfamiliar the alertname', () => {
    const rules = [
      'groups:',
      '  - name: g',
      '    rules:',
      '      - alert: SomeUnrelatedWarning',
      '        expr: vector(1)',
      '        labels:',
      '          severity: warning',
      '',
    ].join('\n');
    expect(findUnregisteredPageSeverityAlerts(rules, PAGE_REGISTER)).toEqual([]);
  });

  it('attributes severity to the nearest preceding alert, not to a sibling rule', () => {
    const rules = [
      'groups:',
      '  - name: g',
      '    rules:',
      '      - alert: TierTwoSafetyMatch',
      '        expr: vector(1)',
      '        labels:',
      '          severity: page',
      '      - alert: SomeOtherAlert',
      '        expr: vector(1)',
      '        labels:',
      '          severity: warning',
      '',
    ].join('\n');
    expect(findUnregisteredPageSeverityAlerts(rules, PAGE_REGISTER)).toEqual([]);
  });

  it('is real, and currently silent, against the actual rendered alert rules', () => {
    // Not a fixture: today's alerts.yml carries no severity: page label at
    // all -- entries 1-4's producers land with their own epics -- so this
    // is a true negative against production, not an assertion that the
    // checker was never run for real.
    expect(findUnregisteredPageSeverityAlerts(renderAlertRules(), PAGE_REGISTER)).toEqual([]);
  });
});

/**
 * The opposite direction to the block above: a live Alertmanager entry whose
 * alertname no `severity: page` rule raises would register a route for a page
 * that never fires. Each live entry must carry such a rule in the rendered
 * rules, or a named exemption saying who raises it instead.
 */
describe('findLiveEntriesWithoutPageRule', () => {
  const rulesRaising = (alertName: string) =>
    [
      'groups:',
      '  - name: g',
      '    rules:',
      `      - alert: ${alertName}`,
      '        expr: vector(1)',
      '        labels:',
      '          severity: page',
      '',
    ].join('\n');
  const live = (overrides: Partial<PageRegisterEntry> = {}): PageRegisterEntry => ({
    id: 'fixture-only',
    name: 'fixture only',
    reason: 'exists only to prove the rule check',
    alertName: 'FixtureOnlyPageAlert',
    deliveryPath: 'alertmanager',
    dormant: false,
    tenantScoped: true,
    ...overrides,
  });

  it('refuses a live Alertmanager entry no severity: page rule raises and that names no exemption', () => {
    expect(findLiveEntriesWithoutPageRule(rulesRaising('SomethingElse'), [live()])).toEqual([
      'FixtureOnlyPageAlert',
    ]);
  });

  it('accepts a live entry whose alertname a severity: page rule raises', () => {
    expect(findLiveEntriesWithoutPageRule(rulesRaising('FixtureOnlyPageAlert'), [live()])).toEqual(
      []
    );
  });

  it('does not accept a rule at another severity as the page rule', () => {
    const warning = rulesRaising('FixtureOnlyPageAlert').replace(
      'severity: page',
      'severity: warning'
    );
    expect(findLiveEntriesWithoutPageRule(warning, [live()])).toEqual(['FixtureOnlyPageAlert']);
  });

  it('accepts a live entry with a named exemption and no rule', () => {
    const exempt = live({ ruleExemption: 'Raised by an external sender, not a Prometheus rule.' });
    expect(findLiveEntriesWithoutPageRule('groups: []\n', [exempt])).toEqual([]);
  });

  it('does not accept a blank exemption as a reason', () => {
    expect(findLiveEntriesWithoutPageRule('groups: []\n', [live({ ruleExemption: '  ' })])).toEqual(
      ['FixtureOnlyPageAlert']
    );
  });

  it('leaves a dormant entry and a Healthchecks-delivered entry alone', () => {
    const register = [
      live({ id: 'a', alertName: 'DormantOne', dormant: true }),
      live({ id: 'b', alertName: null, deliveryPath: 'healthchecks' }),
    ];
    expect(findLiveEntriesWithoutPageRule('groups: []\n', register)).toEqual([]);
  });

  it('reports every offender, in register order', () => {
    const register = [
      live({ id: 'a', alertName: 'First' }),
      live({ id: 'b', alertName: 'Second', ruleExemption: 'Raised elsewhere.' }),
      live({ id: 'c', alertName: 'Third' }),
    ];
    expect(findLiveEntriesWithoutPageRule('groups: []\n', register)).toEqual(['First', 'Third']);
  });

  it('goes red when the dormant reaper entry is flipped live with no rule and no exemption', () => {
    // The sabotage the register's own text asks for: `dormant: false` in the
    // same change that adds no rule.
    const flipped = PAGE_REGISTER.map((entry) =>
      entry.id === 'stopped-demo-reaper' ? { ...entry, dormant: false } : entry
    );
    expect(findLiveEntriesWithoutPageRule(renderAlertRules(), flipped)).toEqual([
      'StoppedDemoReaper',
    ]);
  });

  it('holds for the register as it stands, against the actual rendered alert rules', () => {
    expect(findLiveEntriesWithoutPageRule(renderAlertRules(), PAGE_REGISTER)).toEqual([]);
  });

  it('gives each of the three live Alertmanager entries a named exemption today, since no rule raises them', () => {
    const exempt = PAGE_REGISTER.filter((entry) => entry.ruleExemption !== undefined).map(
      (entry) => entry.alertName
    );
    expect(exempt).toEqual(['TierTwoSafetyMatch', 'TenantFailedUnsafe', 'ReadersCannotRead']);
    for (const entry of PAGE_REGISTER) {
      expect(entry.ruleExemption ?? 'none').not.toMatch(/#\d|workspace/i);
    }
  });
});
