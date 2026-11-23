import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  DISCARD_RECEIVER_NAME,
  NTFY_ABUSE_TOPIC,
  NTFY_PAGE_TOPIC,
  NTFY_PAGE_URL,
  NTFY_PAGER_TOKEN_PLACEHOLDER,
  PAGE_REGISTER,
  PAGE_RECEIVER_NAME,
  findLiveEntriesWithoutPageRule,
  findUnregisteredPageSeverityAlerts,
  holdEdgeBanOwnerStale,
  pageAlertNames,
  renderDiscardReceiverBlock,
  renderEdgeBanOwnerStaleDiscardRoute,
  renderOwnedEdgeBanRoute,
  renderPageReceiverBlock,
  renderPageRoute,
  type PageRegisterEntry,
} from './pageRegister';
import { renderAlertmanagerTemplate, renderAlertRules } from './render';

describe('PAGE_REGISTER', () => {
  it('has exactly ten entries -- the Alertmanager ones, the drain worker and the abuse report outside them, and the secret-scanning page sent by a workflow', () => {
    expect(PAGE_REGISTER).toHaveLength(10);
    expect(PAGE_REGISTER.map((entry) => entry.id)).toEqual([
      'tier2-safety-match',
      'tenant-failed-unsafe',
      'appeal-latency-breach',
      'readers-cannot-read',
      'edge-ban',
      'edge-ban-owner-stale',
      'drain-worker-stopped',
      'abuse-report',
      'stopped-demo-reaper',
      'secret-scanning-alert',
    ]);
  });

  it('routes seven entries through Alertmanager, the drain worker through Healthchecks.io, the abuse report straight to ntfy and the secret-scanning page through a workflow', () => {
    const byPath = (path: PageRegisterEntry['deliveryPath']) =>
      PAGE_REGISTER.filter((entry) => entry.deliveryPath === path).map((entry) => entry.id);
    expect(byPath('alertmanager')).toEqual([
      'tier2-safety-match',
      'tenant-failed-unsafe',
      'appeal-latency-breach',
      'readers-cannot-read',
      'edge-ban',
      'edge-ban-owner-stale',
      'stopped-demo-reaper',
    ]);
    expect(byPath('healthchecks')).toEqual(['drain-worker-stopped']);
    expect(byPath('ntfy_direct')).toEqual(['abuse-report']);
    expect(byPath('github-workflow')).toEqual(['secret-scanning-alert']);
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

/**
 * The secret-scanning page is posted to ntfy by a scheduled workflow, not by
 * Alertmanager. Its entry must therefore leave every Alertmanager check and
 * route exactly as it found them: these tests prove it, and that the checks
 * still bite on an Alertmanager entry with the same shape.
 */
describe('the secret-scanning-alert entry', () => {
  const SECRET_ENTRY_ID = 'secret-scanning-alert';
  const withoutSecretEntry = PAGE_REGISTER.filter((entry) => entry.id !== SECRET_ENTRY_ID);
  const secretEntries = PAGE_REGISTER.filter((entry) => entry.id === SECRET_ENTRY_ID);
  const alertmanagerRouteMatcher =
    'alertname =~ "^(TierTwoSafetyMatch|TenantFailedUnsafe|ReadersCannotRead|EdgeBanIssued)$"';

  it('is delivered by a workflow, with no Alertmanager alertname, live and not tenant-scoped', () => {
    const entry = PAGE_REGISTER.find((candidate) => candidate.id === SECRET_ENTRY_ID);
    expect(entry?.deliveryPath).toBe('github-workflow');
    expect(entry?.alertName).toBeNull();
    expect(entry?.dormant).toBe(false);
    expect(entry?.tenantScoped).toBe(false);
  });

  it('renders a page route byte-identical to the one the register renders without it', () => {
    expect(renderPageRoute(PAGE_REGISTER)).toBe(renderPageRoute(withoutSecretEntry));
  });

  it('renders the same alertname matcher the committed Alertmanager template carries', () => {
    const template = readFileSync(
      join(__dirname, 'stack', 'alertmanager', 'alertmanager.yml.tmpl'),
      'utf8'
    );
    expect(renderPageRoute(holdEdgeBanOwnerStale(PAGE_REGISTER))).toContain(
      alertmanagerRouteMatcher
    );
    expect(template).toContain(alertmanagerRouteMatcher);
  });

  it('puts no secret-related word into the rendered page route', () => {
    expect(renderPageRoute(PAGE_REGISTER)).not.toMatch(/secret/i);
  });

  it('is left out of pageAlertNames, which equals the list without it', () => {
    expect(pageAlertNames(PAGE_REGISTER)).toEqual(pageAlertNames(withoutSecretEntry));
    expect(pageAlertNames(PAGE_REGISTER)).not.toContain(SECRET_ENTRY_ID);
    expect(pageAlertNames(PAGE_REGISTER).some((name) => /secret/i.test(name))).toBe(false);
  });

  it('is not reported by findLiveEntriesWithoutPageRule, even with no rules at all', () => {
    expect(findLiveEntriesWithoutPageRule('groups: []\n', secretEntries)).toEqual([]);
  });

  it('is still reported when an Alertmanager entry beside it has no rule -- the check can fail', () => {
    const unraised: PageRegisterEntry = {
      id: 'fixture-only',
      name: 'fixture only',
      reason: 'exists only to prove the rule check still bites',
      alertName: 'FixtureOnlyPageAlert',
      deliveryPath: 'alertmanager',
      dormant: false,
      tenantScoped: true,
    };
    expect(findLiveEntriesWithoutPageRule('groups: []\n', [...secretEntries, unraised])).toEqual([
      'FixtureOnlyPageAlert',
    ]);
  });
});

describe('pageAlertNames', () => {
  it('names every non-dormant Alertmanager entry, in register order, and nothing else', () => {
    expect(pageAlertNames(PAGE_REGISTER)).toEqual([
      'TierTwoSafetyMatch',
      'TenantFailedUnsafe',
      'ReadersCannotRead',
      'EdgeBanIssued',
      'EdgeBanOwnerStale',
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
  it('renders exactly the five live Alertmanager entries into the matcher, from the register and nothing else', () => {
    const route = renderPageRoute(PAGE_REGISTER);
    expect(route).toContain('severity = "page"');
    expect(route).toContain(
      'alertname =~ "^(TierTwoSafetyMatch|TenantFailedUnsafe|ReadersCannotRead|EdgeBanIssued|EdgeBanOwnerStale)$"'
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

describe('the edge-ban entries', () => {
  const entry = (id: string) => PAGE_REGISTER.find((candidate) => candidate.id === id);

  it('says that owned bans page and the rest go to email', () => {
    expect(entry('edge-ban')?.reason).toMatch(/owner's own addresses? pages/);
    expect(entry('edge-ban')?.reason).toMatch(/any other address goes to email/);
  });

  it('registers the classifier staleness page as a live, untenanted Alertmanager entry with a rule', () => {
    const stale = entry('edge-ban-owner-stale');
    expect(stale?.alertName).toBe('EdgeBanOwnerStale');
    expect(stale?.deliveryPath).toBe('alertmanager');
    expect(stale?.dormant).toBe(false);
    expect(stale?.tenantScoped).toBe(false);
    expect(stale?.ruleExemption).toBeUndefined();
  });

  it('names no work item in its shipped text', () => {
    for (const id of ['edge-ban', 'edge-ban-owner-stale']) {
      expect(`${entry(id)?.name} ${entry(id)?.reason}`).not.toMatch(/#\d|workspace/i);
    }
  });
});

describe('the edge-ban rules', () => {
  const rules = renderAlertRules();
  const ruleText = (name: string): string =>
    (rules.split('- alert: ').find((rule) => rule.startsWith(`${name}\n`)) ?? '').split('\n\n')[0];
  const staleExpression =
    '(max(time() - edge_ban_owner_last_run_timestamp_seconds) > 900) or absent(edge_ban_owner_last_run_timestamp_seconds)';
  const heldExpression =
    '(max(time() - edge_ban_owner_last_run_timestamp_seconds) > 900) or absent_over_time(edge_ban_owner_last_run_timestamp_seconds[10m])';

  it('pages EdgeBanIssued for each owned ban by its decision id, or for every ban while the classifier is stale', () => {
    const rule = ruleText('EdgeBanIssued');
    expect(rule).toContain('sum by (reason, decision_id) (edge_ban_owned{owned="true"}) > 0');
    expect(rule).toContain('severity: page');
  });

  it('holds the page-everything fallback for ten minutes of absence, and only the fallback', () => {
    const rule = ruleText('EdgeBanIssued');
    expect(rule).toContain(`and on() (${heldExpression})`);
    expect(rule).not.toContain(`and on() (${staleExpression})`);
  });

  it('keeps EdgeBanUnowned off the page severity and sends it to the owner by email', () => {
    const rule = ruleText('EdgeBanUnowned');
    expect(rule).toContain('edge_ban_owned{owned="false"}');
    expect(rule).toContain('severity: warning');
    expect(rule).toContain('owner_action: "true"');
    expect(rule).not.toContain('severity: page');
  });

  it('raises EdgeBanOwnerStale at once on absence, not held like the fallback', () => {
    const rule = ruleText('EdgeBanOwnerStale');
    expect(rule).toContain(`expr: ${staleExpression}`);
    expect(rule).toContain('for: 5m');
    expect(rule).toContain('severity: page');
  });

  it('never names an address: no label, annotation or example carries an IP literal', () => {
    for (const name of ['EdgeBanIssued', 'EdgeBanUnowned', 'EdgeBanOwnerStale']) {
      expect(ruleText(name)).not.toMatch(/\b\d{1,3}(\.\d{1,3}){3}\b/);
      expect(ruleText(name)).not.toMatch(/\b[0-9a-f]{1,4}(:[0-9a-f]{0,4}){3,}\b/i);
    }
  });
});

describe('renderOwnedEdgeBanRoute', () => {
  it('matches the page severity and the one alertname, and pages the ntfy receiver', () => {
    const route = renderOwnedEdgeBanRoute(PAGE_REGISTER);
    expect(route).toContain('severity = "page"');
    expect(route).toContain('alertname = "EdgeBanIssued"');
    expect(route).toContain(`receiver: ${PAGE_RECEIVER_NAME}`);
  });

  it('groups on the scenario and renotifies a changed group within five minutes', () => {
    const route = renderOwnedEdgeBanRoute(PAGE_REGISTER);
    expect(route).toContain("group_by: ['alertname', 'reason']");
    expect(route).toContain('group_wait: 30s');
    expect(route).toContain('group_interval: 5m');
  });

  it('never continues, so an owned ban is not delivered a second time by the generic route', () => {
    expect(renderOwnedEdgeBanRoute(PAGE_REGISTER)).not.toContain('continue');
  });

  it('renders nothing once the edge-ban entry is dormant', () => {
    const dormant = PAGE_REGISTER.map((candidate) =>
      candidate.id === 'edge-ban' ? { ...candidate, dormant: true } : candidate
    );
    expect(renderOwnedEdgeBanRoute(dormant)).toBe('');
  });

  it('renders nothing for a register that does not name the alert', () => {
    expect(renderOwnedEdgeBanRoute([])).toBe('');
  });

  it('sits in the template immediately before the generic page route, in either mode', () => {
    for (const installed of [true, false]) {
      const rendered = renderAlertmanagerTemplate(PAGE_REGISTER, installed);
      const routed = installed ? PAGE_REGISTER : holdEdgeBanOwnerStale(PAGE_REGISTER);
      const owned = rendered.indexOf(renderOwnedEdgeBanRoute(routed));
      const generic = rendered.indexOf(renderPageRoute(routed));
      expect(owned).toBeGreaterThan(-1);
      expect(generic).toBeGreaterThan(owned);
      expect(rendered.slice(owned, generic).match(/- matchers:/g)).toHaveLength(1);
    }
  });

  it('leaves the generic page route grouped on tenant', () => {
    expect(renderPageRoute(PAGE_REGISTER)).toContain("group_by: ['tenant']");
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

  it('sends the resolved notice to the phone, so a cleared page reads as cleared', () => {
    expect(renderPageReceiverBlock()).toContain('send_resolved: true');
    expect(renderPageReceiverBlock()).not.toContain('send_resolved: false');
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

  it('grants the two publishers write-only and the owner read-only, on the page topic', () => {
    expect(active).toContain(`'alertmanager:${NTFY_PAGE_TOPIC}:write-only'`);
    expect(active).toContain(`'watcher:${NTFY_PAGE_TOPIC}:write-only'`);
    expect(active).toContain(`'owner:${NTFY_PAGE_TOPIC}:read-only'`);
  });

  it('gives the mail host one grant, write-only on the abuse topic, and nothing on the page topic', () => {
    expect(active).toContain(`'mx1:${NTFY_ABUSE_TOPIC}:write-only'`);
    expect(active).toContain(`'owner:${NTFY_ABUSE_TOPIC}:read-only'`);
    const grants =
      active.match(/^\s+- '[a-z0-9]+:[^:']+:(read-only|write-only|read-write)'$/gm) ?? [];
    expect(grants).toHaveLength(5);
    const mx1 = grants.filter((line) => line.includes("'mx1:"));
    expect(mx1).toHaveLength(1);
    expect(mx1[0]).not.toContain(NTFY_PAGE_TOPIC);
    expect(mx1[0]).toContain('write-only');
  });

  it('commits only placeholders for every secret', () => {
    expect(active).not.toMatch(/tk_[a-z0-9]{29}/);
    expect(active).not.toMatch(/\$2[aby]\$/);
    for (const token of [
      '__NTFY_PAGER_TOKEN__',
      '__NTFY_WATCHER_TOKEN__',
      '__NTFY_OWNER_PASSWORD_HASH__',
      '__NTFY_MACHINE_PASSWORD_HASH__',
      '__NTFY_MX1_TOKEN__',
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
  it('renders every live register entry into the page route while the classifier is installed', () => {
    const rendered = renderAlertmanagerTemplate(PAGE_REGISTER, true);
    expect(rendered).toContain(
      'alertname =~ "^(TierTwoSafetyMatch|TenantFailedUnsafe|ReadersCannotRead|EdgeBanIssued|EdgeBanOwnerStale)$"'
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

  it('leaves a GitHub-workflow entry alone even with an alertname, and still reports an Alertmanager one', () => {
    const register = [
      live({
        id: 'workflow',
        alertName: 'SyntheticWorkflowAlert',
        deliveryPath: 'github-workflow',
      }),
      live({ id: 'control', alertName: 'SyntheticAlertmanagerAlert' }),
    ];
    expect(findLiveEntriesWithoutPageRule('groups: []\n', register)).toEqual([
      'SyntheticAlertmanagerAlert',
    ]);
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

/** An unparseable line in the rendered route tree: the walker below cannot judge it. */
class UnparseableRouteError extends Error {
  public constructor(line: string) {
    super(`unparseable route text: ${line}`);
    this.name = 'UnparseableRouteError';
  }
}

interface RouteDelivery {
  readonly receiver: string;
  readonly groupBy: readonly string[];
  readonly groupWaitSeconds: number;
  readonly groupIntervalSeconds: number;
  readonly groupKey: readonly string[];
}

const SECONDS_PER_UNIT: Readonly<Record<string, number>> = { s: 1, m: 60, h: 3600 };

function durationSeconds(text: string): number {
  const parsed = /^(\d+)([smh])$/.exec(text);
  if (parsed === null) throw new UnparseableRouteError(text);
  return Number(parsed[1]) * SECONDS_PER_UNIT[parsed[2]];
}

function routeSetting(text: string, key: string, indent: string): string | undefined {
  return new RegExp(`^${indent}${key}: (.+)$`, 'm').exec(text)?.[1];
}

function routeGroupBy(text: string, indent: string): string[] | undefined {
  const raw = routeSetting(text, 'group_by', indent);
  return raw === undefined ? undefined : [...raw.matchAll(/'([^']+)'/g)].map((match) => match[1]);
}

function matcherHolds(matcher: string, labels: Readonly<Record<string, string>>): boolean {
  const parsed = /^(\w+) (=~|!~|!=|=) "(.*)"$/.exec(matcher);
  if (parsed === null) throw new UnparseableRouteError(matcher);
  const [, name, operator, expected] = parsed;
  const actual = labels[name] ?? '';
  if (operator === '=') return actual === expected;
  if (operator === '!=') return actual !== expected;
  const matched = new RegExp(`^(?:${expected})$`).test(actual);
  return operator === '=~' ? matched : !matched;
}

/** Each direct child of the root `routes:` list, as one text block. */
function childRoutes(template: string): string[] {
  const route = template.slice(
    template.indexOf('\nroute:\n'),
    template.indexOf('\ninhibit_rules:')
  );
  const blocks: string[] = [];
  for (const line of route.split('\n')) {
    if (line.startsWith('    - ')) blocks.push(`${line}\n`);
    else if (blocks.length > 0 && line.startsWith('      '))
      blocks[blocks.length - 1] += `${line}\n`;
  }
  return blocks;
}

/**
 * Alertmanager's route walk for `labels` over the rendered template: every
 * child in order, the first match wins unless it says `continue`, and the
 * root receiver applies only when no child matched. Settings a child leaves
 * out come from the root. Ported from the Python walker that tests the
 * committed template.
 */
function walkRoutes(template: string, labels: Readonly<Record<string, string>>): RouteDelivery[] {
  const root = template.slice(template.indexOf('\nroute:\n'), template.indexOf('\n  routes:\n'));
  const rootGroupBy = routeGroupBy(root, '  ') ?? [];
  const rootWait = routeSetting(root, 'group_wait', '  ') ?? '';
  const rootInterval = routeSetting(root, 'group_interval', '  ') ?? '';
  const rootReceiver = routeSetting(root, 'receiver', '  ') ?? '';

  const delivery = (receiver: string, block: string): RouteDelivery => {
    const groupBy = routeGroupBy(block, '      ') ?? rootGroupBy;
    return {
      receiver,
      groupBy,
      groupWaitSeconds: durationSeconds(routeSetting(block, 'group_wait', '      ') ?? rootWait),
      groupIntervalSeconds: durationSeconds(
        routeSetting(block, 'group_interval', '      ') ?? rootInterval
      ),
      groupKey: groupBy.map((name) => `${name}=${labels[name] ?? ''}`),
    };
  };

  const reached: RouteDelivery[] = [];
  for (const block of childRoutes(template)) {
    const matchers = [...block.matchAll(/^ {8}- (.+)$/gm)].map((match) => match[1]);
    if (!matchers.every((matcher) => matcherHolds(matcher, labels))) continue;
    reached.push(delivery(routeSetting(block, 'receiver', '      ') ?? '', block));
    if (routeSetting(block, 'continue', '      ') !== 'true') return reached;
  }
  return reached.length > 0 ? reached : [delivery(rootReceiver, '')];
}

const receiversReached = (template: string, labels: Readonly<Record<string, string>>): string[] =>
  walkRoutes(template, labels).map((step) => step.receiver);

const OWNED_BAN_SECONDS_BOUND = 300;
const ownedBan = (decisionId: string, reason = 'crowdsecurity/http-probing') => ({
  alertname: 'EdgeBanIssued',
  severity: 'page',
  reason,
  decision_id: decisionId,
});
const unownedBan = {
  alertname: 'EdgeBanUnowned',
  severity: 'warning',
  owner_action: 'true',
  reason: 'crowdsecurity/http-probing',
};
const staleClassifier = { alertname: 'EdgeBanOwnerStale', severity: 'page' };

describe('the route walker', () => {
  const template = renderAlertmanagerTemplate(PAGE_REGISTER, true);

  it('is not vacuous: a page for an alert no route names reaches email only', () => {
    expect(
      receiversReached(template, { alertname: 'SomeUnregisteredPagingAlert', severity: 'page' })
    ).toEqual(['email']);
  });

  it('honours continue: a critical alert reaches the phone and both mailboxes', () => {
    expect(
      receiversReached(template, { alertname: 'SomeCriticalAlert', severity: 'critical' })
    ).toEqual(['ntfy-page', 'email', 'email-on-host']);
  });
});

describe('who is paged for an edge ban when the classifier is installed', () => {
  const template = renderAlertmanagerTemplate(PAGE_REGISTER, true);

  it('pages the phone for an owned ban, and nothing else', () => {
    expect(receiversReached(template, ownedBan('101'))).toEqual([PAGE_RECEIVER_NAME]);
  });

  it('sends an unowned ban to both mailboxes and never to the phone', () => {
    const reached = receiversReached(template, unownedBan);
    expect(reached).toContain('email');
    expect(reached).toContain('email-on-host');
    expect(reached).not.toContain(PAGE_RECEIVER_NAME);
  });

  it('pages the phone for a stale classifier', () => {
    expect(receiversReached(template, staleClassifier)).toEqual([PAGE_RECEIVER_NAME]);
  });

  it('has no discard receiver or route at all', () => {
    expect(template).not.toContain(DISCARD_RECEIVER_NAME);
  });

  it('puts the owned-ban child before the generic page route, and the child does not continue', () => {
    const routes = childRoutes(template);
    const owned = routes.findIndex((block) => block.includes('alertname = "EdgeBanIssued"'));
    const generic = routes.findIndex((block) => block.includes('alertname =~ "^(TierTwoSafety'));
    expect(owned).toBeGreaterThan(-1);
    expect(generic).toBeGreaterThan(owned);
    expect(routes[owned]).not.toContain('continue');
    expect(walkRoutes(template, ownedBan('101'))).toHaveLength(1);
  });

  it('groups owned bans by scenario and notifies a new group within the bound', () => {
    const [step] = walkRoutes(template, ownedBan('101'));
    expect(step.groupBy).toEqual(['alertname', 'reason']);
    expect(step.groupWaitSeconds).toBeLessThanOrEqual(30);
    expect(step.groupIntervalSeconds).toBeLessThanOrEqual(OWNED_BAN_SECONDS_BOUND);
  });

  it('puts a second ban of the same scenario in the same group, notified within the bound', () => {
    const [first] = walkRoutes(template, ownedBan('101'));
    const [second] = walkRoutes(template, ownedBan('102'));
    expect(second.groupKey).toEqual(first.groupKey);
    expect(second.groupIntervalSeconds).toBeLessThanOrEqual(OWNED_BAN_SECONDS_BOUND);
  });

  it('puts a ban of another scenario in its own group', () => {
    const [first] = walkRoutes(template, ownedBan('101'));
    const [other] = walkRoutes(
      template,
      ownedBan('201', 'branchleft/ghost-admin-login-bruteforce')
    );
    expect(other.groupKey).not.toEqual(first.groupKey);
  });

  it('leaves tenant-scoped pages grouped on tenant at the root interval', () => {
    const [step] = walkRoutes(template, {
      alertname: 'TierTwoSafetyMatch',
      severity: 'page',
      tenant: 'acme',
    });
    expect(step.receiver).toBe(PAGE_RECEIVER_NAME);
    expect(step.groupBy).toEqual(['tenant']);
    expect(step.groupIntervalSeconds).toBe(3600);
  });
});

describe('who is paged for an edge ban while the classifier is not installed', () => {
  const template = renderAlertmanagerTemplate(PAGE_REGISTER, false);

  it('discards the staleness alert and pages no one for it', () => {
    expect(receiversReached(template, staleClassifier)).toEqual([DISCARD_RECEIVER_NAME]);
  });

  it('still pages the phone for a ban, through the fallback and the owned-ban child', () => {
    expect(receiversReached(template, ownedBan('101'))).toEqual([PAGE_RECEIVER_NAME]);
    expect(
      receiversReached(template, {
        alertname: 'EdgeBanIssued',
        severity: 'page',
        reason: 'crowdsecurity/http-probing',
      })
    ).toEqual([PAGE_RECEIVER_NAME]);
  });

  it('leaves an unowned ban and a tenant-scoped page as they are in the other mode', () => {
    const installed = renderAlertmanagerTemplate(PAGE_REGISTER, true);
    const tenant = { alertname: 'ReadersCannotRead', severity: 'page', tenant: 'acme' };
    for (const labels of [unownedBan, tenant]) {
      expect(walkRoutes(template, labels)).toEqual(walkRoutes(installed, labels));
    }
  });

  it('puts the discard route before the page routes', () => {
    const routes = childRoutes(template);
    const discard = routes.findIndex((block) =>
      block.includes(`receiver: ${DISCARD_RECEIVER_NAME}`)
    );
    const owned = routes.findIndex((block) => block.includes('alertname = "EdgeBanIssued"'));
    expect(discard).toBeGreaterThan(-1);
    expect(discard).toBeLessThan(owned);
    expect(routes[discard]).not.toContain('continue');
  });

  it('declares the discard receiver with no integration to send through', () => {
    const receivers = template.slice(template.indexOf('\nreceivers:\n'));
    const block = receivers
      .split('\n  - name: ')
      .find((part) => part.startsWith(`${DISCARD_RECEIVER_NAME}`));
    expect(block?.trim()).toBe(DISCARD_RECEIVER_NAME);
  });

  it('keeps the staleness alertname out of the generic page route', () => {
    const generic = childRoutes(template).find((block) =>
      block.includes('alertname =~ "^(TierTwo')
    );
    expect(generic).toContain('EdgeBanIssued');
    expect(generic).not.toContain('EdgeBanOwnerStale');
  });
});

describe('the classifier gate in the page register helpers', () => {
  it('holds only the staleness entry dormant and leaves the committed register alone', () => {
    const held = holdEdgeBanOwnerStale(PAGE_REGISTER);
    expect(held.filter((entry) => entry.dormant).map((entry) => entry.id)).toEqual([
      'appeal-latency-breach',
      'edge-ban-owner-stale',
      'stopped-demo-reaper',
    ]);
    expect(pageAlertNames(held)).not.toContain('EdgeBanOwnerStale');
    expect(pageAlertNames(held)).toContain('EdgeBanIssued');
    expect(pageAlertNames(PAGE_REGISTER)).toContain('EdgeBanOwnerStale');
  });

  it('renders the discard route only while a live entry names the staleness alert', () => {
    expect(renderEdgeBanOwnerStaleDiscardRoute(PAGE_REGISTER)).toContain(
      'alertname = "EdgeBanOwnerStale"'
    );
    expect(renderEdgeBanOwnerStaleDiscardRoute(holdEdgeBanOwnerStale(PAGE_REGISTER))).toBe('');
    expect(renderEdgeBanOwnerStaleDiscardRoute([])).toBe('');
  });

  it('declares a receiver that is only a name', () => {
    expect(renderDiscardReceiverBlock()).toBe(`  - name: ${DISCARD_RECEIVER_NAME}`);
  });
});
