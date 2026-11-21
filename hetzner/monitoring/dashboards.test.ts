import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  DASHBOARD_DIR,
  DASHBOARD_EXTERNAL_METRICS,
  DATASOURCE_FILE,
  PROVIDER_FILE,
  allPanels,
  dashboardExprs,
  extractRuleEmittedSeries,
  findPanelsOffDatasource,
  queriedByDashboards,
  readDashboards,
  type Dashboard,
} from './dashboards';
import {
  EXTERNAL_METRICS,
  emittedMetricsUnder,
  findUncoveredMetricNames,
  findUnemittedLabelKeys,
} from './metricCrosscheck';
import { renderAlertRules } from './render';

const ANSIBLE_ROLES = join(__dirname, '..', '..', 'ansible', 'roles');

/** The series the collectors this repo owns emit, with the label keys each writes. */
function collectorSeries(): Map<string, Set<string>> {
  const emitted = emittedMetricsUnder(__dirname);
  for (const [name, keys] of emittedMetricsUnder(ANSIBLE_ROLES)) emitted.set(name, keys);
  return emitted;
}

/** Every series a rule or a collector this repo can see emits. A rule's series
 * (`ALERTS`) carries the rule's own labels, so only a collector's label keys are checked. */
function knownSeries(): Map<string, Set<string>> {
  const known = collectorSeries();
  for (const name of extractRuleEmittedSeries(renderAlertRules())) known.set(name, new Set());
  return known;
}

const EXTERNAL: Readonly<Record<string, string>> = {
  ...EXTERNAL_METRICS,
  ...DASHBOARD_EXTERNAL_METRICS,
};

function dashboardWith(expr: string): Dashboard {
  return { uid: 'x', title: 'x', panels: [{ id: 1, title: 'p', targets: [{ expr }] }] };
}

describe('dashboardExprs', () => {
  it('reads every target of a panel, and the panels nested in a row', () => {
    const dashboard: Dashboard = {
      panels: [
        { targets: [{ expr: 'up' }, { expr: 'node_load1' }] },
        { type: 'row', panels: [{ targets: [{ expr: 'probe_success' }] }] },
      ],
    };
    expect(dashboardExprs(dashboard)).toEqual(['up', 'node_load1', 'probe_success']);
  });

  it('reads a label_values template variable as an expression, without its label argument', () => {
    const dashboard: Dashboard = {
      templating: { list: [{ query: 'label_values(node_load1{job="node"}, host)' }] },
    };
    expect(dashboardExprs(dashboard)).toEqual(['node_load1{job="node"}']);
  });

  it('skips a target with no expression', () => {
    expect(dashboardExprs({ panels: [{ targets: [{}] }, { targets: [{ expr: ' ' }] }] })).toEqual(
      []
    );
  });
});

describe('extractRuleEmittedSeries', () => {
  it('names ALERTS and ALERTS_FOR_STATE when the rules hold an alert', () => {
    expect(extractRuleEmittedSeries('rules:\n  - alert: Foo\n    expr: up == 0\n')).toEqual(
      new Set(['ALERTS', 'ALERTS_FOR_STATE'])
    );
  });

  it('names a recording rule, and nothing when the rules hold neither', () => {
    expect(extractRuleEmittedSeries('rules:\n  - record: job:up:sum\n    expr: sum(up)\n')).toEqual(
      new Set(['job:up:sum'])
    );
    expect(extractRuleEmittedSeries('groups: []\n')).toEqual(new Set());
  });
});

/**
 * The join this module exists for, shown red: a panel that queries a series no
 * rule or exporter emits is reported, and one that queries a real series is not.
 */
describe('a query naming a series nothing emits goes red', () => {
  const known = knownSeries();

  it('reports a made-up series', () => {
    const queried = queriedByDashboards(
      new Map([['x.json', dashboardWith('sum(rate(made_up_series_total{job="node"}[5m]))')]])
    );
    expect(findUncoveredMetricNames(queried, known, EXTERNAL)).toEqual(['made_up_series_total']);
  });

  it('reports a collector series renamed on the dashboard side only', () => {
    const queried = queriedByDashboards(
      new Map([['x.json', dashboardWith('snds_complaint_rate_renamed')]])
    );
    expect(findUncoveredMetricNames(queried, known, EXTERNAL)).toEqual([
      'snds_complaint_rate_renamed',
    ]);
  });

  it('passes a series an exporter, a collector and a rule each emit', () => {
    const queried = queriedByDashboards(
      new Map([
        [
          'x.json',
          dashboardWith(
            'up{job="node"} + snds_complaint_rate + count(ALERTS{alertstate="firing"}) + node_load1'
          ),
        ],
      ])
    );
    expect(findUncoveredMetricNames(queried, known, EXTERNAL)).toEqual([]);
  });

  it('reports a label key a locally owned collector never emits', () => {
    const queried = queriedByDashboards(
      new Map([['x.json', dashboardWith('snds_complaint_rate{nonexistent_label="a"}')]])
    );
    expect(findUnemittedLabelKeys(queried, collectorSeries())).toEqual([
      'snds_complaint_rate{nonexistent_label=...}',
    ]);
  });
});

describe('the committed dashboards', () => {
  const dashboards = readDashboards();
  const known = knownSeries();
  const queried = queriedByDashboards(dashboards);

  it('are the five the estate view needs', () => {
    expect([...dashboards.values()].map((d) => d.title).sort()).toEqual([
      'Backups',
      'Host health',
      'Mail queue',
      'Support access',
      'Tenant health',
    ]);
  });

  it('each have a unique uid and a title, and run at least one query', () => {
    const uids = [...dashboards.values()].map((d) => d.uid);
    expect(new Set(uids).size).toBe(uids.length);
    for (const [file, dashboard] of dashboards) {
      expect(dashboard.uid, file).toMatch(/^branchleft-[a-z-]+$/);
      expect(dashboard.title, file).toBeTruthy();
      expect(dashboardExprs(dashboard).length, file).toBeGreaterThan(0);
    }
  });

  it('give every panel an id that is unique within its dashboard and a title', () => {
    for (const [file, dashboard] of dashboards) {
      const panels = allPanels(dashboard);
      const ids = panels.map((p) => p.id);
      expect(new Set(ids).size, file).toBe(ids.length);
      for (const panel of panels) expect(panel.title, file).toBeTruthy();
    }
  });

  it('query only series a rule or an exporter emits, or that an external list names an owner for', () => {
    expect(queried.size).toBeGreaterThan(0);
    expect(findUncoveredMetricNames(queried, known, EXTERNAL)).toEqual([]);
  });

  it('never select on a label key a locally owned collector does not emit for that series', () => {
    expect(findUnemittedLabelKeys(queried, collectorSeries())).toEqual([]);
  });

  it('never list a dashboard-external series that a local collector or the alert external list already covers', () => {
    const shadowed = Object.keys(DASHBOARD_EXTERNAL_METRICS).filter(
      (name) => known.has(name) || name in EXTERNAL_METRICS
    );
    expect(shadowed).toEqual([]);
  });

  it('name the provisioned datasource, by uid, on every panel and target', () => {
    const uid = /^\s*uid:\s*(\S+)\s*$/m.exec(readFileSync(DATASOURCE_FILE, 'utf8'))?.[1];
    expect(uid).toBe('prometheus');
    expect(findPanelsOffDatasource(dashboards, uid as string)).toEqual([]);
  });
});

describe('the dashboards provider', () => {
  const provider = readFileSync(PROVIDER_FILE, 'utf8');

  it('points at the container path of the directory the dashboards are committed in', () => {
    const path = /^\s*path:\s*(\S+)\s*$/m.exec(provider)?.[1];
    const compose = readFileSync(join(__dirname, 'stack', 'compose.yml'), 'utf8');
    // The mount is ./grafana/provisioning -> /etc/grafana/provisioning.
    expect(compose).toContain('./grafana/provisioning:/etc/grafana/provisioning:ro');
    expect(path).toBe('/etc/grafana/provisioning/dashboard-json');
    expect(existsSync(DASHBOARD_DIR)).toBe(true);
    expect(DASHBOARD_DIR.endsWith('/grafana/provisioning/dashboard-json')).toBe(true);
  });

  it('makes the files the one copy: not editable or deletable from the UI', () => {
    expect(provider).toMatch(/^\s*allowUiUpdates:\s*false\s*$/m);
    expect(provider).toMatch(/^\s*disableDeletion:\s*true\s*$/m);
  });
});
