import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

import { extractQueriedMetrics } from './metricCrosscheck';

/**
 * Reads the Grafana dashboards committed under
 * `stack/grafana/provisioning/dashboard-json` and names every query they run,
 * so `dashboards.test.ts` can hold each one to a series a rule or an exporter
 * really emits. See dashboards.md for the design and what it cannot see.
 */

/** The directory the dashboard files are committed in, beside the provider file. */
export const DASHBOARD_DIR = join(__dirname, 'stack', 'grafana', 'provisioning', 'dashboard-json');

/** The provider file that tells Grafana to load `DASHBOARD_DIR`. */
export const PROVIDER_FILE = join(
  __dirname,
  'stack',
  'grafana',
  'provisioning',
  'dashboards',
  'dashboards.yaml'
);

/** The provisioned datasource every panel must name. */
export const DATASOURCE_FILE = join(
  __dirname,
  'stack',
  'grafana',
  'provisioning',
  'datasources',
  'prometheus.yaml'
);

export interface DashboardPanel {
  id?: number;
  type?: string;
  title?: string;
  datasource?: { type?: string; uid?: string };
  targets?: { expr?: string; datasource?: { type?: string; uid?: string } }[];
  panels?: DashboardPanel[];
}

export interface Dashboard {
  uid?: string;
  title?: string;
  panels?: DashboardPanel[];
  templating?: { list?: { query?: unknown; definition?: string }[] };
}

/** Every dashboard file beneath `dir`, parsed, keyed by file name. */
export function readDashboards(dir: string = DASHBOARD_DIR): Map<string, Dashboard> {
  const result = new Map<string, Dashboard>();
  for (const entry of readdirSync(dir).sort()) {
    if (!entry.endsWith('.json')) continue;
    result.set(entry, JSON.parse(readFileSync(join(dir, entry), 'utf8')) as Dashboard);
  }
  return result;
}

/** Every panel of a dashboard, rows' nested panels included. */
export function allPanels(dashboard: Dashboard): DashboardPanel[] {
  const out: DashboardPanel[] = [];
  const walk = (panels: DashboardPanel[] | undefined): void => {
    for (const panel of panels ?? []) {
      out.push(panel);
      walk(panel.panels);
    }
  };
  walk(dashboard.panels);
  return out;
}

/** Every PromQL expression a dashboard runs: panel targets, and the query of
 * any template variable that is itself a `query_result(...)` or `label_values(...)`
 * call (its argument is read as an expression). */
export function dashboardExprs(dashboard: Dashboard): string[] {
  const exprs: string[] = [];
  for (const panel of allPanels(dashboard)) {
    for (const target of panel.targets ?? []) {
      if (typeof target.expr === 'string' && target.expr.trim() !== '') exprs.push(target.expr);
    }
  }
  for (const variable of dashboard.templating?.list ?? []) {
    const text = typeof variable.query === 'string' ? variable.query : variable.definition;
    const inner = /^(?:query_result|label_values)\((.*)\)$/s.exec((text ?? '').trim());
    if (inner) exprs.push(inner[1].replace(/,\s*[a-zA-Z_][a-zA-Z0-9_]*\s*$/, ''));
  }
  return exprs;
}

/** The metric names, and per name the label keys selected on, across every
 * query of every dashboard. */
export function queriedByDashboards(
  dashboards: ReadonlyMap<string, Dashboard>
): Map<string, Set<string>> {
  const result = new Map<string, Set<string>>();
  for (const dashboard of dashboards.values()) {
    for (const expr of dashboardExprs(dashboard)) {
      for (const { name, labelKeys } of extractQueriedMetrics(expr)) {
        const keys = result.get(name) ?? new Set<string>();
        for (const key of labelKeys) keys.add(key);
        result.set(name, keys);
      }
    }
  }
  return result;
}

/**
 * The series Prometheus itself writes for every alerting rule, and the names
 * of any recording rules, read from a rendered rules document: `ALERTS` and
 * `ALERTS_FOR_STATE` exist exactly when at least one `alert:` does, and a
 * `record:` rule's name is a series it writes.
 */
export function extractRuleEmittedSeries(rulesYamlText: string): Set<string> {
  const names = new Set<string>();
  const lines = rulesYamlText.split('\n');
  if (lines.some((line) => /^\s*-?\s*alert:\s*\S/.test(line))) {
    names.add('ALERTS');
    names.add('ALERTS_FOR_STATE');
  }
  for (const line of lines) {
    const match = /^\s*-?\s*record:\s*([a-zA-Z_:][a-zA-Z0-9_:]*)\s*$/.exec(line);
    if (match) names.add(match[1]);
  }
  return names;
}

/**
 * Metric names the dashboards query that no alert rule does, and that this
 * repo does not own the source of: each is written by a third-party exporter
 * or by Caddy, so a rename can only come from upstream. Reasoned per entry, and
 * never a copy of the alert rules' own `EXTERNAL_METRICS`, which the test adds.
 */
export const DASHBOARD_EXTERNAL_METRICS: Readonly<Record<string, string>> = {
  node_load1: 'node_exporter (loadavg collector, on by default)',
  node_boot_time_seconds: 'node_exporter (stat collector, on by default)',
  node_network_receive_bytes_total: 'node_exporter (netdev collector, on by default)',
  node_network_transmit_bytes_total: 'node_exporter (netdev collector, on by default)',
  container_memory_working_set_bytes: 'cAdvisor, on edge1 (the cadvisor scrape job)',
  probe_duration_seconds: 'blackbox_exporter, every probe module',
  probe_http_status_code: 'blackbox_exporter, http modules',
  caddy_http_request_duration_seconds_count:
    "Caddy's own metrics, on by the `metrics` option in the Caddyfile's servers block (the caddy scrape job)",
};

/** Every dashboard panel and target that does not name the provisioned
 * datasource `uid`, as `file: panel title`. */
export function findPanelsOffDatasource(
  dashboards: ReadonlyMap<string, Dashboard>,
  uid: string
): string[] {
  const off: string[] = [];
  for (const [file, dashboard] of dashboards) {
    for (const panel of allPanels(dashboard)) {
      if (panel.type === 'text' || panel.type === 'row') continue;
      const uids = [panel.datasource?.uid, ...(panel.targets ?? []).map((t) => t.datasource?.uid)];
      if (uids.some((found) => found !== uid)) off.push(`${file}: ${panel.title ?? panel.id}`);
    }
  }
  return off;
}
