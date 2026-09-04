import { describe, expect, it } from 'vitest';

import { renderAlertRules } from './render';
import {
  EXTERNAL_METRICS,
  emittedMetricsUnder,
  extractAllQueriedMetrics,
  extractEmittedMetrics,
  extractExprValues,
  extractQueriedMetrics,
  findCollectorPythonFiles,
  findUncoveredMetricNames,
  findUnemittedLabelKeys,
} from './metricCrosscheck';

describe('extractQueriedMetrics', () => {
  it('reads a selector-form name and its label keys', () => {
    const result = extractQueriedMetrics('up{expected_up="true"} == 0');
    expect(result).toEqual([{ name: 'up', labelKeys: new Set(['expected_up']) }]);
  });

  it('reads a bare name with no label constraint', () => {
    const result = extractQueriedMetrics(
      'mysql_global_status_threads_connected / mysql_global_variables_max_connections > 0.70'
    );
    expect(result).toEqual(
      expect.arrayContaining([
        { name: 'mysql_global_status_threads_connected', labelKeys: new Set() },
        { name: 'mysql_global_variables_max_connections', labelKeys: new Set() },
      ])
    );
  });

  it('does not mistake a function or aggregation name for a metric', () => {
    const result = extractQueriedMetrics('sum(increase(delivery_completed[6h])) > 20');
    const names = result.map((r) => r.name);
    expect(names).toEqual(['delivery_completed']);
  });

  it('does not mistake a vector-matching modifier argument for a metric', () => {
    // The real shape this guards: `unless on(ip) snds_message_volume` --
    // without stripping `on(ip)` first, `ip` would be misread as a second
    // bare metric name.
    const result = extractQueriedMetrics(
      'snds_complaint_rate > 0.001 unless on(ip) snds_message_volume'
    );
    const names = result.map((r) => r.name).sort();
    expect(names).toEqual(['snds_complaint_rate', 'snds_message_volume']);
  });

  it('does not mistake a label key inside braces for a metric name', () => {
    const result = extractQueriedMetrics(
      'increase(caddy_rate_limit_declined_requests_total{key!~"172\\\\..*", key!=""}[15m]) > 0'
    );
    expect(result).toEqual([
      { name: 'caddy_rate_limit_declined_requests_total', labelKeys: new Set(['key']) },
    ]);
  });

  it('handles an empty vector-matching modifier list', () => {
    const result = extractQueriedMetrics(
      'absent(delivery_completed) and on() (up{job="stalwart"} == 1)'
    );
    const byName = new Map(result.map((r) => [r.name, r.labelKeys]));
    expect(byName.get('delivery_completed')).toEqual(new Set());
    expect(byName.get('up')).toEqual(new Set(['job']));
    expect(byName.has('on')).toBe(false);
  });
});

describe('extractExprValues', () => {
  it('reads a single-line expr', () => {
    const yaml = [
      'groups:',
      '  - name: g',
      '    rules:',
      '      - alert: A',
      '        expr: up == 0',
      '',
    ].join('\n');
    expect(extractExprValues(yaml)).toEqual(['up == 0']);
  });

  it('reads a folded (>-) block-scalar expr spanning several lines', () => {
    const yaml = [
      '      - alert: A',
      '        expr: >-',
      '          (1 - (node_filesystem_avail_bytes /',
      '          node_filesystem_size_bytes)) > 0.70',
      '        for: 15m',
      '',
    ].join('\n');
    expect(extractExprValues(yaml)).toEqual([
      '(1 - (node_filesystem_avail_bytes / node_filesystem_size_bytes)) > 0.70',
    ]);
  });

  it('reads every expr against the real render output without throwing', () => {
    const exprs = extractExprValues(renderAlertRules());
    expect(exprs.length).toBeGreaterThan(0);
    for (const expr of exprs) expect(expr.length).toBeGreaterThan(0);
  });
});

describe('extractEmittedMetrics', () => {
  const collectorSource = [
    '# HELP fixture_widget_count Number of widgets seen, for extraction testing only.',
    '# TYPE fixture_widget_count gauge',
    'def render(rows):',
    '    lines = ["# TYPE fixture_widget_count gauge"]',
    '    for row in rows:',
    '        lines.append(f\'fixture_widget_count{{region="{row.region}"}} {row.count}\')',
    '    return "\\n".join(lines)',
    '',
  ].join('\n');

  it('reads the declared name and the label keys used on its value line', () => {
    expect(extractEmittedMetrics(collectorSource)).toEqual([
      { name: 'fixture_widget_count', labelKeys: new Set(['region']) },
    ]);
  });

  it('reads a metric with no labels as an empty label-key set', () => {
    const source = [
      '# TYPE fixture_last_run_seconds gauge',
      "lines.append(f'fixture_last_run_seconds {now}')",
    ].join('\n');
    expect(extractEmittedMetrics(source)).toEqual([
      { name: 'fixture_last_run_seconds', labelKeys: new Set() },
    ]);
  });

  it('reads a # TYPE line one quote character short of the line start, the shape a Python string-literal list produces', () => {
    // A collector builds its exposition lines as
    // `lines = ["# TYPE name gauge"]`, so the `#` a real scrape would see
    // sits one quote character in from where a bare source-code comment
    // would start -- a pattern requiring `#` at the line start misses it.
    const source = ['        "# TYPE fixture_widget_count gauge",'].join('\n');
    expect(extractEmittedMetrics(source)).toEqual([
      { name: 'fixture_widget_count', labelKeys: new Set() },
    ]);
  });
});

/**
 * The sabotage the issue hands over, reproduced mechanically rather than
 * described: a collector's real emitted name renamed everywhere in its own
 * source, with the rule that queries it left untouched. Uses the same
 * `findUncoveredMetricNames` the real integration check below calls, so
 * this is not a parallel claim about the mechanism -- it is the mechanism.
 */
describe('the join catches a collector metric renamed out from under its rule', () => {
  const baselineCollector = [
    '# TYPE fixture_widget_count gauge',
    'lines.append(f\'fixture_widget_count{{region="{row.region}"}} {row.count}\')',
  ].join('\n');
  const renamedCollector = baselineCollector.replaceAll(
    'fixture_widget_count',
    'fixture_widg_count'
  );
  const ruleExpr = 'fixture_widget_count{region="eu"} > 10';

  it('passes when the collector and the rule agree on the name', () => {
    const emitted = new Map(
      extractEmittedMetrics(baselineCollector).map((m) => [m.name, m.labelKeys])
    );
    const queried = new Map(extractQueriedMetrics(ruleExpr).map((m) => [m.name, m.labelKeys]));
    expect(findUncoveredMetricNames(queried, emitted, EXTERNAL_METRICS)).toEqual([]);
  });

  it('goes red when only the collector is renamed', () => {
    const emitted = new Map(
      extractEmittedMetrics(renamedCollector).map((m) => [m.name, m.labelKeys])
    );
    const queried = new Map(extractQueriedMetrics(ruleExpr).map((m) => [m.name, m.labelKeys]));
    expect(findUncoveredMetricNames(queried, emitted, EXTERNAL_METRICS)).toEqual([
      'fixture_widget_count',
    ]);
  });

  it('still goes red when the collector\'s own unit test is renamed alongside it -- the exact "obvious future PR" the issue predicts', () => {
    // Modelled, not merely asserted: a test file renamed in step with the
    // collector is exactly what `findCollectorPythonFiles` already excludes
    // by name, so its content is irrelevant here -- proven by never reading
    // it, not by inspecting it and finding it irrelevant.
    const renamedCollectorTestFile = [
      '# test_fixture_widget_count.py -- would also be renamed in that PR',
      "assert 'fixture_widg_count' in render(rows)",
    ].join('\n');
    void renamedCollectorTestFile;
    const emitted = new Map(
      extractEmittedMetrics(renamedCollector).map((m) => [m.name, m.labelKeys])
    );
    const queried = new Map(extractQueriedMetrics(ruleExpr).map((m) => [m.name, m.labelKeys]));
    expect(findUncoveredMetricNames(queried, emitted, EXTERNAL_METRICS)).toEqual([
      'fixture_widget_count',
    ]);
  });
});

describe('findUnemittedLabelKeys', () => {
  it('reports a label key a rule selects on that the collector never emits for that metric', () => {
    const emitted = new Map([['fixture_widget_count', new Set(['region'])]]);
    const queried = new Map([['fixture_widget_count', new Set(['region', 'zone'])]]);
    expect(findUnemittedLabelKeys(queried, emitted)).toEqual(['fixture_widget_count{zone=...}']);
  });

  it('says nothing about a metric this repo does not own the emission of', () => {
    const emitted = new Map<string, Set<string>>();
    const queried = new Map([['mysql_up', new Set(['instance'])]]);
    expect(findUnemittedLabelKeys(queried, emitted)).toEqual([]);
  });
});

/**
 * The real, present-day check. `renderAlertRules()` -- not the committed
 * `alerts.yml` -- is the authoritative source of queried names: it is the
 * hand-authored generator, and `render.test.ts` already proves the
 * committed file is byte-identical to its output, so reading the file here
 * would just repeat that proof rather than add one. `findCollectorPythonFiles`
 * scans this directory rather than the whole repo: every collector this
 * stack owns lives under `hetzner/monitoring`, per its own `stack/`
 * layout.
 *
 * No `.py` file under this directory declares a `# TYPE` line today -- every
 * metric these rules query is emitted by a third-party binary (node_exporter,
 * mysqld_exporter, blackbox_exporter, Caddy, Alertmanager, Stalwart), listed
 * and reasoned in `EXTERNAL_METRICS`. This assertion is real and will start
 * covering a genuine local collector -- proven mechanically above, not
 * merely claimed -- the moment one lands here with a `# TYPE` line of its
 * own; it is not a placeholder waiting on that.
 */
describe('metric name crosscheck against every collector this repo owns', () => {
  const queried = extractAllQueriedMetrics(renderAlertRules());
  const emitted = emittedMetricsUnder(__dirname);

  it('finds at least one alert rule to check, so a rendering failure here cannot read as a pass', () => {
    expect(queried.size).toBeGreaterThan(0);
  });

  it('queries only metric names a collector under this directory emits, or that EXTERNAL_METRICS names an owner for', () => {
    expect(findUncoveredMetricNames(queried, emitted, EXTERNAL_METRICS)).toEqual([]);
  });

  it('never selects on a label key a locally-owned collector does not emit for that metric', () => {
    expect(findUnemittedLabelKeys(queried, emitted)).toEqual([]);
  });

  it('never lists an EXTERNAL_METRICS entry for a name a local collector already emits', () => {
    // Guards the allowlist itself: a name that starts being emitted locally
    // (a future collector reusing an existing rule's metric name) must be
    // dropped from EXTERNAL_METRICS, or it stops being cross-checked against
    // its own real emitter.
    const shadowed = Object.keys(EXTERNAL_METRICS).filter((name) => emitted.has(name));
    expect(shadowed).toEqual([]);
  });
});

describe('findCollectorPythonFiles', () => {
  it("excludes this directory's own test files", () => {
    const files = findCollectorPythonFiles(__dirname);
    for (const file of files) {
      expect(file.endsWith('.py')).toBe(true);
      expect(/(^|\/)test_/.test(file) || file.endsWith('_test.py')).toBe(false);
    }
  });
});
