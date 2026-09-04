import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Cross-checks the metric names (and, where derivable, the label keys) an
 * alert rule expression queries against the metric names a collector this
 * repo owns actually emits.
 *
 * Why this exists, and what it does not replace: `render.test.ts` proves
 * `alerts.yml` matches what `render.ts` generates -- self-consistency
 * between a generator and its own output, never a check against the thing
 * that actually produces a metric's samples. `alert_rules_test.yml` proves
 * an expression evaluates the way a human expects against hand-typed
 * synthetic series -- it never reads a collector either. A rule and its
 * collector can each be internally consistent this way and still disagree
 * on a name, and that failure is silent in production: a broken selector
 * returns no results, which reads exactly like "nothing is wrong".
 *
 * A collector, for this module's purposes, is any non-test `.py` file
 * beneath a given root that declares at least one Prometheus text-exposition
 * `# TYPE <name> <type>` line -- the format's own metric-name declaration,
 * never a name this module invents. A queried name with no such declaration
 * is assumed to belong to a third-party binary this repo does not author;
 * `EXTERNAL_METRICS` is the reasoned, per-entry account of which one.
 *
 * Known limitations, disclosed rather than silently accepted:
 *
 * - **Label-value matching is out of scope.** `findUnemittedLabelKeys` only
 *   ever checks that a selected label KEY is one the collector emits for
 *   that metric, never that the VALUES on either side can actually meet --
 *   a selector whose pattern never matches a real emitted value (the
 *   `remote_ip`/IPv6 shape) is a live failure mode this cannot see, since
 *   values are only known at scrape time.
 * - **No control-flow or reachability analysis.** A `# TYPE` line is read
 *   as text, not as a statement proven to execute. `extractEmittedMetrics`
 *   strips triple-quoted (`"""..."""`/`'''...'''`) spans before scanning,
 *   specifically because this codebase's docstrings are exclusively
 *   triple-quoted (see `collect_snds_metrics.py`, `configure_stalwart.py`)
 *   and a documentation example quoting `# TYPE foo gauge` must not count
 *   as this file emitting `foo`. That removes the demonstrated failure
 *   shape, not every one: a bare, non-string Python `#` comment that
 *   happens to read exactly `# TYPE name gauge` on its own line, or a real
 *   single-quoted exposition string sitting in a genuinely dead branch
 *   (behind an `if False:`, or otherwise never reached), still reads as
 *   emitted. Closing that fully needs a real Python parse (AST/tokenize)
 *   this module does not perform. Prefer deleting dead exposition code
 *   over leaving it -- this check cannot tell the difference.
 * - **The allowlist is reviewed, not verified.** `EXTERNAL_METRICS` is
 *   reasoned per entry so it is not a wholesale copy of `alerts.yml`'s
 *   query list, and one test asserts no entry in it names a metric a local
 *   collector already emits -- but nothing stops a plausible-sounding
 *   reason being written for a metric that is, in fact, local. It narrows
 *   the risk; it does not eliminate it.
 */

export interface NamedSeries {
  name: string;
  labelKeys: Set<string>;
}

/** PromQL keywords that can stand alone (never followed by `(`) and so
 * would otherwise be misread as a bare metric name. Function and
 * aggregation names are excluded structurally instead -- see
 * `extractQueriedMetrics` -- because they are always call syntax. */
const PROMQL_BARE_KEYWORDS = new Set(['and', 'or', 'unless', 'bool', 'offset']);

/** Vector-matching modifiers whose parenthesised argument names labels, not
 * a metric or a value -- `on(ip)`, `by(job)`, `without(instance)`,
 * `ignoring(x)`, `group_left(x)`, `group_right(x)`. The whole span is
 * stripped before metric-name extraction so its arguments are never misread
 * as bare metric names. */
const VECTOR_MATCH_MODIFIER = /\b(?:on|ignoring|by|without|group_left|group_right)\s*\([^)]*\)/g;

function stripExprNoise(expr: string): string {
  return expr
    .replace(/"(?:[^"\\]|\\.)*"/g, '') // label-matcher / regex string literals
    .replace(/\[[^\]]*\]/g, '') // range-vector durations, e.g. [15m]
    .replace(VECTOR_MATCH_MODIFIER, ' ');
}

/**
 * Parses one PromQL expression into the set of metric names it queries and,
 * per name, the label keys a selector constrained it by. A name with no
 * `{...}` of its own still appears, with an empty label-key set.
 */
export function extractQueriedMetrics(expr: string): NamedSeries[] {
  let text = stripExprNoise(expr);
  const byName = new Map<string, Set<string>>();

  // Selector form: name{labels}. Captured first and collapsed to the bare
  // name so the pass below never has to special-case braces.
  text = text.replace(
    /([a-zA-Z_:][a-zA-Z0-9_:]*)\{([^}]*)\}/g,
    (_full, name: string, labels: string) => {
      const keys = byName.get(name) ?? new Set<string>();
      for (const keyMatch of labels.matchAll(/([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:=~|!~|=|!=)/g)) {
        keys.add(keyMatch[1]);
      }
      byName.set(name, keys);
      return ` ${name} `;
    }
  );

  // Bare form: any remaining identifier that is not a function/aggregation
  // call (always immediately followed by `(`) and not a PromQL keyword is a
  // metric name with no label constraint of its own.
  for (const match of text.matchAll(/[a-zA-Z_:][a-zA-Z0-9_:]*/g)) {
    const name = match[0];
    const isCall = text[match.index + name.length] === '(';
    if (isCall || PROMQL_BARE_KEYWORDS.has(name)) continue;
    if (!byName.has(name)) byName.set(name, new Set());
  }

  return [...byName.entries()].map(([name, labelKeys]) => ({ name, labelKeys }));
}

/**
 * Extracts every `expr:` value from a rendered alert-rules YAML document
 * (i.e. `renderAlertRules()`'s own output), including a folded (`>-`) or
 * literal (`|-`) block scalar spanning several lines. A small hand-rolled
 * reader rather than a YAML library: this project has never taken a YAML
 * dependency, and the shape read here is exactly the shape `renderAlertRules`
 * itself produces -- the same discipline `render.test.ts` already relies on
 * by comparing that function's output to a committed file with no parser in
 * between.
 */
export function extractExprValues(rulesYamlText: string): string[] {
  const lines = rulesYamlText.split('\n');
  const exprs: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    const match = /^(\s*)expr:\s*(.*)$/.exec(lines[i]);
    if (!match) continue;
    const indent = match[1].length;
    const rest = match[2].trim();
    if (rest === '>-' || rest === '>' || rest === '|-' || rest === '|') {
      const parts: string[] = [];
      let j = i + 1;
      while (j < lines.length) {
        const next = lines[j];
        if (next.trim() === '') break;
        const nextIndent = next.length - next.trimStart().length;
        if (nextIndent <= indent) break;
        parts.push(next.trim());
        j++;
      }
      exprs.push(parts.join(' '));
    } else {
      exprs.push(rest);
    }
  }
  return exprs;
}

/**
 * The metric names (and, per name, the label keys used against them
 * anywhere) queried across every `expr:` in a rendered alert-rules document.
 */
export function extractAllQueriedMetrics(rulesYamlText: string): Map<string, Set<string>> {
  const result = new Map<string, Set<string>>();
  for (const expr of extractExprValues(rulesYamlText)) {
    for (const { name, labelKeys } of extractQueriedMetrics(expr)) {
      const keys = result.get(name) ?? new Set<string>();
      for (const key of labelKeys) keys.add(key);
      result.set(name, keys);
    }
  }
  return result;
}

// An optional leading quote: the `# TYPE` marker is not a Python comment in
// a collector like this -- it is exposition-format text the script writes,
// so in the source it sits inside a string literal (`"# TYPE name gauge"`),
// one quote character ahead of the `#` a real Prometheus scrape would see.
const TYPE_DECLARATION = /^\s*['"]?#\s*TYPE\s+([a-zA-Z_:][a-zA-Z0-9_:]*)\s+\S+/;

/** The label keys a collector's own source uses on a value-emitting line for
 * `name` -- matched on `name{{...}}`, the doubled-brace shape an f-string
 * literal produces for a real (single-braced, at scrape time) Prometheus
 * label list, with no space between the metric name and the opening brace,
 * matching the exposition format itself. A metric with no such line (no
 * labels of its own) yields an empty set, correctly. */
function labelKeysAdjacentTo(name: string, sourceText: string): Set<string> {
  const keys = new Set<string>();
  // Non-greedy up to the first literal `}}`, not a `[^}]*` character class:
  // a real label value routinely carries its own single-brace interpolation
  // (an f-string's `{row.region}`), and a class that excludes `}` entirely
  // would stop at that inner brace instead of the outer pair closing the
  // label list.
  const pattern = new RegExp(`${name}\\{\\{(.*?)\\}\\}`, 'g');
  for (const match of sourceText.matchAll(pattern)) {
    for (const keyMatch of match[1].matchAll(/([a-zA-Z_][a-zA-Z0-9_]*)\s*=/g)) {
      keys.add(keyMatch[1]);
    }
  }
  return keys;
}

/**
 * Removes every triple-quoted string span (`"""..."""` / `'''...'''`) before
 * `# TYPE` scanning. This codebase's docstrings are exclusively
 * triple-quoted -- a collector's real exposition text lives in
 * single-quoted string literals inside a list that gets joined and written
 * (see `render_prometheus_text` in `collect_snds_metrics.py`) -- so this
 * removes documentation examples without touching any real declaration. It
 * does not remove a single-quoted string sitting in genuinely dead code;
 * see this module's docstring for that residual limitation.
 */
function stripDocstrings(sourceText: string): string {
  return sourceText.replace(/"""[\s\S]*?"""|'''[\s\S]*?'''/g, '');
}

/**
 * The metric names a single collector script's source declares, each with
 * the label keys it emits that name under. Reads only `# TYPE` lines to
 * decide which names this file emits -- deliberately not the value-emitting
 * lines, so a rename that only touches the value line (and not its own
 * `# TYPE`/`# HELP` pair) is a different, already-invalid exposition
 * document, not something this function needs to special-case.
 */
export function extractEmittedMetrics(sourceText: string): NamedSeries[] {
  const withoutDocstrings = stripDocstrings(sourceText);
  const names = new Set<string>();
  for (const line of withoutDocstrings.split('\n')) {
    const match = TYPE_DECLARATION.exec(line);
    if (match) names.add(match[1]);
  }
  return [...names].map((name) => ({
    name,
    labelKeys: labelKeysAdjacentTo(name, withoutDocstrings),
  }));
}

/** Every non-test `.py` file beneath `rootDir` -- the convention this module
 * uses to mean "a collector this repo owns", never a specific filename. A
 * file is excluded as a test, not a collector, the same way
 * `.claude/delivery-paths.json`'s exclude list treats `test_*.py`: changing
 * one alters no exposition output. */
export function findCollectorPythonFiles(rootDir: string): string[] {
  const results: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
        continue;
      }
      if (!entry.name.endsWith('.py')) continue;
      if (entry.name.startsWith('test_') || entry.name.endsWith('_test.py')) continue;
      results.push(full);
    }
  };
  walk(rootDir);
  return results;
}

/** Every metric name and label-key set emitted by the non-test `.py` files
 * beneath `rootDir`. */
export function emittedMetricsUnder(rootDir: string): Map<string, Set<string>> {
  const result = new Map<string, Set<string>>();
  for (const file of findCollectorPythonFiles(rootDir)) {
    for (const { name, labelKeys } of extractEmittedMetrics(readFileSync(file, 'utf8'))) {
      const keys = result.get(name) ?? new Set<string>();
      for (const key of labelKeys) keys.add(key);
      result.set(name, keys);
    }
  }
  return result;
}

/**
 * Metric names this repo's alert rules query but does not own the source
 * of: each is written by a third-party binary, or built into Prometheus or
 * Alertmanager themselves, so a rename can only originate upstream, never in
 * a commit to this repo. Listed and reasoned individually -- copying
 * `alerts.yml`'s query list wholesale here would recreate exactly the
 * incidental, self-referential catch this module exists to replace; an
 * unrecognised name must be added with its own reason, never assumed.
 *
 * This list is reviewed, not verified: a plausible-sounding reason can still
 * be written for a metric that is, in fact, local. The one automated guard
 * is narrow -- a test asserts no entry here names a metric a local collector
 * already emits -- and does not by itself prove every reason given is true.
 */
export const EXTERNAL_METRICS: Readonly<Record<string, string>> = {
  up: 'built into Prometheus itself, for every scrape target',
  probe_success: 'blackbox_exporter',
  caddy_rate_limit_declined_requests_total: "Caddy's own rate-limit module",
  node_memory_MemAvailable_bytes: 'node_exporter',
  node_memory_MemTotal_bytes: 'node_exporter',
  node_filesystem_avail_bytes: 'node_exporter',
  node_filesystem_size_bytes: 'node_exporter',
  mysql_global_status_threads_connected: 'mysqld_exporter, on db1',
  mysql_global_variables_max_connections: 'mysqld_exporter, on db1',
  mysql_up: 'mysqld_exporter, on db1',
  delivery_dsn_perm_fail: "Stalwart's own Prometheus exporter, on mx1",
  delivery_rcpt_to_rejected: "Stalwart's own Prometheus exporter, on mx1",
  delivery_completed: "Stalwart's own Prometheus exporter, on mx1",
  alertmanager_notifications_failed_total: 'built into Alertmanager itself',
};

/**
 * The queried metric names with no emitter: neither a collector under the
 * scanned root nor a reasoned entry in `external`. Non-empty means an alert
 * rule queries a name that production will never see a sample for.
 */
export function findUncoveredMetricNames(
  queried: ReadonlyMap<string, ReadonlySet<string>>,
  emitted: ReadonlyMap<string, ReadonlySet<string>>,
  external: Readonly<Record<string, string>>
): string[] {
  return [...queried.keys()].filter((name) => !emitted.has(name) && !(name in external)).sort();
}

/**
 * For every queried metric this repo does own the emission of (i.e. present
 * in `emitted`), the label keys a rule selects on that the collector never
 * emits for that metric. A metric absent from `emitted` (third-party, or
 * already reported by `findUncoveredMetricNames`) is out of scope here --
 * this repo has no source to check a third-party exporter's label set
 * against. Deliberately name-only beyond that: a label whose emitted VALUES
 * never match a selector's pattern (the `remote_ip`/IPv6 shape) is a live
 * failure mode this cannot see, since values are only known at scrape time.
 */
export function findUnemittedLabelKeys(
  queried: ReadonlyMap<string, ReadonlySet<string>>,
  emitted: ReadonlyMap<string, ReadonlySet<string>>
): string[] {
  const mismatches: string[] = [];
  for (const [name, requestedKeys] of queried) {
    const emittedKeys = emitted.get(name);
    if (!emittedKeys) continue;
    for (const key of [...requestedKeys].sort()) {
      if (!emittedKeys.has(key)) mismatches.push(`${name}{${key}=...}`);
    }
  }
  return mismatches;
}
