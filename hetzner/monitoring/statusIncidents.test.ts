import { describe, expect, it } from 'vitest';

import {
  applyProbe,
  CLOSED,
  replayProbes,
  STATUS_TEST_COMPONENT,
  utcTimestamp,
} from './statusIncidents';

/** Seconds between probes in these fixtures; a failure must open within this plus one minute. */
const INTERVAL = 60;
const T0 = Date.parse('2026-10-12T05:00:00Z') / 1000;

describe('the probe-to-incident rule', () => {
  it('opens an incident on the first failed probe, not after a second one', () => {
    const events = replayProbes([
      { at: T0, ok: true },
      { at: T0 + INTERVAL, ok: false },
    ]);
    expect(events).toEqual([{ kind: 'opened', openedAt: T0 + INTERVAL }]);
  });

  it('resolves that incident on recovery, stamped with the recovery time in UTC', () => {
    const events = replayProbes([
      { at: T0, ok: false },
      { at: T0 + INTERVAL, ok: false },
      { at: T0 + 2 * INTERVAL, ok: true },
    ]);
    expect(events).toEqual([
      { kind: 'opened', openedAt: T0 },
      { kind: 'resolved', recoveredAt: '2026-10-12T05:02:00Z' },
    ]);
  });

  it('keeps one incident open across repeated failures, with no second open event', () => {
    const events = replayProbes([
      { at: T0, ok: false },
      { at: T0 + INTERVAL, ok: false },
      { at: T0 + 2 * INTERVAL, ok: false },
    ]);
    expect(events.filter((event) => event.kind === 'opened')).toHaveLength(1);
    expect(events.filter((event) => event.kind === 'resolved')).toHaveLength(0);
  });

  it('control: a probe pointed at a healthy target never opens an incident', () => {
    const healthy = Array.from({ length: 5 }, (_, i) => ({ at: T0 + i * INTERVAL, ok: true }));
    expect(replayProbes(healthy)).toEqual([]);
  });

  it('a recovery with no open incident changes nothing', () => {
    const next = applyProbe(CLOSED, { at: T0, ok: true });
    expect(next.state).toEqual(CLOSED);
    expect(next.event).toEqual({ kind: 'none' });
  });
});

describe('the recovery timestamp', () => {
  it('is UTC to the second, with no milliseconds', () => {
    expect(utcTimestamp(T0)).toBe('2026-10-12T05:00:00Z');
  });
});

describe('the TEST component', () => {
  it('is named TEST and probes a reserved .invalid name, never a public hostname', () => {
    expect(STATUS_TEST_COMPONENT.name).toBe('TEST');
    expect(new URL(STATUS_TEST_COMPONENT.probeUrl).hostname.endsWith('.invalid')).toBe(true);
  });
});
