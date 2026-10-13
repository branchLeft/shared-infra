/**
 * The public status page's probe-to-incident rule. Pure: a probe result goes
 * in and an incident transition comes out. Incidents open and close from
 * probe state only, never from a person or an agent. Nothing here touches a
 * host; the rule is rendered into the probe runner's config by a later change.
 */

/** A probe reading: `at` is whole seconds since the epoch, `ok` is whether the target answered healthy. */
export interface ProbeResult {
  at: number;
  ok: boolean;
}

export type IncidentState = { open: false } | { open: true; openedAt: number };

export type IncidentEvent =
  | { kind: 'none' }
  | { kind: 'opened'; openedAt: number }
  | { kind: 'resolved'; recoveredAt: string };

export interface StatusComponent {
  name: string;
  probeUrl: string;
}

/** The component that exercises the rule end to end; it is never a public service. */
export const STATUS_TEST_COMPONENT: StatusComponent = {
  name: 'TEST',
  probeUrl: 'https://status-test.invalid/',
};

export const CLOSED: IncidentState = { open: false };

/** UTC, second precision, `YYYY-MM-DDTHH:MM:SSZ`, for a whole-second epoch value. */
export function utcTimestamp(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toISOString().replace('.000Z', 'Z');
}

/** One probe result applied to the incident state: a failure opens, a recovery resolves. */
export function applyProbe(
  state: IncidentState,
  probe: ProbeResult
): { state: IncidentState; event: IncidentEvent } {
  if (!state.open && !probe.ok) {
    return {
      state: { open: true, openedAt: probe.at },
      event: { kind: 'opened', openedAt: probe.at },
    };
  }
  if (state.open && probe.ok) {
    return {
      state: CLOSED,
      event: { kind: 'resolved', recoveredAt: utcTimestamp(probe.at) },
    };
  }
  return { state, event: { kind: 'none' } };
}

/** Drives the rule over an ordered probe history and returns each event that changed the page. */
export function replayProbes(probes: readonly ProbeResult[]): IncidentEvent[] {
  let state: IncidentState = CLOSED;
  const events: IncidentEvent[] = [];
  for (const probe of probes) {
    const next = applyProbe(state, probe);
    state = next.state;
    if (next.event.kind !== 'none') events.push(next.event);
  }
  return events;
}
