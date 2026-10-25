/**
 * The public status page's staleness rule. Pure: the probe runner's last-report
 * time, the clock and the last probe reading go in, and one component's shown
 * state comes out. A page that shows green while its own checker has stopped
 * is wrong, so a component is UP or DOWN only while its runner's report is
 * fresh; otherwise the state is UNKNOWN. Nothing here touches a host.
 */

/** The state a component shows on the page. UNKNOWN means "no current data", never "healthy". */
export type ComponentState = 'UP' | 'DOWN' | 'UNKNOWN';

/**
 * The shown state of one component.
 *
 * `lastReportAt` is whole seconds since the epoch of the runner's last report,
 * or `null` if it has never reported. `now` is whole seconds since the epoch.
 * `maxAgeSeconds` is the oldest report still counted as fresh; a report exactly
 * that old is fresh, one second older is not. `lastProbeOk` is the reading in
 * that last report and is shown only while the report is fresh.
 *
 * A report stamped after `now` is UNKNOWN: its age is negative, so trusting it
 * would keep a stopped runner green indefinitely once its clock runs ahead.
 */
export function componentStatus(
  lastReportAt: number | null,
  now: number,
  maxAgeSeconds: number,
  lastProbeOk: boolean
): ComponentState {
  if (!(maxAgeSeconds > 0)) {
    throw new RangeError(`maxAgeSeconds must be positive, got ${maxAgeSeconds}`);
  }
  if (lastReportAt === null) return 'UNKNOWN';
  const age = now - lastReportAt;
  if (age < 0 || age > maxAgeSeconds) return 'UNKNOWN';
  return lastProbeOk ? 'UP' : 'DOWN';
}
