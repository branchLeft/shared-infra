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
 * The shown state of one component: UP or DOWN from `lastProbeOk` while the
 * runner's report is fresh, else UNKNOWN. `lastReportAt` (null if never
 * reported) and `now` are whole epoch seconds. A report exactly `maxAgeSeconds`
 * old is fresh; one older, or stamped after `now` (negative age, which would
 * keep a stopped runner green once its clock runs ahead), is UNKNOWN.
 */
export function componentStatus(
  lastReportAt: number | null,
  now: number,
  maxAgeSeconds: number,
  lastProbeOk: boolean
): ComponentState {
  if (!Number.isFinite(maxAgeSeconds) || !(maxAgeSeconds > 0)) {
    throw new RangeError(`maxAgeSeconds must be finite and positive, got ${maxAgeSeconds}`);
  }
  if (lastReportAt === null) return 'UNKNOWN';
  // Number.isFinite, not the stale comparison below: NaN fails every comparison,
  // so a NaN timestamp would otherwise read as fresh.
  if (!Number.isFinite(lastReportAt) || !Number.isFinite(now)) return 'UNKNOWN';
  const age = now - lastReportAt;
  if (age < 0 || age > maxAgeSeconds) return 'UNKNOWN';
  return lastProbeOk ? 'UP' : 'DOWN';
}
