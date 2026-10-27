import { describe, expect, it } from 'vitest';

import { componentStatus } from './statusStaleness';

/** Seconds. An example threshold for these fixtures; the configured value is set by the runner wiring. */
const MAX_AGE = 120;
const NOW = Date.parse('2026-10-25T12:00:00Z') / 1000;

describe('the status page staleness rule', () => {
  it('shows the probe result when the runner reported recently: healthy is UP', () => {
    expect(componentStatus(NOW - 60, NOW, MAX_AGE, true)).toBe('UP');
  });

  it('shows the probe result when the runner reported recently: unhealthy is DOWN', () => {
    expect(componentStatus(NOW - 60, NOW, MAX_AGE, false)).toBe('DOWN');
  });

  it('is UNKNOWN, never UP, when the last report is older than the threshold', () => {
    expect(componentStatus(NOW - MAX_AGE - 1, NOW, MAX_AGE, true)).toBe('UNKNOWN');
  });

  it('is UNKNOWN, never DOWN, when the last report is older than the threshold', () => {
    expect(componentStatus(NOW - 3600, NOW, MAX_AGE, false)).toBe('UNKNOWN');
  });

  it('is UNKNOWN when the runner has never reported', () => {
    expect(componentStatus(null, NOW, MAX_AGE, true)).toBe('UNKNOWN');
    expect(componentStatus(null, NOW, MAX_AGE, false)).toBe('UNKNOWN');
  });

  it('is still fresh at exactly the threshold, and UNKNOWN one second past it', () => {
    expect(componentStatus(NOW - MAX_AGE, NOW, MAX_AGE, true)).toBe('UP');
    expect(componentStatus(NOW - MAX_AGE - 1, NOW, MAX_AGE, true)).toBe('UNKNOWN');
  });

  it('is UNKNOWN for a report stamped in the future, since its freshness cannot be trusted', () => {
    expect(componentStatus(NOW + 1, NOW, MAX_AGE, true)).toBe('UNKNOWN');
    expect(componentStatus(NOW + 1, NOW, MAX_AGE, false)).toBe('UNKNOWN');
  });

  it('refuses a non-positive threshold rather than reading every report as fresh', () => {
    expect(() => componentStatus(NOW, NOW, 0, true)).toThrow(RangeError);
    expect(() => componentStatus(NOW, NOW, -5, true)).toThrow(RangeError);
  });

  it.each([
    ['NaN', Number.NaN],
    ['undefined', undefined],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['-Infinity', Number.NEGATIVE_INFINITY],
  ])('is UNKNOWN, never UP or DOWN, when lastReportAt is %s', (_label, value) => {
    const lastReportAt = value as unknown as number;
    expect(componentStatus(lastReportAt, NOW, MAX_AGE, true)).toBe('UNKNOWN');
    expect(componentStatus(lastReportAt, NOW, MAX_AGE, false)).toBe('UNKNOWN');
  });

  it.each([
    ['NaN', Number.NaN],
    ['undefined', undefined],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['-Infinity', Number.NEGATIVE_INFINITY],
  ])('is UNKNOWN, never UP or DOWN, when now is %s', (_label, value) => {
    const now = value as unknown as number;
    expect(componentStatus(NOW - 60, now, MAX_AGE, true)).toBe('UNKNOWN');
    expect(componentStatus(NOW - 60, now, MAX_AGE, false)).toBe('UNKNOWN');
  });

  it.each([
    ['NaN', Number.NaN],
    ['undefined', undefined],
    ['Infinity', Number.POSITIVE_INFINITY],
  ])('refuses a maxAgeSeconds of %s with a RangeError, not a verdict', (_label, value) => {
    const maxAgeSeconds = value as unknown as number;
    expect(() => componentStatus(NOW - 60, NOW, maxAgeSeconds, true)).toThrow(RangeError);
    expect(() => componentStatus(NOW - 60, NOW, maxAgeSeconds, false)).toThrow(RangeError);
  });

  it('gives the probe state for a finite, positive, valid input set', () => {
    expect(componentStatus(NOW - 60, NOW, MAX_AGE, true)).toBe('UP');
    expect(componentStatus(NOW - 60, NOW, MAX_AGE, false)).toBe('DOWN');
  });
});
