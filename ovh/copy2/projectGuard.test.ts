import { describe, expect, it } from 'vitest';

import { assertProject, UNSET_MARKER } from './projectGuard';

const ALLOWED = '0123456789abcdef0123456789abcdef';
const OTHER = 'fedcba9876543210fedcba9876543210';

describe('assertProject', () => {
  it('returns the project id when the addressed project is the allowed one', () => {
    expect(assertProject(ALLOWED, ALLOWED)).toBe(ALLOWED);
  });

  it('refuses the unset marker the probe stack ships with', () => {
    expect(() => assertProject(UNSET_MARKER, ALLOWED)).toThrow(/allowedProjectId is not set/);
    expect(() => assertProject(UNSET_MARKER, UNSET_MARKER)).toThrow(/allowedProjectId is not set/);
  });

  it('refuses an allowed id that is not a 32-character lower-case hex string', () => {
    for (const bad of ['', '  ', 'abc', ALLOWED.toUpperCase(), `${ALLOWED}0`, 'project-name']) {
      expect(() => assertProject(bad, bad)).toThrow(/allowedProjectId/);
    }
  });

  it('refuses a different project, whatever the allowed id is', () => {
    expect(() => assertProject(ALLOWED, OTHER)).toThrow(/not the allowed project/);
  });

  it('refuses when the environment names no project at all', () => {
    expect(() => assertProject(ALLOWED, undefined)).toThrow(/OVH_CLOUD_PROJECT_SERVICE/);
    expect(() => assertProject(ALLOWED, '')).toThrow(/OVH_CLOUD_PROJECT_SERVICE/);
  });

  it('matches exactly: neither a prefix, a suffix nor extra whitespace passes', () => {
    expect(() => assertProject(ALLOWED, ALLOWED.slice(0, 31))).toThrow(/not the allowed project/);
    expect(() => assertProject(ALLOWED, ` ${ALLOWED}`)).toThrow(/not the allowed project/);
    expect(() => assertProject(ALLOWED, `${ALLOWED}\n`)).toThrow(/not the allowed project/);
  });
});
