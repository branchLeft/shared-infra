import { describe, expect, it } from 'vitest';

import { shouldSkipPrettierConfigTests } from './prettierConfigSkip';

describe('shouldSkipPrettierConfigTests', () => {
  it.each([
    { resolves: true, ci: undefined, skip: false },
    { resolves: true, ci: 'true', skip: false },
    { resolves: false, ci: 'true', skip: false },
    { resolves: false, ci: undefined, skip: true },
    { resolves: false, ci: '', skip: true },
  ])('resolves=$resolves ci=$ci gives skip=$skip', ({ resolves, ci, skip }) => {
    expect(shouldSkipPrettierConfigTests({ resolves, ci })).toBe(skip);
  });
});
