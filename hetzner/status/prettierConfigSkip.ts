import { createRequire } from 'node:module';
import path from 'node:path';

/** The private package the repo root's `prettier` field names. */
export const PRETTIER_CONFIG_PACKAGE = '@branchleft/prettier-config';

/** Whether `repoRoot` can resolve the package, as Prettier does from the root package.json. */
export const prettierConfigResolves = (repoRoot: string): boolean => {
  try {
    createRequire(path.join(repoRoot, 'package.json')).resolve(PRETTIER_CONFIG_PACKAGE);
    return true;
  } catch {
    return false;
  }
};

/**
 * Skip only when the package is absent and CI is unset. An unset or empty CI
 * means a local worktree, where the package may be missing. A CI run must
 * fail on the missing package rather than skip it.
 */
export const shouldSkipPrettierConfigTests = (input: {
  resolves: boolean;
  ci: string | undefined;
}): boolean => !input.resolves && (input.ci === undefined || input.ci === '');
