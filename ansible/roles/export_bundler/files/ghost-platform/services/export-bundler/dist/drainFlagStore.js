import { mkdir, rm, writeFile, rename } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { randomUUID } from 'node:crypto';
/**
 * Exported so a caller wiring this store's write side to drainFlag.ts's
 * read side (see cli.ts) computes the identical path both directions --
 * the two must never drift, or the read-back in exportRunner.ts's own
 * boot-drained check would silently check nothing real.
 */
export function flagPathFor(dir, colourId) {
    return join(dir, `${colourId}.drain`);
}
async function writeAtomic(path) {
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    const tmp = `${path}.${randomUUID()}.tmp`;
    await writeFile(tmp, '', { mode: 0o600 });
    await rename(tmp, path);
}
export function createDrainFlagStore(dir) {
    return {
        set: (colourId) => writeAtomic(flagPathFor(dir, colourId)),
        clear: (colourId) => rm(flagPathFor(dir, colourId), { force: true }),
    };
}
