import { accessSync, constants, lstatSync } from 'node:fs';
import { dirname } from 'node:path';
// Spelled out instead of NodeJS.ErrnoException so this file has no
// dependency on the ambient @types/node globals eslint's plain
// (non-type-aware) config doesn't resolve -- mirrors
// services/drain-sidecar/src/drainFlag.ts's own reasoning.
function isEnoent(err) {
    return err?.code === 'ENOENT';
}
function directoryIsReadable(dir) {
    try {
        accessSync(dir, constants.R_OK | constants.X_OK);
        return true;
    }
    catch {
        return false;
    }
}
/**
 * A stat-and-forget presence check, deliberately duplicated rather than
 * imported. See ../README.md#the-drain-flag-check.
 */
export function createFileDrainFlag(path) {
    const dir = dirname(path);
    return {
        isSet: () => {
            try {
                lstatSync(path);
                return true;
            }
            catch (err) {
                return !(isEnoent(err) && directoryIsReadable(dir));
            }
        },
    };
}
