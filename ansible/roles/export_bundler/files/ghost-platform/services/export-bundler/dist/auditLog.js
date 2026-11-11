import { chmod, mkdir, open } from 'node:fs/promises';
import { dirname } from 'node:path';
export class AuditWriteError extends Error {
    constructor(detail) {
        super(`the audit record could not be written (${detail})`);
        this.name = 'AuditWriteError';
    }
}
export function createFileAuditLog(path) {
    return {
        async record(entry) {
            try {
                await mkdir(dirname(path), { recursive: true, mode: 0o700 });
                // One write of one whole line to an O_APPEND file, then fsync: a
                // record is either all there or absent, never interleaved or torn
                // by a concurrent run.
                const handle = await open(path, 'a', 0o600);
                try {
                    await handle.write(`${JSON.stringify(entry)}\n`);
                    await handle.sync();
                }
                finally {
                    await handle.close();
                }
                // The open mode applies only on creation; a looser existing log is
                // tightened on every write.
                await chmod(path, 0o600);
            }
            catch (err) {
                throw new AuditWriteError(err.code ?? err.message);
            }
        },
    };
}
