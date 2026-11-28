import { createHash } from 'node:crypto';
import { readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { isMediaEntryName, MEDIA_ENTRY_PREFIX } from './entryNames.js';
import { assertDrained } from './drainGate.js';
import { waitUntilHealthy } from './ghostProbe.js';
import { activeThemeOf, buildManifest, sidecarOf, } from './manifest.js';
import { collectExtensions, } from './extensions.js';
import { writeEncryptedArchive, writeManifestSidecar } from './archive.js';
import { assertAgeRecipient, recipientFingerprint } from './ageEncryption.js';
import { assertColourOnScratch, pointAtScratch, } from './scratchDatabase.js';
import { assertIsSupportRole, assertSupportAccountActive, parseSupportGrant, SupportAccountNotActiveError, } from './supportGrant.js';
/**
 * Raised by the CLI, after it has printed the result, when the export itself
 * succeeded but a teardown step (colour, scratch copy, drain flag) failed: the
 * archive, manifest and audit entry exist, and so does a leftover resource.
 */
export class ExportCleanupError extends Error {
    result;
    cleanupErrors;
    constructor(result, cleanupErrors) {
        super(`the export succeeded but ${describeCleanupErrors(cleanupErrors)}`);
        this.result = result;
        this.cleanupErrors = cleanupErrors;
        this.name = 'ExportCleanupError';
    }
}
const CLEANUP_ERRORS = 'cleanupErrors';
/**
 * Teardown failures attached to the error that failed the export, in
 * teardown order; empty when there are none. The export's own error is
 * still the one thrown: a cleanup failure never replaces it.
 */
export function cleanupErrorsOf(err) {
    if (typeof err !== 'object' || err === null)
        return [];
    const attached = err[CLEANUP_ERRORS];
    return Array.isArray(attached) ? attached : [];
}
/** `name: message` for each failure, for a log line. */
export function describeCleanupErrors(errors) {
    const parts = errors.map((e) => (e instanceof Error ? `${e.name}: ${e.message}` : String(e)));
    return `${parts.length === 1 ? 'a cleanup step' : `${parts.length} cleanup steps`} failed (${parts.join('; ')})`;
}
/** Teardown steps run to the end, each on its own, and the failures are kept for the caller. */
class CleanupFailures {
    errors = [];
    async attempt(step) {
        try {
            await step();
        }
        catch (err) {
            this.errors.push(err);
        }
    }
}
function withCleanupErrors(err, errors) {
    if (errors.length === 0)
        return err;
    if (typeof err === 'object' && err !== null) {
        try {
            Object.defineProperty(err, CLEANUP_ERRORS, {
                value: [...cleanupErrorsOf(err), ...errors],
                writable: true,
                configurable: true,
                enumerable: false,
            });
            return err;
        }
        catch {
            // A frozen or sealed error cannot carry the field: fall through.
        }
    }
    // Not an object, or one that cannot be written to: keep the original as the
    // first of the aggregate, so it is still what a reader sees first.
    return new AggregateError([err, ...errors], `${String(err)}; ${describeCleanupErrors(errors)}`);
}
export class GhostNeverBecameHealthyError extends Error {
    constructor(colourId, timeoutMs) {
        super(`Ghost on colour "${colourId}" never answered 200 within ${timeoutMs}ms`);
        this.name = 'GhostNeverBecameHealthyError';
    }
}
const CONTENT_ENTRY = 'content_and_settings.json';
const ANALYTICS_ENTRY = 'post_analytics.csv';
/**
 * The bundler LLD-8 §08b describes, run as a support grant (LLD-5 §05)
 * against a copy of the tenant's database (owner ruling, "the copy"):
 * refuse unless a grant is in force and the support account is active; make
 * the copy; start the tenant's image on a drained colour pointed at the
 * copy, and at nothing else; call Ghost's two existing admin exports; bundle
 * one archive encrypted to the tenant's recipient; record the audit entry.
 * The colour, then the copy, then the drain flag are removed on every exit
 * path -- signals included, through cleanup.ts.
 */
export async function runExport(deps, request) {
    const grant = parseSupportGrant(request.grant.lane, request.grant.reference);
    assertAgeRecipient(request.ageRecipient);
    const { account } = await deps.supportAccount.readPreflight(request.supportIdentity);
    if (account === null)
        throw new SupportAccountNotActiveError(request.supportIdentity, null);
    assertIsSupportRole(request.supportIdentity, account.roles);
    assertSupportAccountActive(request.supportIdentity, account.status);
    // A new colour always boots drained (LLD-4 §U3b/§U7): the flag is set
    // before anything starts, then re-read rather than trusted, so this
    // function's own refusal path exercises the exact same check a stray
    // live colour would fail.
    await deps.drainFlags.set(request.colourId);
    // A teardown failure is kept, never thrown from where it happens: thrown
    // from a `finally` it would replace the export's own error, or, after a
    // finished export, hide the archive that bundle() had already written and
    // audited. Every step still runs; the failures go to the caller with the
    // outcome instead.
    const cleanup = new CleanupFailures();
    let result;
    try {
        result = await exportOnScratch(deps, request, grant, cleanup);
    }
    catch (err) {
        await cleanup.attempt(() => deps.drainFlags.clear(request.colourId));
        throw withCleanupErrors(err, cleanup.errors);
    }
    await cleanup.attempt(() => deps.drainFlags.clear(request.colourId));
    return cleanup.errors.length === 0 ? result : { ...result, cleanupErrors: cleanup.errors };
}
async function exportOnScratch(deps, request, grant, cleanup) {
    assertDrained(deps.readDrainFlag(request.colourId), request.colourId);
    try {
        const copy = await deps.scratch.prepare();
        const colourEnv = pointAtScratch(request.colourBaseEnv, copy);
        // Before the colour exists: a colour pointed at the live database
        // must never boot, because Ghost acts on its database during boot.
        assertColourOnScratch(colourEnv, copy.target, request.liveDatabase);
        const { baseUrl } = await deps.containerRunner.start(colourEnv, {
            network: copy.network,
            volumes: copy.colourVolumes,
        });
        try {
            const healthy = await waitUntilHealthy(deps.probe, baseUrl, deps.healthTimeoutMs, deps.healthPollIntervalMs);
            if (!healthy) {
                throw new GhostNeverBecameHealthyError(request.colourId, deps.healthTimeoutMs);
            }
            // Again, before any export call, on what Docker says the running
            // colour was actually given.
            assertColourOnScratch(await deps.containerRunner.readEnv(), copy.target, request.liveDatabase);
            const [contentAndSettings, postAnalytics] = await Promise.all([
                deps.exportClient.fetchContentAndSettings(baseUrl),
                deps.exportClient.fetchPostAnalytics(baseUrl),
            ]);
            const extensions = await collectExtensions({
                client: deps.exportClient,
                mediaProbe: deps.mediaProbe,
                baseUrl,
                tenantId: request.tenantId,
                media: request.media,
                ...(request.mediaTree === undefined ? {} : { mediaTree: request.mediaTree }),
                nowSeconds: Math.floor(Date.parse(deps.nowIso()) / 1000),
                contentJson: contentAndSettings.body.toString('utf8'),
            });
            return await bundle(deps, request, grant, contentAndSettings, postAnalytics, extensions);
        }
        finally {
            await cleanup.attempt(() => deps.containerRunner.stop());
        }
    }
    finally {
        await cleanup.attempt(() => deps.scratch.destroy());
    }
}
async function bundle(deps, request, grant, contentAndSettings, postAnalytics, extensions) {
    const generatedAt = deps.nowIso();
    const extensionFiles = extensions.flatMap((e) => e.files);
    const fingerprint = recipientFingerprint(request.ageRecipient);
    const manifest = buildManifest(request.tenantId, generatedAt, {
        encrypted: true,
        format: 'age',
        recipient: request.ageRecipient,
        recipientFingerprint: fingerprint,
    }, [
        { name: 'content_and_settings', path: CONTENT_ENTRY },
        { name: 'post_analytics', path: ANALYTICS_ENTRY },
        ...extensionFiles
            .filter((file) => !isMediaEntryName(file.name))
            .map((file) => ({
            name: file.name.replace(/\.json$/, '').replace(/\.csv$/, '_csv'),
            path: file.name,
        })),
        // One line for the whole tree: a file's name is the tenant's own content,
        // and this list sits beside the archive in the clear.
        ...(extensionFiles.some((file) => isMediaEntryName(file.name))
            ? [{ name: 'media_files', path: MEDIA_ENTRY_PREFIX }]
            : []),
    ], extensions.map((e) => e.report), undefined, extensions.find((e) => e.mediaFiles !== undefined)?.mediaFiles, activeThemeOf(contentAndSettings.body.toString('utf8')));
    const manifestJson = JSON.stringify(manifest, null, 2);
    // Beside the archive, readable without the key: counts, never file names.
    const sidecarJson = JSON.stringify(sidecarOf(manifest), null, 2);
    const stem = join(request.destDir, `${request.tenantId}-export-${generatedAt.replace(/[:.]/g, '')}`);
    const archivePath = `${stem}.tar.age`;
    const manifestPath = `${stem}.manifest.json`;
    await writeEncryptedArchive(archivePath, [
        { name: CONTENT_ENTRY, data: contentAndSettings.body },
        { name: ANALYTICS_ENTRY, data: postAnalytics.body },
        ...extensionFiles,
        { name: 'manifest.json', data: manifestJson },
    ], Math.floor(Date.parse(generatedAt) / 1000), request.ageRecipient, deps.ageCommand);
    // An archive without its audit record must not outlive the run: any
    // failure from here on removes both files before it is reported.
    try {
        await writeManifestSidecar(manifestPath, sidecarJson);
        const archiveSha256 = createHash('sha256')
            .update(await readFile(archivePath))
            .digest('hex');
        await deps.auditLog.record({
            tenantId: request.tenantId,
            requestedBy: request.requestedBy,
            occurredAt: generatedAt,
            contents: manifest.included.map((entry) => entry.name),
            complete: manifest.complete,
            deliveredTo: request.deliveredTo,
            grant: { lane: grant.lane, reference: grant.reference },
            supportIdentity: request.supportIdentity,
            encryptedTo: fingerprint,
            archiveSha256,
        });
        return { archivePath, manifestPath, manifest, archiveSha256 };
    }
    catch (err) {
        await rm(archivePath, { force: true });
        await rm(manifestPath, { force: true });
        throw err;
    }
}
