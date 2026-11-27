export function sidecarOf(manifest) {
    const { mediaFiles, ...rest } = manifest;
    if (mediaFiles === undefined)
        return rest;
    const carried = mediaFiles.files.filter((f) => f.status === 'carried');
    return {
        ...rest,
        mediaFiles: {
            treeFileCount: mediaFiles.treeFileCount,
            carried: carried.length,
            carriedBytes: carried.reduce((n, f) => n + f.size, 0),
            oversized: mediaFiles.files.filter((f) => f.status === 'oversized').length,
            notSent: mediaFiles.files.filter((f) => f.status === 'not-sent').length,
            unreferenced: mediaFiles.unreferenced.length,
            unrepresentable: mediaFiles.unrepresentable.length,
            danglingReferences: mediaFiles.danglingReferences.length,
        },
    };
}
export const REQUIRED_EXTENSIONS = [
    'media',
    'members_and_subscriptions',
    'comments',
];
/**
 * What no archive from this bundler can contain, named so the tenant finds
 * out before they leave rather than after. These are limits of reach, not
 * failures: they do not make a run incomplete.
 */
export const KNOWN_EXPORT_GAPS = [
    {
        name: 'analytics_beyond_post_csv',
        reason: 'the open item named in LLD-8 §11, not closeable before the analytics backend is chosen',
    },
    {
        name: 'stripe_billing_relationship',
        reason: "Stripe's side of each subscription cannot be moved by this archive: the archive carries Ghost's subscription records, and the ability to keep charging those cards elsewhere is Stripe's to move",
    },
    {
        name: 'portal_moderation_record',
        reason: "classifier verdicts and moderator decisions held by the portal's moderation queue are not in Ghost and not in this archive; the archive carries Ghost's own status and the member reports for each comment",
    },
    {
        name: 'deleted_comments',
        reason: "Ghost's admin comment list leaves out comments with status deleted, and blanks their text, so they are not in the archive and the comment count does not include them",
    },
    {
        name: 'media_bytes',
        reason: "the archive lists the public address of each media file, never the bytes; those addresses stop working on the tenant's erasure date, and a tenant keeps nothing from them after that unless they download first",
    },
];
function shortfalls(extensions) {
    const gaps = [];
    // The media files of a demo slot are required exactly when they were attempted.
    const required = extensions.some((e) => e.name === 'media_files')
        ? [...REQUIRED_EXTENSIONS, 'media_files']
        : REQUIRED_EXTENSIONS;
    for (const name of required) {
        const report = extensions.find((e) => e.name === name);
        if (report === undefined) {
            gaps.push({ name, reason: 'not attempted' });
        }
        else if (report.status === 'complete' && report.expected !== report.present) {
            // A report that says complete over a short count is a defect in the
            // collector, and the manifest must not repeat it.
            gaps.push({
                name,
                reason: `reported complete but present ${report.present} of expected ${String(report.expected)}`,
            });
        }
        else if (report.status !== 'complete') {
            gaps.push({
                name,
                reason: `${report.status}: ${report.notes.join('; ')}`,
            });
        }
    }
    return gaps;
}
export function buildManifest(tenantId, generatedAtIso, encryption, included, extensions = [], permanentGaps = KNOWN_EXPORT_GAPS, mediaFiles, activeTheme = null) {
    const failed = shortfalls(extensions);
    // The bytes are in this archive when the slot's media files were carried.
    const gaps = mediaFiles === undefined
        ? permanentGaps
        : permanentGaps.filter((g) => g.name !== 'media_bytes');
    return {
        ...(mediaFiles === undefined ? {} : { mediaFiles }),
        tenantId,
        generatedAt: generatedAtIso,
        encryption,
        activeTheme,
        complete: failed.length === 0,
        extensions,
        included,
        excluded: [...failed, ...gaps],
    };
}
/**
 * The `active_theme` setting from Ghost's own content export
 * (`db[0].data.settings`), or null when the export holds no such row or is
 * not the JSON that export writes. Never throws: the manifest then names no
 * theme rather than failing the export.
 */
export function activeThemeOf(contentJson) {
    let parsed;
    try {
        parsed = JSON.parse(contentJson);
    }
    catch {
        return null;
    }
    const db = parsed?.db;
    const settings = Array.isArray(db)
        ? db[0]?.data?.settings
        : undefined;
    if (!Array.isArray(settings))
        return null;
    const row = settings.find((r) => typeof r === 'object' && r !== null && r.key === 'active_theme');
    return typeof row?.value === 'string' ? row.value : null;
}
