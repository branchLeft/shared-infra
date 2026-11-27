import { MediaTreeRefusedError, MediaTreeTooLargeError, readMediaTree } from './mediaTree.js';
import { parseErasureDate, countSiteRelativeReferences, planMedia, scanMediaReferences, } from './mediaManifest.js';
export const MEMBERS_ENTRY = 'members.json';
export const MEMBERS_CSV_ENTRY = 'members.csv';
export const COMMENTS_ENTRY = 'comments.json';
export const MEDIA_ADDRESSES_ENTRY = 'media_addresses.json';
/** Ghost's admin comment list returns these two; it leaves `deleted` out, which the manifest names. */
export const COMMENT_STATUSES = ['published', 'hidden'];
/**
 * The manifest sits beside the archive in the clear, so a failure is named
 * by its kind and route only, never by a message that could echo Ghost's
 * response body, which can hold a member's data.
 */
function describe(err) {
    if (!(err instanceof Error))
        return 'unknown failure';
    const { route, status } = err;
    return typeof route === 'string' && typeof status === 'number'
        ? `${err.name} on ${route.split('?')[0]} (${status})`
        : err.name;
}
function failure(name, err) {
    return {
        report: {
            name,
            status: 'failed',
            expected: null,
            present: 0,
            notes: [describe(err)],
            info: [],
        },
        files: [],
    };
}
function json(value) {
    return JSON.stringify(value, null, 2);
}
/** Counts distinct, non-empty ids; every other row is one the archive cannot vouch for. */
function distinctIds(items) {
    const seen = new Set();
    let unidentified = 0;
    for (const row of items) {
        const id = row.id;
        if (typeof id !== 'string' || id.length === 0 || seen.has(id))
            unidentified += 1;
        else
            seen.add(id);
    }
    return { distinct: seen.size, unidentified };
}
function statusFor(notes) {
    return notes.length === 0 ? 'complete' : 'partial';
}
export async function collectMembers(deps) {
    let members;
    let csv;
    try {
        members = await deps.client.fetchMembers(deps.baseUrl);
        csv = await deps.client.fetchMembersCsv(deps.baseUrl);
    }
    catch (err) {
        return failure('members_and_subscriptions', err);
    }
    const notes = [];
    const { distinct, unidentified } = distinctIds(members.items);
    if (members.items.length !== members.total) {
        notes.push(`read ${members.items.length} members, Ghost counts ${members.total}`);
    }
    if (unidentified > 0)
        notes.push(`${unidentified} member rows have a missing or repeated id`);
    const withoutSubscriptions = members.items.filter((m) => !Array.isArray(m.subscriptions)).length;
    if (withoutSubscriptions > 0) {
        notes.push(`${withoutSubscriptions} member rows carry no subscription list`);
    }
    const subscriptions = members.items.reduce((n, m) => n + (Array.isArray(m.subscriptions) ? m.subscriptions.length : 0), 0);
    return {
        report: {
            name: 'members_and_subscriptions',
            status: statusFor(notes),
            expected: members.total,
            present: distinct,
            notes,
            info: [`${subscriptions} subscription records included`],
        },
        files: [
            { name: MEMBERS_ENTRY, data: json({ members: members.items }) },
            { name: MEMBERS_CSV_ENTRY, data: csv.body },
        ],
    };
}
function reportCountOf(comment) {
    const count = comment.count;
    if (typeof count === 'object' && count !== null) {
        const reports = count.reports;
        if (typeof reports === 'number' && reports > 0)
            return reports;
    }
    return 0;
}
export async function collectComments(deps) {
    let comments;
    try {
        comments = await deps.client.fetchComments(deps.baseUrl);
    }
    catch (err) {
        return failure('comments', err);
    }
    const notes = [];
    const { distinct, unidentified } = distinctIds(comments.items);
    if (comments.items.length !== comments.total) {
        notes.push(`read ${comments.items.length} comments, Ghost counts ${comments.total}`);
    }
    if (unidentified > 0)
        notes.push(`${unidentified} comment rows have a missing or repeated id`);
    const exported = [];
    let unreadable = 0;
    let reportsMissing = 0;
    for (const comment of comments.items) {
        const status = comment.status;
        const stateKnown = typeof status === 'string' && COMMENT_STATUSES.includes(status);
        if (!stateKnown)
            unreadable += 1;
        const expectedReports = reportCountOf(comment);
        let reports = [];
        let reportsRead = true;
        if (expectedReports > 0 && typeof comment.id === 'string') {
            try {
                const read = await deps.client.fetchCommentReports(deps.baseUrl, comment.id);
                reports = read.items;
                reportsRead = read.items.length === read.total && read.total === expectedReports;
            }
            catch {
                reportsRead = false;
            }
            if (!reportsRead)
                reportsMissing += 1;
        }
        exported.push({
            ...comment,
            moderation: {
                status: stateKnown ? status : null,
                reportCount: expectedReports,
                reports,
                reportsComplete: reportsRead,
            },
        });
    }
    if (unreadable > 0)
        notes.push(`${unreadable} comments have no readable moderation status`);
    if (reportsMissing > 0)
        notes.push(`${reportsMissing} comments have reports that could not be read in full`);
    const byStatus = COMMENT_STATUSES.map((s) => `${exported.filter((c) => c.moderation.status === s).length} ${s}`).join(', ');
    return {
        report: {
            name: 'comments',
            status: statusFor(notes),
            expected: comments.total,
            present: distinct,
            notes,
            info: [`moderation states: ${byStatus}`],
        },
        files: [{ name: COMMENTS_ENTRY, data: json({ comments: exported }) }],
    };
}
export async function collectMedia(deps) {
    if (deps.media.baseUrl === null) {
        return {
            report: {
                name: 'media',
                status: 'failed',
                expected: null,
                present: 0,
                notes: ["the tenant's rendered environment names no object-storage media address"],
                info: [],
            },
            files: [],
        };
    }
    try {
        const erasureDate = parseErasureDate(deps.media.erasureDate, deps.nowSeconds);
        const scan = scanMediaReferences(deps.contentJson, deps.media.baseUrl);
        const plan = await planMedia(scan, deps.media.baseUrl, deps.mediaProbe);
        const omittedSiteRelative = countSiteRelativeReferences(deps.contentJson);
        // An outside-prefix refusal is another tenant's or an external object: a fact, not a gap.
        // An in-prefix refusal is the tenant's own file, which the archive does not carry.
        const outsidePrefix = plan.refused.filter((r) => r.reason === 'outside-tenant-prefix').length;
        const unsafeKey = plan.refused.length - outsidePrefix;
        const notes = [];
        if (plan.missing.length > 0) {
            notes.push(`${plan.missing.length} referenced objects are not in storage`);
        }
        if (plan.unverified.length > 0) {
            notes.push(`${plan.unverified.length} referenced objects could not be checked`);
        }
        if (unsafeKey > 0) {
            notes.push(`${unsafeKey} tenant media references have unsafe object keys and were not listed`);
        }
        if (omittedSiteRelative > 0) {
            notes.push(`${omittedSiteRelative} site-relative media references were omitted, with no object key to list`);
        }
        return {
            report: {
                name: 'media',
                status: statusFor(notes),
                expected: scan.keys.length,
                present: plan.addresses.length,
                notes,
                info: [
                    `${outsidePrefix} references under another prefix were refused and not listed`,
                    `public addresses only, no media bytes: they stop working after ${erasureDate}`,
                ],
            },
            files: [
                {
                    name: MEDIA_ADDRESSES_ENTRY,
                    data: json({
                        tenantId: deps.tenantId,
                        erasureDate,
                        addresses: plan.addresses,
                        missing: plan.missing,
                        unverified: plan.unverified,
                        refused: plan.refused,
                    }),
                },
            ],
        };
    }
    catch (err) {
        return failure('media', err);
    }
}
/**
 * The originals of a demo slot's served media tree. A link, a device or any
 * other non-file in the tree is not a failure to report but a refusal, and it
 * ends the export: the error is thrown, never turned into a report.
 */
export async function collectMediaFiles(deps) {
    const tree = deps.mediaTree;
    if (tree === undefined)
        throw new Error('collectMediaFiles needs a media tree');
    let result;
    try {
        result = await readMediaTree({ ...tree, contentJson: deps.contentJson });
    }
    catch (err) {
        if (err instanceof MediaTreeRefusedError || err instanceof MediaTreeTooLargeError)
            throw err;
        return failure('media_files', err);
    }
    const { listing } = result;
    const oversized = listing.files.filter((f) => f.status === 'oversized');
    const notSent = listing.files.filter((f) => f.status === 'not-sent');
    const notes = [];
    if (listing.unrepresentable.length > 0) {
        notes.push(`${listing.unrepresentable.length} files have names the bundle cannot carry and were listed, not carried`);
    }
    return {
        report: {
            name: 'media_files',
            status: statusFor(notes),
            expected: listing.treeFileCount,
            present: listing.files.length + listing.unreferenced.length,
            notes,
            info: [
                `${result.files.length} referenced files carried`,
                `${listing.unreferenced.length} files no content references counted, left out`,
                `${notSent.length} files under media listed, not sent`,
                `${oversized.length} files over the upload ceiling listed, not carried`,
                `${listing.danglingReferences.length} references to files the tree does not hold`,
            ],
        },
        files: result.files,
        mediaFiles: listing,
    };
}
/** Runs them all; one failing never stops the others. A media tree refusal still ends the export. */
export async function collectExtensions(deps) {
    const outcomes = [
        await collectMedia(deps),
        await collectMembers(deps),
        await collectComments(deps),
    ];
    return deps.mediaTree === undefined ? outcomes : [...outcomes, await collectMediaFiles(deps)];
}
