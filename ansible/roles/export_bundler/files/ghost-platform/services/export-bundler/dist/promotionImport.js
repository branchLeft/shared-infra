import { openBundle, readTar } from './bundleReader.js';
/** The destination already holds members, so before-and-after counts would not mean what they say. */
export class DestinationNotFreshError extends Error {
    members;
    constructor(members) {
        super(`the destination already holds ${members} members; a promotion imports into an empty tenant`);
        this.members = members;
        this.name = 'DestinationNotFreshError';
    }
}
/** One of Ghost's imports failed or the destination could not be read; the tenant is not verified. */
export class ImportStepError extends Error {
    step;
    constructor(step, cause) {
        super(`promotion import failed at ${step}: ${cause instanceof Error ? cause.name : 'unknown failure'}`, { cause });
        this.step = step;
        this.name = 'ImportStepError';
    }
}
/**
 * The imports ran but the tenant does not hold what the bundle held. Names
 * the figures and never a member's address.
 */
export class ImportVerificationError extends Error {
    mismatches;
    before;
    expected;
    after;
    constructor(mismatches, before, expected, after) {
        super(`promotion import did not verify: ${mismatches.join('; ')}`);
        this.mismatches = mismatches;
        this.before = before;
        this.expected = expected;
        this.after = after;
        this.name = 'ImportVerificationError';
    }
}
async function step(name, run) {
    try {
        return await run();
    }
    catch (err) {
        throw new ImportStepError(name, err);
    }
}
const FIELDS = ['posts', 'pages', 'members'];
function countMismatches(expected, after) {
    return FIELDS.flatMap((field) => after[field] === expected[field]
        ? []
        : [`${field}: expected ${expected[field]} after import, found ${after[field]}`]);
}
function tierMismatches(bundle, destination) {
    const held = new Map(destination.map((m) => [m.email.trim().toLowerCase(), new Set(m.tierSlugs)]));
    const lost = bundle.memberTiers.filter((m) => {
        const slugs = held.get(m.email);
        return slugs === undefined || m.tierSlugs.some((slug) => !slugs.has(slug));
    });
    return lost.length === 0
        ? []
        : [
            `${lost.length} of ${bundle.memberTiers.length} members on a tier are not on it after import`,
        ];
}
/**
 * Opens the bundle (refusing one that does not agree with itself, before
 * anything is copied), requires an empty member table at the destination,
 * imports content then members through Ghost, and counts again. The tenant
 * must hold exactly what it held before plus what the bundle carried, and
 * every member who was on a tier must still be on it: the tier gap in Ghost's
 * export and import is checked here, not assumed.
 */
export async function runPromotionImport(deps) {
    const bundle = openBundle(readTar(await deps.openArchive()));
    const before = await step('count-before', () => deps.target.count());
    if (before.members !== 0)
        throw new DestinationNotFreshError(before.members);
    await step('import-content', () => deps.target.importContent(bundle.contentJson));
    await step('import-members', () => deps.target.importMembersCsv(bundle.membersCsv));
    const expected = {
        posts: before.posts + bundle.counts.posts,
        pages: before.pages + bundle.counts.pages,
        members: before.members + bundle.counts.members,
    };
    const after = await step('count-after', () => deps.target.count());
    const mismatches = countMismatches(expected, after);
    if (mismatches.length === 0 && bundle.memberTiers.length > 0) {
        const destination = await step('list-members', () => deps.target.listMembers());
        mismatches.push(...tierMismatches(bundle, destination));
    }
    if (mismatches.length > 0)
        throw new ImportVerificationError(mismatches, before, expected, after);
    return { before, bundle: bundle.counts, after, tierMembersVerified: bundle.memberTiers.length };
}
