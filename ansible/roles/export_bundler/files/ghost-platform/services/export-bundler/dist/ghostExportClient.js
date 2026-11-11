const PAGE_SIZE = 100;
const MAX_PAGES = 100_000;
export class GhostExportError extends Error {
    route;
    status;
    constructor(route, status, body) {
        super(`Ghost admin export ${route} answered ${status}: ${body.slice(0, 500)}`);
        this.route = route;
        this.status = status;
        this.name = 'GhostExportError';
    }
}
export class BreakGlassSessionError extends Error {
    constructor(status, body) {
        super(`break-glass session request answered ${status}: ${body.slice(0, 500)}`);
        this.name = 'BreakGlassSessionError';
    }
}
function filenameFromDisposition(header, fallback) {
    const match = header?.match(/filename="([^"]+)"/i);
    return match?.[1] ?? fallback;
}
// This colour is never routed (drainGate.ts's whole point), so it is only
// ever reached over plain loopback HTTP -- but the tenant's own `url`
// config is https (real tenants always are), and Ghost redirects (301,
// or refuses a Secure-flagged cookie) any request it considers insecure.
// Carrying the same header the real edge sets on every request it
// forwards is what makes Ghost treat this request as the secure one it
// actually is, on a real path production traffic also takes. Mirrors
// ghostProbe.ts's identical reasoning for the health check.
const FORWARDED_PROTO_HEADERS = { 'X-Forwarded-Proto': 'https' };
/**
 * Authenticates as `adapters/sso/README.md`'s break-glass adapter does.
 * See ../README.md#why-a-break-glass-session-not-an-admin-api-key.
 */
async function openBreakGlassSession(baseUrl, tokens, timeoutMs) {
    // Obtained before the request timer starts: the operator's time to mint
    // and hand over the token is not part of the HTTP timeout.
    const token = await tokens.obtain();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const url = new URL('/ghost/', baseUrl);
        url.searchParams.set('bl_break_glass', token);
        const response = await fetch(url, {
            signal: controller.signal,
            headers: FORWARDED_PROTO_HEADERS,
            redirect: 'manual',
        });
        const setCookie = response.headers.get('set-cookie');
        // A 2xx/3xx with no session cookie is not a session -- the adapter
        // fails closed to the login page on every refusal, which still
        // answers successfully as far as HTTP is concerned.
        if (!setCookie) {
            const body = await response.text();
            throw new BreakGlassSessionError(response.status, body || '(no Set-Cookie header; token likely refused)');
        }
        response.body?.cancel().catch(() => undefined);
        // Only the name=value pair travels on to the next request -- the
        // attributes (Path, Secure, SameSite, Expires) are for a browser's
        // cookie jar, not for the manual Cookie header this client sends.
        return setCookie.split(';', 1)[0];
    }
    finally {
        clearTimeout(timer);
    }
}
async function get(baseUrl, path, cookie, fallbackFilename, timeoutMs) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const response = await fetch(new URL(path, baseUrl), {
            headers: { Cookie: cookie, ...FORWARDED_PROTO_HEADERS },
            signal: controller.signal,
            redirect: 'manual',
        });
        const body = Buffer.from(await response.arrayBuffer());
        if (response.status !== 200) {
            throw new GhostExportError(path, response.status, body.toString('utf8'));
        }
        return {
            filename: filenameFromDisposition(response.headers.get('content-disposition'), fallbackFilename),
            contentType: response.headers.get('content-type') ?? 'application/octet-stream',
            body,
        };
    }
    finally {
        clearTimeout(timer);
    }
}
async function getCollection(baseUrl, path, key, cookie, timeoutMs) {
    const items = [];
    let total = null;
    for (let page = 1; page <= MAX_PAGES; page += 1) {
        const sep = path.includes('?') ? '&' : '?';
        const file = await get(baseUrl, `${path}${sep}limit=${PAGE_SIZE}&page=${page}`, cookie, `${key}.json`, timeoutMs);
        let parsed;
        try {
            parsed = JSON.parse(file.body.toString('utf8'));
        }
        catch {
            throw new GhostExportError(path, 200, 'the response is not JSON');
        }
        const record = (parsed ?? {});
        const rows = parsed?.[key];
        const pagination = record.meta?.pagination;
        if (!Array.isArray(rows) ||
            typeof pagination?.total !== 'number' ||
            typeof pagination.pages !== 'number') {
            throw new GhostExportError(path, 200, `the response has no "${key}" list and pagination total`);
        }
        items.push(...rows);
        total = pagination.total;
        if (page >= pagination.pages)
            return { items, total };
    }
    throw new GhostExportError(path, 200, `more than ${MAX_PAGES} pages`);
}
/**
 * One export, one administrator session: the cookie is opened at most
 * once per client and reused for both routes, the same way a person
 * signed in to Ghost's admin would call both without logging in twice --
 * not two independent break-glass spends for what LLD-8 §08b treats as
 * one audited action.
 */
export function createHttpGhostExportClient(tokens, timeoutMs) {
    let sessionPromise;
    function session(baseUrl) {
        sessionPromise ??= openBreakGlassSession(baseUrl, tokens, timeoutMs);
        return sessionPromise;
    }
    return {
        fetchContentAndSettings: async (baseUrl) => get(baseUrl, '/ghost/api/admin/db/', await session(baseUrl), 'ghost.json', timeoutMs),
        fetchPostAnalytics: async (baseUrl) => get(baseUrl, '/ghost/api/admin/posts/export/', await session(baseUrl), 'ghost.analytics.csv', timeoutMs),
        fetchMembersCsv: async (baseUrl) => get(baseUrl, '/ghost/api/admin/members/upload/?limit=all', await session(baseUrl), 'members.csv', timeoutMs),
        fetchMembers: async (baseUrl) => getCollection(baseUrl, '/ghost/api/admin/members/?include=tiers', 'members', await session(baseUrl), timeoutMs),
        fetchComments: async (baseUrl) => getCollection(baseUrl, '/ghost/api/admin/comments/?include_nested=true&order=created_at%20asc', 'comments', await session(baseUrl), timeoutMs),
        fetchCommentReports: async (baseUrl, commentId) => getCollection(baseUrl, `/ghost/api/admin/comments/${encodeURIComponent(commentId)}/reports/`, 'comment_reports', await session(baseUrl), timeoutMs),
    };
}
