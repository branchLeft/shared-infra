// The page a person sees when the edge refuses them with a 403: an address
// CrowdSec has banned, or a request AppSec refuses in-band. Why it exists, where
// it sits and what it deliberately leaves out: `render.md`, "Blocked page".

/** The status the page answers with: the status of the refusal it replaces. */
export const BLOCKED_PAGE_STATUS = 403;

/**
 * The words on the page are the owner's. Each is an ALL_CAPS placeholder until
 * the owner supplies the copy; the pull request that ships this lists them. A
 * placeholder is plain text, so the page works, unfinished, as it stands.
 */
export const BLOCKED_PAGE_PLACEHOLDERS = [
  'BLOCKED_PAGE_TITLE',
  'BLOCKED_PAGE_HEADING',
  'BLOCKED_PAGE_EXPLANATION',
  'BLOCKED_PAGE_NEXT_STEPS',
  'BLOCKED_PAGE_CONTACT',
  'BLOCKED_PAGE_REFERENCE_LABEL',
] as const;

/**
 * The one runtime value on the page: the time the edge answered, in UTC. It is
 * what a person can quote and the owner can look up in `cscli alerts list` and
 * `cscli decisions list`, since the owner knows the address they were using. It
 * names neither the address nor the reason, so the page gives nothing to an
 * attacker that a bare 403 did not.
 */
export const BLOCKED_PAGE_TIME_PLACEHOLDER = '{time.now.http}';

// Why: the heredoc marker the page is closed by. The body has no line equal to it,
// and a test holds that. Same device as `SHARED_TENANT_FILE_EOF` in render.ts.
const BLOCKED_PAGE_HEREDOC = 'EDGE_BLOCKED_PAGE_EOF';

/** The matcher that picks a 403 out of every error Caddy routes to `handle_errors`. */
const BLOCKED_MATCHER = '@refused';

// Why: a static page with no asset of any kind. Styling is inline `style`
// attributes, never a `<style>` block: Caddy replaces every `{...}` in a
// `respond` body with its placeholder value (empty when it names nothing), and
// a CSS rule is written in braces. No `<script>`, `<link>`, `<img>`, font or
// URL, so a person whose address is banned loads nothing from anywhere else,
// and the policy below forbids it as well.
const BLOCKED_PAGE_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="robots" content="noindex">
<title>BLOCKED_PAGE_TITLE</title>
</head>
<body style="font-family: system-ui, sans-serif; line-height: 1.5; max-width: 40rem; margin: 3rem auto; padding: 0 1rem">
<h1>BLOCKED_PAGE_HEADING</h1>
<p>BLOCKED_PAGE_EXPLANATION</p>
<p>BLOCKED_PAGE_NEXT_STEPS</p>
<p>BLOCKED_PAGE_CONTACT</p>
<p style="font-size: 0.875rem">BLOCKED_PAGE_REFERENCE_LABEL: ${BLOCKED_PAGE_TIME_PLACEHOLDER}</p>
</body>
</html>
`;

/** The body of the page, ending in a newline so its heredoc closes on its own line. */
export function blockedPageHtml(): string {
  return BLOCKED_PAGE_HTML;
}

// Why: nothing may load. `default-src 'none'` forbids every fetch the page could
// make; the inline style attributes need `style-src 'unsafe-inline'`, which is
// safe on a page that runs no script and echoes nothing from the request.
const BLOCKED_PAGE_CSP =
  "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/**
 * The site-level `handle_errors` block of a site that carries a protection
 * chain. Caddy refuses `handle_errors` inside a `route`, and allows one per site,
 * so everything the site needs on an error it writes itself goes here.
 *
 * It matches a Caddy error of status 403, which is what the CrowdSec bouncer
 * and AppSec raise once `enable_caddy_error` is set (`globalOptions`). A `respond
 * 403` of the renderer's own (the Ghost setup and upload refusals) is not an
 * error and keeps its bare answer, and every other error keeps what it had.
 *
 * Unindented: each caller nests it at its own depth. The heredoc body is at
 * column 0 whatever the depth, which is what Caddy reads.
 */
export function blockedPageErrorBlock(options: { nosniff: boolean }): string[] {
  return [
    'handle_errors {',
    // Deferred, so it replaces any copy already set, as on the route (`nosniffDirective`).
    ...(options.nosniff ? ['\theader >X-Content-Type-Options "nosniff"'] : []),
    `\t${BLOCKED_MATCHER} expression \`{http.error.status_code} == ${BLOCKED_PAGE_STATUS}\``,
    `\thandle ${BLOCKED_MATCHER} {`,
    '\t\theader Content-Type "text/html; charset=utf-8"',
    // A ban is temporary: a cached page would outlive it.
    '\t\theader Cache-Control "no-store"',
    '\t\theader X-Robots-Tag "noindex"',
    `\t\theader Content-Security-Policy "${BLOCKED_PAGE_CSP}"`,
    `\t\trespond <<${BLOCKED_PAGE_HEREDOC}\n${BLOCKED_PAGE_HTML}${BLOCKED_PAGE_HEREDOC} ${BLOCKED_PAGE_STATUS}`,
    '\t}',
    '}',
  ];
}
