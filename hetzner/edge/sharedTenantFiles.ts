/**
 * Fixed text files the edge answers on the shared tenant domain, keyed by the
 * `name` of their `StaticSite` in `sites.ts`. Why these files, and what each is
 * read by: `sites.md` section "Shared tenant domain files".
 *
 * Every wording below is an ALL_CAPS placeholder until the owner supplies the prose.
 * The contact is not prose: it is the abuse role mailbox the mail setup provisions,
 * defined here as a plain constant because this file is its only user, so it has one
 * home. `sharedTenantFiles.test.ts` pins its value and its domain.
 */

export interface StaticTextFile {
  /** Literal request path, starting with `/`. */
  path: string;
  /** Served as this media type. */
  contentType: string;
  /** The body as served. May span lines; the renderer emits it as a Caddy heredoc. */
  body: string;
}

/** The abuse role mailbox named as the `security.txt` contact. */
export const SHARED_TENANT_ABUSE_CONTACT = 'abuse@branchleft.co.uk';

const TEXT_CONTENT_TYPE = 'text/plain; charset=utf-8';

/**
 * Expiry for `security.txt` (RFC 9116 requires it, and a client must not trust
 * an expired file). A year from when this was written; renew before it passes.
 */
const SECURITY_TXT_EXPIRES = '2027-11-07T00:00:00.000Z';

export const SHARED_TENANT_FILES: Record<string, StaticTextFile[]> = {
  'sites-tenant-signals': [
    {
      // A comment-only robots.txt sets no crawl rule at all, so it states no
      // crawl policy; the AI-crawler default stays an open editorial question.
      path: '/robots.txt',
      contentType: TEXT_CONTENT_TYPE,
      body: '# HOSTING_NOTICE_PLACEHOLDER\n',
    },
    {
      path: '/.well-known/security.txt',
      contentType: TEXT_CONTENT_TYPE,
      body: [
        '# HOSTING_NOTICE_PLACEHOLDER',
        `Contact: mailto:${SHARED_TENANT_ABUSE_CONTACT}`,
        `Expires: ${SECURITY_TXT_EXPIRES}`,
        '',
      ].join('\n'),
    },
  ],
};
