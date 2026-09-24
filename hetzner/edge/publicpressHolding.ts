/**
 * The one-page holding site `render.ts` serves at `publicpress.co.uk`.
 *
 * Kept separate from the Caddy-rendering logic in `render.ts` on purpose:
 * the owner's copy drops in as a change to `PUBLICPRESS_HOLDING_TEXT` below,
 * and nobody editing that sentence needs to read or touch the renderer.
 *
 * The assembled page is a single line with no line breaks and single-quoted
 * HTML attributes throughout. `render.ts` embeds it inside a double-quoted
 * Caddyfile token, so a double quote anywhere in this file would need
 * escaping that a future hand-edit of the prose could easily get wrong --
 * avoiding the character avoids the escaping question entirely.
 */

/**
 * The owner's own copy. Change it here only; nothing else in this file or in
 * `render.ts` needs to change. Keep attributes single-quoted and never use a
 * double quote (see the note at the top of this file).
 */
export const PUBLICPRESS_HOLDING_TEXT = `PublicPress&trade;, a platform, ecosystem &amp; community for independent journalism. Built for people &amp; planet by <a href='https://branchleft.co.uk'>branchLeft</a>. Register interest: <a href='mailto:contact@branchleft.co.uk'>contact@branchleft.co.uk</a>. Complaints: <a href='mailto:complaints@branchleft.co.uk'>complaints@branchleft.co.uk</a>.`;

/**
 * The address the Public Suffix List's submission process requires to be
 * easily found on the listed domain's own website. A dedicated role mailbox
 * on `branchleft.co.uk`, not a personal address and not one on
 * `publicpress.co.uk` itself, which has no mail service yet.
 */
export const PUBLICPRESS_ABUSE_CONTACT = 'abuse@branchleft.co.uk';

/**
 * The full page `render.ts` serves verbatim for every path on
 * `publicpress.co.uk`. No script, no stylesheet, no font, no image, no
 * external resource of any kind -- `render.ts` attaches a
 * Content-Security-Policy to this hostname that assumes exactly that.
 */
export const PUBLICPRESS_HOLDING_HTML =
  "<!doctype html><html lang='en'><head><meta charset='utf-8'>" +
  "<meta name='viewport' content='width=device-width, initial-scale=1'>" +
  '<title>PublicPress</title></head><body>' +
  '<h1>PublicPress</h1>' +
  `<p>${PUBLICPRESS_HOLDING_TEXT}</p>` +
  '<section>' +
  `<p>Report abuse: <a href='mailto:${PUBLICPRESS_ABUSE_CONTACT}'>${PUBLICPRESS_ABUSE_CONTACT}</a></p>` +
  '<p>Operated by BRANCHLEFT LTD</p>' +
  '</section>' +
  '</body></html>';
