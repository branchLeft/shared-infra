/**
 * The one-page holding site `render.ts` serves at `publicpress.co.uk`.
 *
 * Kept separate from the Caddy-rendering logic in `render.ts` on purpose:
 * the owner's copy drops in as a change to `PUBLICPRESS_HOLDING_TEXT` below,
 * and nobody editing that sentence needs to read or touch the renderer.
 *
 * The assembled page is a single line with no line breaks and single-quoted
 * HTML attributes throughout. `render.ts` embeds it inside a double-quoted
 * Caddyfile token, so a double quote anywhere in the page would need
 * escaping that a future hand-edit of the prose could easily get wrong --
 * avoiding the character avoids the escaping question entirely.
 */

import { PublicPressLogo, PublicPressWordmark } from '@branchleft/components';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

/**
 * The owner's own copy. Change it here only; nothing else in this file or in
 * `render.ts` needs to change. Keep attributes single-quoted and never use a
 * double quote (see the note at the top of this file).
 */
export const PUBLICPRESS_HOLDING_TEXT = `PublicPress&trade;, a platform, ecosystem &amp; community for independent journalism. Built for people &amp; planet by <a href='https://branchleft.co.uk'>branchLeft</a>.`;

/**
 * Each contact renders as its own paragraph, the label on one line and the
 * address on the next. Same quoting rule as the copy above.
 */
export const PUBLICPRESS_CONTACTS: ReadonlyArray<readonly [label: string, address: string]> = [
  ['Register interest:', 'contact@branchleft.co.uk'],
  ['Complaints:', 'complaints@branchleft.co.uk'],
];

/**
 * The address the Public Suffix List's submission process requires to be
 * easily found on the listed domain's own website. A dedicated role mailbox
 * on `branchleft.co.uk`, not a personal address and not one on
 * `publicpress.co.uk` itself, which has no mail service yet.
 */
export const PUBLICPRESS_ABUSE_CONTACT = 'abuse@branchleft.co.uk';

/**
 * Renders a mark from `@branchleft/components` to the markup this page
 * inlines, so the geometry is never copied here. The component's `style`
 * attribute is removed (the CSP admits only the hashed stylesheet below, so
 * it would be silently dropped) and its attributes are single-quoted.
 */
function markSvg(mark: typeof PublicPressWordmark | typeof PublicPressLogo): string {
  const markup = renderToStaticMarkup(createElement(mark)).replace(/ style="[^"]*"/, '');
  if (markup.includes("'")) {
    throw new Error('a mark carries a single quote, which the quote swap below would corrupt');
  }
  return markup.replaceAll('"', "'");
}

/** The PublicPress wordmark, blue ink, as outlined SVG. */
export const PUBLICPRESS_WORDMARK_SVG = markSvg(PublicPressWordmark);

/**
 * The pilcrow-P logo as the favicon, inline as a `data:` URI because the
 * page may fetch nothing. `render.ts` admits `data:` images for it.
 */
export const PUBLICPRESS_FAVICON_HREF = `data:image/svg+xml,${encodeURIComponent(markSvg(PublicPressLogo)).replaceAll("'", '%27')}`;

/**
 * The page's only stylesheet. `render.ts` admits it by its SHA-256 in the
 * Content-Security-Policy, computed from whatever `<style>` element the page
 * carries, so an edit here needs no second edit there.
 */
export const PUBLICPRESS_HOLDING_CSS =
  `html{background:#FAFAF7}` +
  `body{margin:0;min-height:100vh;display:flex;align-items:center;background:#FAFAF7;color:#1F2E4F;background-image:radial-gradient(rgba(50,85,164,.07) 1px,transparent 1.2px);background-size:5px 5px;font:400 1.125rem/1.6 'Futura','Century Gothic','Avenir Next',system-ui,sans-serif}` +
  `main{width:100%;max-width:34rem;margin:0 auto;padding:3rem 1rem;box-sizing:border-box}` +
  `h1{margin:0 0 2rem}` +
  `h1 svg{display:block;width:100%;max-width:26rem;height:auto;box-shadow:.4rem .4rem 0 #FF48B0}` +
  `p{margin:0 0 1rem}` +
  `a{color:#3255A4;text-decoration:underline;text-decoration-color:#FF48B0;text-decoration-thickness:2px;text-underline-offset:3px}` +
  `a:hover,a:focus-visible{background:#FFE800;color:#000;outline:none}` +
  `footer{margin-top:2.5rem;padding-top:1rem;border-top:2px solid #FF48B0;font:400 .875rem/1.5 'Courier Prime','Courier New',Courier,monospace;color:#000}` +
  `footer p{margin:0 0 .25rem}` +
  `canvas{position:fixed;top:0;left:0;width:100%;height:100%;touch-action:none;cursor:crosshair}` +
  `main{position:relative;pointer-events:none}` +
  `main>*{pointer-events:auto}`;

/**
 * An easter egg: the dotted background is a sheet to draw on in the three
 * Riso inks, each stroke fading away ten seconds after it is finished. The
 * content column takes its own pointer events so text stays selectable.
 *
 * `render.ts` admits it by its SHA-256, as for the stylesheet. Besides the
 * no-double-quote rule, it must contain no backslash (the Caddyfile lexer
 * reads one as an escape) and every `{` must be followed by a space, because
 * Caddy substitutes a known placeholder such as `{path}` inside the body.
 */
export const PUBLICPRESS_HOLDING_SCRIPT = [
  '(function () {',
  " var c = document.querySelector('canvas'), x = c.getContext('2d');",
  " var inks = ['#FF48B0', '#3255A4', '#FFE800'], strokes = [], live = null, n = 0, raf = 0;",
  ' var HOLD = 10000, FADE = 1500;',
  ' function size() { var d = window.devicePixelRatio || 1; c.width = innerWidth * d; c.height = innerHeight * d; x.setTransform(d, 0, 0, d, 0, 0); draw(); }',
  ' function draw() {',
  '  var now = Date.now();',
  '  strokes = strokes.filter(function (s) { return s === live || now - s.t < HOLD + FADE; });',
  '  x.clearRect(0, 0, c.width, c.height);',
  "  x.globalCompositeOperation = 'multiply'; x.lineWidth = 6; x.lineCap = x.lineJoin = 'round';",
  '  strokes.forEach(function (s) {',
  '   x.globalAlpha = s === live ? 1 : Math.min(1, (HOLD + FADE - (now - s.t)) / FADE);',
  '   x.strokeStyle = s.ink; x.beginPath(); x.moveTo(s.p[0][0], s.p[0][1]);',
  '   s.p.forEach(function (q) { x.lineTo(q[0] + 0.01, q[1]); });',
  '   x.stroke();',
  '  });',
  '  raf = strokes.length ? requestAnimationFrame(draw) : 0;',
  ' }',
  " c.addEventListener('pointerdown', function (e) { live = { ink: inks[n++ % inks.length], p: [[e.clientX, e.clientY]], t: 0 }; strokes.push(live); c.setPointerCapture(e.pointerId); if (!raf) raf = requestAnimationFrame(draw); });",
  " c.addEventListener('pointermove', function (e) { if (live) live.p.push([e.clientX, e.clientY]); });",
  ' function end() { if (live) { live.t = Date.now(); live = null; } }',
  " c.addEventListener('pointerup', end); c.addEventListener('pointercancel', end);",
  " addEventListener('resize', size); size();",
  '})();',
].join('');

function contactLine(label: string, address: string): string {
  return `<p>${label}<br><a href='mailto:${address}'>${address}</a></p>`;
}

/**
 * The full page `render.ts` serves verbatim for every path on
 * `publicpress.co.uk`. No font, no image, no external resource of any kind;
 * one inline stylesheet and one inline script, each admitted by hash.
 */
export const PUBLICPRESS_HOLDING_HTML =
  "<!doctype html><html lang='en'><head><meta charset='utf-8'>" +
  "<meta name='viewport' content='width=device-width, initial-scale=1'>" +
  `<link rel='icon' type='image/svg+xml' href='${PUBLICPRESS_FAVICON_HREF}'>` +
  `<title>PublicPress</title><style>${PUBLICPRESS_HOLDING_CSS}</style></head><body>` +
  "<canvas aria-hidden='true'></canvas><main>" +
  `<h1>${PUBLICPRESS_WORDMARK_SVG}</h1>` +
  `<p>${PUBLICPRESS_HOLDING_TEXT}</p>` +
  PUBLICPRESS_CONTACTS.map(([label, address]) => contactLine(label, address)).join('') +
  '<footer>' +
  contactLine(
    'Seen spam, phishing or other misuse on a PublicPress site? Report it to:',
    PUBLICPRESS_ABUSE_CONTACT
  ) +
  '<p>Operated by BRANCHLEFT LTD</p>' +
  '</footer>' +
  '</main>' +
  `<script>${PUBLICPRESS_HOLDING_SCRIPT}</script>` +
  '</body></html>';
