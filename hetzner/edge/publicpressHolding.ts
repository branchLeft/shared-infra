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
 * The PublicPress wordmark, blue ink, as outlined SVG: rendered from
 * `PublicPressWordmark` in `@branchleft/components` and pasted here, because
 * this page may load no font and no image. Regenerate it from that component
 * rather than editing the paths. Its `style` attribute is removed (the CSP
 * admits only the hashed stylesheet below, so an inline style attribute would
 * be silently dropped) and its attributes are single-quoted.
 */
export const PUBLICPRESS_WORDMARK_SVG =
  "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 6620 1340' role='img' aria-label='PublicPress'><rect x='0' y='0' width='6620' height='1340' fill='#3255A4'></rect><path d='M813.0 511.0Q813.0 590.0 774.0 641.0Q735.0 692.0 668.5 717.0Q602.0 742.0 522.0 742.0H70.0V616.0H126.0V22.0Q126.0 0.0 148.0 0.0H228.5V616.0H278.5V0.0H355.0Q381.0 0.0 381.0 23.0V273.0Q381.0 284.0 392.0 284.0H542.0Q622.0 284.0 682.5 310.0Q743.0 336.0 778.0 386.5Q813.0 437.0 813.0 511.0ZM633.0 514.0Q633.0 465.0 602.0 437.0Q571.0 409.0 518.0 409.0H395.0Q381.0 409.0 381.0 428.0V599.0Q381.0 616.0 400.0 616.0H511.0Q547.0 616.0 575.0 605.0Q603.0 594.0 618.0 571.5Q633.0 549.0 633.0 514.0Z' fill='#FAFAF7' transform='translate(260, 1020) scale(1,-1)'></path><path d='M274 101Q305 101 332.5 117.5Q360 134 383 160V507Q383 530 409 530H517Q538 530 538 509L536 18Q536 0 520 0H401Q386 0 386 17V66Q386 72 383.0 73.5Q380 75 375 70Q333 27 291.5 8.5Q250 -10 203 -10Q159 -10 124.5 9.0Q90 28 70.0 64.5Q50 101 50 151V506Q50 530 74 530H185Q204 530 204 509V173Q204 140 222.5 120.5Q241 101 274 101Z' fill='#FAFAF7' transform='translate(1111, 1020) scale(1,-1)'></path><path d='M78 0Q65 0 60.0 5.0Q55 10 55 22V723Q55 742 71 742H194Q209 742 209 724V491Q209 479 214.5 478.5Q220 478 227 484Q243 499 263.5 511.5Q284 524 310.0 532.0Q336 540 367 540Q435 540 481.5 506.0Q528 472 552.0 411.0Q576 350 576 268Q576 141 517.0 65.5Q458 -10 348 -10Q312 -10 281.5 1.5Q251 13 228.5 32.0Q206 51 190 71Q186 76 182.5 75.5Q179 75 178 68L166 20Q161 0 143 0ZM209 183Q209 153 223.0 131.0Q237 109 259.5 96.5Q282 84 309 84Q342 84 367.0 102.0Q392 120 405.5 160.5Q419 201 419 266Q419 358 392.0 400.0Q365 442 313 442Q281 442 255.0 427.5Q229 413 209 389Z' fill='#FAFAF7' transform='translate(1703, 1020) scale(1,-1)'></path><path d='M210 24Q210 11 204.0 5.5Q198 0 183 0H77Q55 0 55 21L58 723Q58 742 74 742H195Q210 742 210 724Z' fill='#FAFAF7' transform='translate(2312, 1020) scale(1,-1)'></path><path d='M209 24Q209 11 203.0 5.5Q197 0 182 0H77Q64 0 59.5 5.0Q55 10 55 21V511Q55 530 71 530H194Q209 530 209 513ZM211 619Q211 594 184 594H76Q63 594 58.5 600.0Q54 606 54 617V722Q54 742 71 742H195Q211 742 211 723Z' fill='#FAFAF7' transform='translate(2578, 1020) scale(1,-1)'></path><path d='M297 540Q362 540 407.5 517.5Q453 495 482.0 460.0Q511 425 523 388Q530 368 511 367L406 357Q395 356 391 368Q382 387 371.0 403.0Q360 419 344.0 429.0Q328 439 302 439Q268 439 242.0 420.0Q216 401 201.5 362.5Q187 324 187 265Q187 205 202.0 166.0Q217 127 244.5 108.0Q272 89 310 89Q354 89 379.5 112.0Q405 135 428 174Q431 179 434.0 180.0Q437 181 445 179L519 162Q530 159 526 143Q518 121 501.0 94.0Q484 67 456.5 44.0Q429 21 389.5 5.5Q350 -10 297 -10Q220 -10 160.0 24.5Q100 59 65.5 120.5Q31 182 31 263Q31 345 66.0 407.5Q101 470 161.0 505.0Q221 540 297 540Z' fill='#FAFAF7' transform='translate(2843, 1020) scale(1,-1)'></path><path d='M813.0 511.0Q813.0 590.0 774.0 641.0Q735.0 692.0 668.5 717.0Q602.0 742.0 522.0 742.0H70.0V616.0H126.0V22.0Q126.0 0.0 148.0 0.0H228.5V616.0H278.5V0.0H355.0Q381.0 0.0 381.0 23.0V273.0Q381.0 284.0 392.0 284.0H542.0Q622.0 284.0 682.5 310.0Q743.0 336.0 778.0 386.5Q813.0 437.0 813.0 511.0ZM633.0 514.0Q633.0 465.0 602.0 437.0Q571.0 409.0 518.0 409.0H395.0Q381.0 409.0 381.0 428.0V599.0Q381.0 616.0 400.0 616.0H511.0Q547.0 616.0 575.0 605.0Q603.0 594.0 618.0 571.5Q633.0 549.0 633.0 514.0Z' fill='#FAFAF7' transform='translate(3454, 1020) scale(1,-1)'></path><path d='M76 0Q65 0 60.0 5.0Q55 10 55 20V511Q55 530 71 530H188Q204 530 204 513V454Q204 448 208.5 446.5Q213 445 218 451Q238 478 263.5 498.0Q289 518 316.0 529.0Q343 540 367 540Q403 540 403 523V407Q403 391 388 394Q370 399 351.0 400.5Q332 402 318 402Q300 402 280.5 395.0Q261 388 245.0 375.0Q229 362 219.0 347.0Q209 332 209 315V23Q209 0 183 0H76Z' fill='#FAFAF7' transform='translate(4305, 1020) scale(1,-1)'></path><path d='M190 220Q190 183 207.5 154.5Q225 126 254.5 110.5Q284 95 321 95Q357 95 387.5 110.5Q418 126 449 162Q453 166 456.0 166.5Q459 167 467 163L539 133Q553 127 542 113Q510 67 475.0 40.0Q440 13 397.5 1.5Q355 -10 302 -10Q224 -10 163.0 24.0Q102 58 66.5 118.5Q31 179 31 257Q31 343 67.5 406.5Q104 470 165.0 505.0Q226 540 299 540Q376 540 434.0 506.5Q492 473 525.5 411.0Q559 349 559 260Q559 249 557.0 243.0Q555 237 542 236H202Q196 236 193.0 232.0Q190 228 190 220ZM391 320Q402 320 405.0 322.5Q408 325 408 334Q408 359 396.5 385.0Q385 411 362.5 428.5Q340 446 305 446Q272 446 246.0 430.0Q220 414 206.0 385.5Q192 357 192 321Z' fill='#FAFAF7' transform='translate(4714, 1020) scale(1,-1)'></path><path d='M382 392Q365 414 336.0 430.0Q307 446 265 446Q228 446 202.5 431.5Q177 417 177 392Q177 379 187.0 367.5Q197 356 233 347L348 319Q431 300 466.0 257.0Q501 214 501 161Q501 107 470.5 69.0Q440 31 386.0 10.5Q332 -10 262 -10Q173 -10 111.0 21.5Q49 53 24 100Q20 107 20.0 113.5Q20 120 26 123L94 158Q104 163 109.5 162.5Q115 162 119 157Q132 139 150.0 123.0Q168 107 195.0 97.5Q222 88 263 89Q291 89 313.5 95.5Q336 102 349.0 114.5Q362 127 362 144Q362 161 348.0 173.5Q334 186 296 195L193 217Q118 234 79.5 270.5Q41 307 41 366Q41 417 67.5 456.0Q94 495 145.0 517.5Q196 540 267 540Q343 540 398.5 512.0Q454 484 478 445Q482 439 484.0 432.5Q486 426 477 421L405 386Q398 383 392.5 384.5Q387 386 382 392Z' fill='#FAFAF7' transform='translate(5300, 1020) scale(1,-1)'></path><path d='M382 392Q365 414 336.0 430.0Q307 446 265 446Q228 446 202.5 431.5Q177 417 177 392Q177 379 187.0 367.5Q197 356 233 347L348 319Q431 300 466.0 257.0Q501 214 501 161Q501 107 470.5 69.0Q440 31 386.0 10.5Q332 -10 262 -10Q173 -10 111.0 21.5Q49 53 24 100Q20 107 20.0 113.5Q20 120 26 123L94 158Q104 163 109.5 162.5Q115 162 119 157Q132 139 150.0 123.0Q168 107 195.0 97.5Q222 88 263 89Q291 89 313.5 95.5Q336 102 349.0 114.5Q362 127 362 144Q362 161 348.0 173.5Q334 186 296 195L193 217Q118 234 79.5 270.5Q41 307 41 366Q41 417 67.5 456.0Q94 495 145.0 517.5Q196 540 267 540Q343 540 398.5 512.0Q454 484 478 445Q482 439 484.0 432.5Q486 426 477 421L405 386Q398 383 392.5 384.5Q387 386 382 392Z' fill='#FAFAF7' transform='translate(5830, 1020) scale(1,-1)'></path></svg>";

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
  `footer p{margin:0 0 .25rem}`;

/**
 * The full page `render.ts` serves verbatim for every path on
 * `publicpress.co.uk`. No script, no font, no image, no external resource of
 * any kind; one inline stylesheet, admitted by hash.
 */
export const PUBLICPRESS_HOLDING_HTML =
  "<!doctype html><html lang='en'><head><meta charset='utf-8'>" +
  "<meta name='viewport' content='width=device-width, initial-scale=1'>" +
  `<title>PublicPress</title><style>${PUBLICPRESS_HOLDING_CSS}</style></head><body><main>` +
  `<h1>${PUBLICPRESS_WORDMARK_SVG}</h1>` +
  `<p>${PUBLICPRESS_HOLDING_TEXT}</p>` +
  '<footer>' +
  `<p>Report abuse: <a href='mailto:${PUBLICPRESS_ABUSE_CONTACT}'>${PUBLICPRESS_ABUSE_CONTACT}</a></p>` +
  '<p>Operated by BRANCHLEFT LTD</p>' +
  '</footer>' +
  '</main></body></html>';
