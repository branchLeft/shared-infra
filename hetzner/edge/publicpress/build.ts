/**
 * Assembles the publicpress.co.uk pages from `src/` and `assets/`.
 * Layout, the token syntax and what each step guards: `site.md`.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { Logo, PublicPressLogo, PublicPressWordmark } from '@branchleft/components';
import { createElement } from 'react';
import type { ReactElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

import {
  ENTRY_TIER,
  LAUNCH_DATE,
  PAGES,
  REGISTER_ADDRESS,
  REGISTER_BODY,
  REGISTER_SUBJECT,
} from './config';

/** One page of a static site: the path it answers on and the whole document. */
export interface StaticPage {
  path: string;
  html: string;
}

const SRC = join(__dirname, 'src');
const ASSETS = join(__dirname, 'assets');

const source = (name: string): string => readFileSync(join(SRC, name), 'utf8');
/** An asset kept as base64 text (`<name>.b64`), as a `data:` URI. */
const dataUri = (file: string, type: string): string =>
  `data:${type};base64,${readFileSync(join(ASSETS, `${file}.b64`), 'utf8').trim()}`;

/** A mark from `@branchleft/components` as inline markup in single-quoted attributes. */
function markupOf(element: ReactElement): string {
  const markup = renderToStaticMarkup(element).replace(/ style="[^"]*"/, '');
  if (markup.includes("'")) {
    throw new Error('a mark carries a single quote, which the quote swap below would corrupt');
  }
  return markup.replaceAll('"', "'");
}

const escapeAttribute = (value: string): string =>
  value.replaceAll('&', '&amp;').replaceAll('"', '&quot;').replaceAll('<', '&lt;');

/** `mailto:` link with the subject and body pre-filled; `&` separators are HTML-escaped. */
export function registerMailto(address: string, subject: string, body: string): string {
  if (!/^[^\s@?&<>"']+@[^\s@?&<>"']+$/.test(address)) {
    throw new Error(`register address ${address} is not a plain email address`);
  }
  const query = `subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
  return escapeAttribute(`mailto:${address}?${query}`);
}

function tokens(): Record<string, string> {
  const wordmark = markupOf(createElement(PublicPressWordmark));
  const blmark = markupOf(
    createElement(Logo, { width: '20', height: '20', 'aria-hidden': 'true' })
  );
  const blmarkLarge = blmark
    .replace(" width='20' height='20'", '')
    .replace(" aria-hidden='true'", " role='img' aria-label='branchLeft logo'");
  const fonts: Record<string, string> = {
    JOST: dataUri('jost.woff2', 'font/woff2'),
    COURIER: dataUri('courier-prime.woff2', 'font/woff2'),
    SYNE: dataUri('syne-branchleft.woff2', 'font/woff2'),
  };
  const partial = (name: string): string => source(name).trimEnd();
  return {
    ...fonts,
    DATE: LAUNCH_DATE,
    ENTRY: ENTRY_TIER,
    REGISTER_ADDRESS: escapeAttribute(REGISTER_ADDRESS),
    REGISTER_MAILTO: registerMailto(REGISTER_ADDRESS, REGISTER_SUBJECT, REGISTER_BODY),
    WORDMARK: wordmark,
    BLMARK: blmark,
    BLMARK_LARGE: blmarkLarge,
    HEADSHOT: dataUri('headshot-320.webp', 'image/webp'),
    GHOSTANIM: partial('ghost-anim.html'),
    PRICES: partial('prices.html'),
    DIALOGS: partial('dialogs.html'),
    MOVING: partial('moving.html'),
    PPFOOTER: partial('footer.html'),
    JSCRIPT: partial('script.html'),
    REGISTER: partial('register.html'),
  };
}

/** Substitutes `%%TOKEN%%` until none is left; an unknown or unused-by-nesting token throws. */
function substitute(text: string, values: Record<string, string>): string {
  let out = text;
  for (let pass = 0; pass < 3; pass += 1) {
    out = out.replace(/%%([A-Z_]+)%%/g, (whole, key: string) => values[key] ?? whole);
  }
  const left = out.match(/%%[A-Z_]+%%/g);
  if (left !== null) throw new Error(`unfilled page tokens: ${left.join(', ')}`);
  return out;
}

function headValue(head: string, pattern: RegExp, what: string): string {
  const value = pattern.exec(head)?.[1];
  if (value === undefined) throw new Error(`a page template's head has no ${what}`);
  return value;
}

function buildPage(page: (typeof PAGES)[number], values: Record<string, string>): StaticPage {
  const template = source(`${page.template}.html`);
  const split = template.indexOf('<header');
  if (split < 0) throw new Error(`${page.template}.html has no <header>`);
  const head = template.slice(0, split).trim();
  const body = template.slice(split);

  const title = headValue(head, /<title>([^<]*)<\/title>/, 'title');
  const description = headValue(head, /<meta name="description" content="([^"]*)">/, 'description');
  const canonical = headValue(head, /<link rel="canonical" href="([^"]*)">/, 'canonical link');
  const css = substitute(
    [source('site.css'), ...page.stylesheets.map(source)].join('\n'),
    values
  ).trimEnd();
  if (css.includes('<')) throw new Error(`${page.template}: a stylesheet contains "<"`);

  const favicon = `data:image/svg+xml,${encodeURIComponent(markupOf(createElement(PublicPressLogo))).replaceAll("'", '%27')}`;
  const document = [
    "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
    "<meta name='viewport' content='width=device-width, initial-scale=1'>",
    `<title>${title}</title>`,
    `<meta name="description" content="${description}">`,
    `<link rel="canonical" href="${canonical}">`,
    `<meta property="og:title" content="${title}">`,
    `<meta property="og:description" content="${description}">`,
    `<meta property="og:url" content="${canonical}">`,
    '<meta property="og:type" content="website">',
    '<meta name="twitter:card" content="summary">',
    `<link rel='icon' type='image/svg+xml' href='${favicon}'>`,
    `<style>\n${css}\n</style></head><body>`,
    substitute(body, values).trimEnd(),
    '</body></html>',
  ].join('\n');
  return { path: page.path, html: document };
}

/** Every page of the site, built from the committed sources. */
export function buildPublicpressPages(): StaticPage[] {
  const values = tokens();
  return PAGES.map((page) => buildPage(page, values));
}

/** The file a page is committed to under `dist/`. */
export function distName(page: StaticPage): string {
  return page.path === '/' ? 'index.html' : `${page.path.slice(1)}.html`;
}
