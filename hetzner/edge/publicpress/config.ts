/**
 * The three values that appear in more than one place on the publicpress.co.uk
 * pages and so are set here once. The page sources carry `%%DATE%%`,
 * `%%ENTRY%%` and `%%REGISTER_ADDRESS%%` where each belongs; `build.ts`
 * substitutes them. Layout and the rest of the notes: `site.md`.
 */

/** The latest date before which PublicPress launches, as page markup. */
export const LAUNCH_DATE = '1<sup>st</sup> March 2027';

/** The name of the entry plan, used in the prices, the mail tables and the support copy. */
export const ENTRY_TIER = 'Essentials';

/** Where "Register interest" sends the visitor's email. The only place the address is set. */
export const REGISTER_ADDRESS = 'info@branchleft.co.uk';

/** The subject of the pre-filled email. */
export const REGISTER_SUBJECT = 'Register interest in PublicPress';

/** The body of the pre-filled email: what the visitor is asked to say. */
export const REGISTER_BODY = [
  'Name:',
  '',
  'Outlet or organisation:',
  '',
  'What do you publish on today?',
  '',
].join('\r\n');

/**
 * The pages, in the order served. The page at `/` is also the answer for every
 * path no other page claims, which is what lets the pop-up addresses
 * (`/included`, `/about`, ...) serve it without being listed.
 */
export const PAGES: ReadonlyArray<{
  path: string;
  template: string;
  stylesheets: readonly string[];
}> = [
  { path: '/', template: 'journey', stylesheets: ['journey.css'] },
  {
    path: '/ghost-hosting',
    template: 'ghost-hosting',
    stylesheets: ['journey.css', 'ghost-hosting.css'],
  },
];
