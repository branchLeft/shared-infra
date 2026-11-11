# The publicpress.co.uk site

Pointer target for `build.ts` and `config.ts`. The edge renders this site into the
committed Caddyfile; `render.md` ("`staticBlock`", "`staticSiteCsp`") covers the rendering,
this file covers where the pages come from.

## Layout

| Path                     | What it is                                                                                                                                       |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `config.ts`              | The launch date, the entry plan's name, the register address, subject and body, and the list of pages. The one home of each.                     |
| `src/journey.html`       | The page served at `/`, from `<title>` to the end of the body. The head's title, description and canonical link are read from its first lines.   |
| `src/ghost-hosting.html` | The page served at `/ghost-hosting`, same shape.                                                                                                 |
| `src/*.html`, `*.css`    | Partials the two pages share (prices, pop-ups, footer, script, the animation, the register block) and the stylesheets, one per page plus shared. |
| `assets/`                | Fonts and the headshot, embedded as `data:` URIs at build time.                                                                                  |
| `build.ts`               | Reads all of the above and returns each page as a complete document.                                                                             |
| `dist/`                  | The committed build, one file per page. `render.test.ts` fails when it differs from what the sources build.                                      |

Sources carry `%%TOKEN%%` where a value belongs (`%%DATE%%`, `%%ENTRY%%`, `%%REGISTER_ADDRESS%%`,
`%%REGISTER_MAILTO%%`, the marks, the fonts, the partials). `build.ts` substitutes until none is
left and throws on an unknown token. The prose is the owner's: change a sentence in `src/`, nothing
else.

## Changing something

1. Edit `config.ts` (a value used in several places) or a file in `src/`.
2. Run `pnpm run render` in `hetzner/`. It rewrites `dist/`, `stack/caddy/Caddyfile` and
   `validation/Caddyfile.enforcing`; the host receives only the Caddyfile.
3. Commit all of them. `pnpm run test` fails if any is stale.

## What a page must satisfy

The edge's policy admits the page's own `<script>` and `<style>` elements by SHA-256 and
fetches nothing, so:

- No `style=""` attribute and no `on...=` handler. Put a rule in a stylesheet and use a class.
  Script may set `element.style.x`; the policy governs the attribute in markup only.
- Every script and style element is a bare `<script>` or `<style>`, and a stylesheet contains
  no `<`. `staticSiteCsp` throws on a block it cannot hash.
- Images and fonts are `data:` URIs. A form cannot post (`form-action 'none'`), and script cannot
  fetch (`connect-src 'none'`), so "Register interest" is a `mailto:` link.
- No `{name}` shape in a page: Caddy substitutes known placeholders in a response body.

## Pop-up addresses

Each pop-up's bar shows its path (`/what-is-ghost`, `/included`, `/your-site`, `/moving`,
`/how-its-built`, `/why`, `/everyone`, `/about`). The server answers all of them, and every
unknown path, with the journey page; the script reads the path and opens that pop-up. Opening one
pushes its path, closing returns to the page's own path (its canonical link), Back closes it, and
`#hash` links, including the sources in the "What is Ghost?" pop-up, still work. A pop-up opened
from the Ghost hosting page shows its path on the journey page's address, so reloading it lands on
the journey page with the pop-up open.

## The register address

`REGISTER_ADDRESS` in `config.ts` is the mailbox. The link's subject and body come from the same
file. The address is also shown as selectable text beside the button.

## Fonts and image

Embedded as `data:` URIs because the pages fetch nothing; the policy admits `font-src data:`
for that reason.

- `assets/jost.woff2`: `@fontsource-variable/jost@5.3.0`, latin-subset variable woff2
  (`jost-latin-wght-normal.woff2`), SIL OFL 1.1; the same file `@branchleft/brand-publicpress`
  embeds. SHA-256 `7726a5cd6f3c0e876c028ea2a643d45f7aad4b0f164b70966c669f4a4668f4b9`.
- `assets/syne-branchleft.woff2`: the branchLeft wordmark face, the ten glyphs of "branchLeft"
  subset from `@branchleft/brand-branchleft@0.3.0`'s `Syne-VariableFont_wght.woff2` (source SHA-256
  `8d0710f0bc5d9a7899376e97edc680fe66474e5a6a4b6b475f55af13679521ff`) with
  `uv run --with fonttools --with brotli pyftsubset <source> --text=branchLeft --flavor=woff2`.
  SIL OFL 1.1. SHA-256 `9fed958f9efb48206e59d2c42f0ee2b93889f584922ba488fb9739cbe3075560`.
- `assets/courier-prime.woff2`: `CourierPrime-Regular.woff2` from `components`,
  `packages/brand-publicpress/src/styles/fonts/CourierPrime/`, SIL OFL 1.1. SHA-256
  `f09844e1f4fe9e67df2cc77474519e68756d559b4648278b9dd4f03c8ac9c31f`.
- `assets/headshot-320.webp`: the 320px headshot published in the `website` repository's
  `public/people/`. SHA-256 `a5a5d2e0d6208ef1ced8c698fa1399b67ec438969a4afaaf610f1eef9473ecd9`.

The wordmark, the branchLeft mark and the favicon are rendered from `@branchleft/components` at
build time, so the geometry is never copied here.

## Why the sources are not formatted

`.prettierignore` lists `src/` and `dist/`: a formatter would re-wrap the owner's prose and
whitespace-sensitive inline markup, and `dist/` is generated.
