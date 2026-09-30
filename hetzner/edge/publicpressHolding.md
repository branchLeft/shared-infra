# `publicpressHolding.ts` notes

CMT-3 pointer target: the narrative moved out of that file's comments lives
here. Update this doc, not a long comment block, when any of the following
changes.

## File layout

`render.ts` serves this one-page holding site at `publicpress.co.uk`. It is
kept separate from the Caddy-rendering logic there on purpose: the owner's
copy drops in as a change to `PUBLICPRESS_HOLDING_TEXT` below, and nobody
editing that sentence needs to read or touch the renderer.

The assembled page is a single line with no line breaks and single-quoted
HTML attributes throughout. `render.ts` embeds it inside a double-quoted
Caddyfile token, so a double quote anywhere in the page would need escaping
that a future hand-edit of the prose could easily get wrong -- avoiding the
character avoids the escaping question entirely.

## The branchLeft credit

The owner's own copy in `PUBLICPRESS_HOLDING_TEXT` lives in the source file;
change it there only. Keep attributes single-quoted and never use a double
quote (see "File layout" above).

The branchLeft credit is the brand's own logo mark (inlined SVG, same
treatment as the PublicPress marks below it) plus the word "branchLeft" set
in the brand's own wordmark face (Syne, weight 500 -- see "Syne (branchLeft
wordmark)" below). Both sit inside one link, `.bl-credit` in the stylesheet.

## Jost (body/display face)

Self-hosted as a base64 `data:` URI -- this page fetches nothing, so a
linked font file is not an option (see the CSP note on `staticSiteCsp` in
`render.ts`, which admits `font-src data:` only because of this constant).

Same source and pin as `@branchleft/brand-publicpress`'s own
`styles/fonts.css`: `@fontsource-variable/jost@5.3.0`'s latin-subset variable
woff2 (`jost-latin-wght-normal.woff2`), SIL OFL 1.1 -- see that package's
`styles/fonts/Jost/OFL.txt` for the licence text.

Regular style only; this page sets no italic text. Weight range 100-900
matches the variable font file itself, even though the page only ever
requests 400 -- declaring less would just make the browser fake a weight it
already has.

## Syne (branchLeft wordmark)

Embeds the branchLeft brand's own wordmark face for exactly the word
"branchLeft" inside the `.bl-credit` link, matching `.bl-wordmark` in
`@branchleft/components` `packages/brand-branchleft/src/styles` (Syne,
weight 500).

Source: `components` repo, `packages/brand-branchleft/src/styles/fonts/Syne/Syne-VariableFont_wght.woff2`
(package `@branchleft/brand-branchleft@0.3.0`), the same file
`@branchleft/brand-branchleft`'s own `fonts.css` embeds. SHA-256 of that
source file: `8d0710f0bc5d9a7899376e97edc680fe66474e5a6a4b6b475f55af13679521ff`.

Subsetted to only the ten glyphs "branchLeft" needs, with `pyftsubset` (via
`uv run --with fonttools --with brotli`):

```
uv run --with fonttools --with brotli pyftsubset Syne-VariableFont_wght.woff2 \
  --text=branchLeft --flavor=woff2 --output-file=syne-branchleft-subset.woff2
```

Result: 2,956 bytes (down from the source's 38,713 bytes), embedded here as
a base64 `data:` URI, same reasoning as Jost above -- this page fetches
nothing. SIL OFL 1.1, same licence family as Jost -- see the source file's
sibling `OFL.txt` in the `components` repo for the licence text. Variable
font, so `font-weight: 400 500` is declared (matching `fonts.css`'s own
range) rather than a single value, and only weight 500 is ever requested.
