# Hugo and Zola, built the same way

Two pages, Overview and How it works, written for a technical newcomer who meets this repository
cold, built once with Hugo and once with Zola. Each lives on its own branch (`cloud-1c/shared-infra-3030-hugo`
and `cloud-1c/shared-infra-3030-zola`) with the same content, the same hand-written stylesheet
(`static/site.css`) and the same diagram data (`data/diagram.json`). Only the generator's own files
differ. This file is the same on both branches.

## What was built

|                                   | Hugo                                                               | Zola                                                               |
| --------------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------ |
| Version                           | 0.139.3 (standard release, not the extended one)                   | 0.19.2                                                             |
| Binary                            | `hugo_0.139.3_linux-amd64.tar.gz`, 16.8 MB                         | `zola-v0.19.2-x86_64-unknown-linux-gnu.tar.gz`, 11.3 MB            |
| sha256 of the archive             | `fcf9265c4d72f713a07c73b7fcf32f4aa31a1d9cf13444e6d22ae1926d527652` | `0798e69b86c628ddcb264ebd86c8cc8dce7670b9049060bf94faa73f6857cd9c` |
| Theme                             | none; `layouts/` written by hand                                   | none; `templates/` written by hand                                 |
| Source files (without the binary) | 14 files, about 190 lines                                          | 12 files, about 170 lines                                          |

`build.sh` fetches the pinned archive, checks its sha256, unpacks it and builds. Built output goes
to `docs/site/public/` and is not committed.

## The checklist

| Check                                              | Hugo                                                                                                                                                                                                | Zola                                                                                                                                                                                                                                                                             |
| -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Zero third-party requests in the built output      | Pass. `grep -rEo 'https?://' public` finds nothing. A headless browser loading the page made requests to its own origin only.                                                                       | Pass for the HTML: the same grep over `*.html` finds nothing, and the browser made requests to its own origin only. The same grep over all of `public/` finds one string, `http://weixsong.github.io`, a comment inside the bundled `elasticlunr.min.js`. It is never requested. |
| Client-side search, no third-party service         | Pass, by hand. The build writes `index.json` (6 KB) from a template, and `search.js` (about 35 lines, written here) filters it in the page. It matches substrings only: no ranking and no stemming. | Pass, built in. `build_search_index = true` writes `search_index.en.js` (39 KB) and ships `elasticlunr.min.js` (18 KB, a bundled third-party library under its own licence). Ranked, stemmed results. `search.js` (about 25 lines, written here) is the glue.                    |
| One diagram rendered to SVG at build time          | Pass, with no native diagram engine. A shortcode (`layouts/shortcodes/diagram.html`) draws boxes and arrows as inline SVG from `data/diagram.json` while the site is built.                         | Pass, the same way, with a Tera shortcode (`templates/shortcodes/diagram.html`) and `load_data`. Neither tool draws a diagram from a text description (Mermaid, Graphviz) without an outside program; both can template SVG from data.                                           |
| Light and dark themes                              | Pass, in CSS alone: custom properties and `prefers-color-scheme`. The headless browser reported the dark background in dark mode. No script, no toggle.                                             | Pass, the same stylesheet and the same result.                                                                                                                                                                                                                                   |
| Builds with no network after the binary is fetched | Pass. `unshare -rn sh build.sh --offline` (a network namespace with no interface) built the site.                                                                                                   | Pass, the same command.                                                                                                                                                                                                                                                          |
| Build time                                         | 42 ms wall, 41 ms CPU, mean of ten builds on this machine (two small pages).                                                                                                                        | 25 ms wall, 13 ms CPU, mean of ten builds. Both are far below anything that matters at this size; the difference says nothing about a large site.                                                                                                                                |
| Dependency count                                   | 0 modules, 0 themes, 0 packages. One binary.                                                                                                                                                        | 0 themes, 0 packages. One binary.                                                                                                                                                                                                                                                |
| No client JavaScript needed to read the pages      | Pass. The pages are complete HTML; the only script is the optional search, and its form is hidden until it runs.                                                                                    | Pass, the same.                                                                                                                                                                                                                                                                  |

## Differences that decided nothing but are worth knowing

- **URLs.** Hugo can write relative URLs (`relativeURLs = true`), so the output works from any
  directory, including a GitHub Pages project path, without a setting. Zola writes URLs from
  `base_url`; this build sets it to `/`, which works at a domain root. Serving from a project path
  means setting `base_url` to that path.
- **Embedded services.** Hugo has built-in shortcodes for analytics, comments and embedded media,
  and a `privacy` and `services` configuration. This build turns each of them off explicitly
  (`hugo.toml`). Zola has none of these built in, so there is nothing to turn off; its config
  carries no feed, no sitemap and no highlighting.
- **Extra output.** Both would write a feed, a sitemap and a robots file by default; this build
  turns them off in both, so the only files are the pages, the stylesheet, the search files and,
  for Zola, a `404.html`.
- **Binary size.** Zola's archive is two thirds the size of Hugo's.
- **Search quality.** Zola's search is better out of the box and is not code anyone here wrote;
  Hugo's is ours to maintain, and trivial.

## Reading of the result

Both tools pass every item on the list. Zola gets search for nothing and ships a library to do it;
Hugo needs about 35 lines of script to match substrings and ships nothing it did not write.
Hugo's relative URLs are the better fit for a Pages project path. If the repository wants ranked
search with no code to own, choose Zola; if it wants the smallest output with no bundled
third-party file and relative URLs, choose Hugo. The measured difference in speed is not a reason
either way.
