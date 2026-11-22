# Status page renderer

`render.ts` writes the configuration of the status page: two files in `stack/`, both
committed. The `status_page` role (`ansible/roles/status_page/`) copies them onto the
control-plane host, where Gatus reads them. This document holds the reasoning that the code
comments leave out.

## What it renders

| File                | Read by              | Holds                                                         |
| ------------------- | -------------------- | ------------------------------------------------------------- |
| `stack/config.yaml` | the `gatus` service  | one probe per registry hostname, the TEST probe, sqlite       |
| `stack/target.yaml` | `status-test-target` | one probe of itself, because Gatus refuses to start with none |

Regenerate with `pnpm run render` in `hetzner/`. `render.test.ts` fails if a committed file
differs from the renderer's output, and also if Prettier would rewrite it, so the files need
no entry in `.prettierignore`.

## One home for each fact

- The hostname list is `sites.ts`, read through `blackboxTargets` in
  `../monitoring/render.ts`. The status page and the blackbox probes therefore watch the
  same set, and no target is written by hand here.
- The TEST component is `STATUS_TEST_COMPONENT` in `../monitoring/statusIncidents.ts`. Only
  its probe URL is replaced here, with the compose service that can be stopped on demand;
  the rule's own placeholder address never resolves and is not used by the page.
- The Compose file is the role's template, `ansible/roles/status_page/templates/compose.yml.j2`.
  The test reads it to check the TEST service name and that exactly one port is published.

## How the probe-to-incident rule is met

`statusIncidents.ts` opens an incident on the first failed probe and resolves it on the first
good one, with probes one interval apart. Gatus records an event at the first changed result
of an endpoint, so the page needs no alert threshold: a failure threshold would delay the
incident, and a success threshold would delay the resolution. The renderer sets neither, and
no `alerting` block, and the test pins both.

Every probe uses the interval of 60 seconds that the rule's tests assume, a client timeout,
and two conditions: `[CONNECTED] == true` and `[STATUS] < 300`, the second being the same
status rule as the blackbox `http_2xx` module. Gatus follows redirects, as the blackbox module
does, so a redirect source is judged by where it ends.

The first condition is not optional. In Gatus v5.37.0 a probe that cannot connect (DNS
failure, refused connection, timeout) records only an error and leaves the status at 0, and
`[STATUS] < 300` passes 0. Without `[CONNECTED] == true` every outage reads as success. For
HTTP, `[CONNECTED]` is true only when a status code above 0 came back. `render.test.ts` fails
if any probe, the TEST target's own probe included, lacks the condition.

## Post-mortems

A post-mortem is a markdown file in `postmortems/`, written by a person and merged by pull
request. No agent writes or edits one. The file name is lower-case words joined by `-`, ending
`.md`, and it opens with a front-matter block:

```text
---
title: One line of plain text, no [ ] ` < > or backslash
resolved: 2026-12-01T10:42:00Z
---
```

`postmortems.ts` reads the files committed at `HEAD` (`git ls-tree` and `git show`), never the
working tree, so a file that is only written, only staged, or on a branch that has not landed
does not appear. A file with no `resolved` line is a draft of an incident still open and is
skipped. A file that cannot be read (bad name, no title, a `resolved` that is not a UTC time)
fails `pnpm test`, so a mistake is loud, not a silent omission. Each remaining file becomes one
archived `announcements:` entry of type `operational`, stamped with `resolved`, whose message
links to the file on `main` of the public repository. With no file, the key is absent.

Limit: Gatus gives its incident list no hook to attach a link to, so the link sits in the page's
Past Announcements section at the time the incident resolved, not inside the component's own
incident list.

## What is not set, on purpose

- No `ui` block. Gatus defaults apply, so no wording is written here.
- No alerting and no secret. The Prometheus and Alertmanager path stays the pager.
- No staleness state. The page is served by the checker itself, so a stopped Gatus means no
  page, not a green one, and the rule in `statusStaleness.ts` has nothing to guard.

## Limits

The probes run from the control-plane host, which has no public address and reaches the
internet through the edge host's NAT. The page therefore reports what is visible through that
path, and it cannot answer while the edge host is stopped. Probing from a vantage that does
not depend on the edge host is a later change.
