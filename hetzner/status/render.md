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

Regenerate with `npm run render` in `hetzner/`. `render.test.ts` fails if a committed file
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
and the condition `[STATUS] < 300`, the same pass rule as the blackbox `http_2xx` module.
Gatus follows redirects, as the blackbox module does, so a redirect source is judged by where
it ends.

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
