# check_page_cadence.py

Proves, against a real Alertmanager, that a further edge ban reaches the phone
within about a minute of being raised even when an earlier ban has already
paged, and that the tenant-scoped pages are no noisier for it.

## Why `amtool` is not enough

`amtool config routes test` says which receiver an alert reaches. It cannot
say when: a route's `group_interval` is not in its output. A new alert that
joins a group which has already notified waits for the next group interval, and
the page route's estate-wide alerts (`EdgeBanIssued` has no `tenant` label)
all share one group, so with the root's `group_interval: 1h` a second ban could
wait an hour behind the first, and a ban that ended sooner never paged. The
route test in CI would pass the whole time. Only a running Alertmanager shows
the wait.

## What it does

1. Takes the rendered `alertmanager.yml` and points its one ntfy receiver at a
   stand-in webhook on the runner (`retarget_pager` refuses a config that does
   not name the ntfy URL exactly once). Nothing else in the config changes, so
   the routes and intervals under test are the committed ones.
2. Starts the pinned Alertmanager image on it and posts an `EdgeBanIssued`
   alert and a `TenantFailedUnsafe` alert for one tenant. Both page after the
   30s `group_wait`.
3. Posts a second `EdgeBanIssued` alert (another scenario) and a second alert
   for the same tenant.
4. Passes only if the second ban reaches the stand-in within 90s, and the
   second tenant alert has not reached it when the second ban has. The
   interval is 1m, so the ban lands about a minute after it is raised; the
   tenant group keeps the root's 1h and so stays quiet.

It takes about 100s and needs a local Docker daemon. `judge` and
`retarget_pager` are pure and are covered by `test_check_page_cadence.py`; the
timing itself runs as its own CI step, `Test how soon a further page reaches
the phone`.

## What the bound does not cover

A second ban by a scenario that is already firing is not a new alert: the
alert is the same series with a higher count, and Alertmanager notifies again
only at the repeat interval. `render.ts` says so beside the rule. The cadence
here is for a ban by a scenario that is not yet firing.

## Sabotage

Each of these makes the check fail, and restoring the config makes it pass:
the child route's `group_interval` set to `1h`; the child route removed
(the page route as it was, inheriting the root's hour); the page route's own
`group_interval` set to `1m` (the tenant group made noisy).
