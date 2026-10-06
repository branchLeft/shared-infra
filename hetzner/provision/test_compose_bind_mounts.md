# test_compose_bind_mounts.py

## Deploy-time bind-mount sources

Sources written on the host at deploy time instead of being committed, keyed
by stack. The exemption is the dangerous half of this check -- an entry here
is a mount nothing verifies -- so each one is pinned by exact path and needs
a reason, and the test below fails a stale entry.

`alertmanager.yml` is rendered from `alertmanager.yml.tmpl` and four secrets
by `render_alertmanager_config.py`, written 0600 on the host. Committing it
would put those secrets in a public repository, which is why the template is
what lives here.
`prometheus/mx1-metrics-password` is the same shape: the `stalwart` scrape
job's `basic_auth` password, written 0600 on the host by the same script from
`STALWART_PROMETHEUS_SECRET`. Committing it would put a live credential in a
public repository.

`ntfy/server.yml` is the same shape again: rendered from `server.yml.tmpl` by
the same script, 0600, because it carries the pager's access tokens and the
owner's password hash. `main()` clears an empty directory left at that path.

This exemption is what makes the empty-directory failure this file describes
reachable for that one path, so `write_prometheus_password()` clears such a
directory before writing -- without that, one hand-run `docker compose up`
would wedge every later `ExecStartPre` and take the whole stack down.
Prometheus itself tolerates the file being absent: it starts, that one scrape
fails, and `up{job="stalwart"} == 0` pages within five minutes.

## test_compose_bind_mounts.py

Every relative bind-mount source a stack names must exist in the repository.

A stack is deployed by rsyncing its `stack/` directory to the host, so a
`./thing:/in/container` mount resolves against what was copied. When the source
is missing, Docker does not fail: it creates an empty _directory_ at that path
and mounts it. A container expecting a file then reads a directory and dies, and
because the unit is `Type=oneshot` the restart policy turns that into a crash
loop behind a stack that reported a clean start.

`docker compose config` does not catch it -- the file is syntactically valid
with or without the source present -- and neither do the config-validation jobs,
which load rendered Caddy and Prometheus configuration and nothing else. This is
the only check that reads the mount sources, so a typo'd or deleted one is
caught here or on the host.

Sources are matched by regex rather than by parsing YAML: these files are
hand-written in one consistent style, and the suites beside this one hand-roll
their Compose parsing for the same reason -- to stay stdlib-only, so the CI job
needs no install step.
