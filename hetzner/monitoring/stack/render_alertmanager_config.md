# render_alertmanager_config.py

Writes the monitoring stack's two secret-bearing files from
`/etc/branchleft/monitoring.env`: `alertmanager.yml`, substituted from
`alertmanager.yml.tmpl`, and `prometheus/mx1-metrics-password`, the basic-auth
password Prometheus presents to Stalwart's exporter on mx1.

The filename is narrower than the remit. It stays as it is because
`../systemd/monitoring.override.conf` names it in an `ExecStartPre` that is
installed on the host, so a rename is a hand-delivered systemd change plus a
`daemon-reload` bought for nothing but tidiness.

Alertmanager's config format has no way to read an environment variable from
inside itself -- unlike Caddy's `{env.X}`, which is what lets the edge stack
keep its two secrets out of the committed tree without this step. Plain
string replacement rather than a templating library or `sed`/`envsubst`: a
password or a webhook URL can contain `/`, `&` or `$`, every one of which is
significant to a regex engine or a shell, and a literal `str.replace` is the
only substitution here that cannot be tripped by the value it is
substituting.

Run again after any secret rotation, then restart the monitoring stack to
pick up the change -- `branchleft-compose@monitoring`'s systemd drop-in also
runs this once before every start, so a fresh boot never serves a stale
render.

## Why the rendered file's mode and owner are both asserted

The rendered file must be readable by the process it exists for.

Alertmanager reads it through a bind mount, which is read as the
container-side user (`nobody`) regardless of who wrote the file on the host.
A root-owned 0600 file is unreadable to it, and Alertmanager exits with
`error loading configuration file: ... permission denied` on every start --
while the unit still reports success, because `docker compose up -d --wait`
does not catch a container that starts and then dies.

So the mode must stay 0600 -- the file holds an SMTP password in plaintext,
and 0644 would expose it to every other account on the host, including the
CI deploy account -- _and_ ownership must move to that uid. Both halves are
asserted, because either alone leaves the file unreadable or the password
over-exposed.

## write_prometheus_password

Writes the mx1 scrape credential, or removes it when there is none.

Deliberately not fatal when the variable is unset, unlike the Alertmanager
substitution above. Alertmanager cannot start at all without its config;
Prometheus starts fine without this file and simply fails that one scrape,
which `up{job="stalwart"} == 0` turns into a HostOrServiceDown page within
five minutes. Refusing to start the stack would trade one dead scrape
target for no alerting at all across the estate -- including the alert that
would have reported it.

The removal branch matters as much as the write: `/etc/branchleft/`
`monitoring.env` is the single source for this secret, so a value rotated
out of it must not leave the previous one readable on disk.

## ALERTMANAGER_UID

The image runs as `nobody`, and a bind mount is read as the container-side
user regardless of who wrote the file on the host. A root-owned 0600 file is
therefore unreadable to the one process it exists for, and Alertmanager exits
with "error loading configuration file: ... permission denied" on every start.

Ownership moves to that uid rather than the mode widening: the file holds an
SMTP password in plaintext, and 0644 would expose it to every other account
on the host, including the CI deploy account.

Only when running as root -- which is how the systemd ExecStartPre invokes
this. Under CI, or a local render, there is no container to read the file and
no privilege to chown with.
