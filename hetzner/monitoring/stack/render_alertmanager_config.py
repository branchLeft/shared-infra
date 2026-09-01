#!/usr/bin/env python3
"""Writes the monitoring stack's two secret-bearing files from
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
"""

from __future__ import annotations

import os
import pathlib
import sys

# Maps the template's placeholder token to the environment variable it comes
# from. `RUNBOOK-monitoring.md` is the authority on where each value
# originates; this dict is only the wiring between the two names.
PLACEHOLDERS: dict[str, str] = {
    "__SMTP_USERNAME__": "SMTP_USERNAME",
    "__SMTP_PASSWORD__": "SMTP_PASSWORD",
    "__HEALTHCHECKS_PING_URL__": "HEALTHCHECKS_PING_URL",
    "__ALERT_RECIPIENT_EMAIL__": "ALERT_RECIPIENT_EMAIL",
    "__MAILHOST_PING_URL__": "MAILHOST_PING_URL",
}

TEMPLATE_NAME = "alertmanager.yml.tmpl"
OUTPUT_NAME = "alertmanager.yml"

# Prometheus has no `{env.X}` of its own either, and `prometheus.yml` is
# committed to a public repository, so the credential reaches it as a
# `basic_auth.password_file` written here beside the config that names it.
# `render.ts`'s STALWART_METRICS_PASSWORD_FILE is the container-side path this
# file is mounted at; these two have to agree.
PROMETHEUS_PASSWORD_VAR = "STALWART_PROMETHEUS_SECRET"
PROMETHEUS_PASSWORD_PATH = ("prometheus", "mx1-metrics-password")


def render(template: str, env: dict[str, str]) -> str:
    """Pure substitution -- no I/O, so this is what the unit tests exercise."""
    missing = [var for var in PLACEHOLDERS.values() if not env.get(var)]
    if missing:
        raise ValueError(
            "missing required environment variable(s): "
            + ", ".join(missing)
            + " -- set them in /etc/branchleft/monitoring.env"
        )
    rendered = template
    for placeholder, var in PLACEHOLDERS.items():
        rendered = rendered.replace(placeholder, env[var])
    return rendered


# The image runs as `nobody`, and a bind mount is read as the container-side
# user regardless of who wrote the file on the host. A root-owned 0600 file is
# therefore unreadable to the one process it exists for, and Alertmanager exits
# with "error loading configuration file: ... permission denied" on every start.
#
# Ownership moves to that uid rather than the mode widening: the file holds an
# SMTP password in plaintext, and 0644 would expose it to every other account
# on the host, including the CI deploy account.
#
# Only when running as root -- which is how the systemd ExecStartPre invokes
# this. Under CI, or a local render, there is no container to read the file and
# no privilege to chown with.
ALERTMANAGER_UID = int(os.environ.get("ALERTMANAGER_UID", "65534"))

# Same reasoning and, today, the same uid: prom/prometheus also runs as
# `nobody`. Kept as its own constant rather than reusing the one above,
# because the two images are pinned and upgraded independently and a shared
# constant would silently carry one image's uid onto the other.
PROMETHEUS_UID = int(os.environ.get("PROMETHEUS_UID", "65534"))


def write_prometheus_password(stack_dir: pathlib.Path, env: dict[str, str]) -> pathlib.Path | None:
    """Writes the mx1 scrape credential, or removes it when there is none.

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
    """
    path = stack_dir.joinpath(*PROMETHEUS_PASSWORD_PATH)
    # Docker creates an empty *directory* at a bind-mount source that does not
    # exist, so a `docker compose up` run by hand before this script has ever
    # written the file leaves one here. Clearing it is what keeps that mistake
    # self-healing: without this, every later run raises IsADirectoryError out
    # of the systemd ExecStartPre and the monitoring stack stops starting at
    # all -- turning a missing scrape credential into a total loss of alerting.
    if path.is_dir() and not path.is_symlink():
        try:
            path.rmdir()
        except OSError as exc:
            print(
                f"render_alertmanager_config: {path} is a non-empty directory "
                f"and was left alone ({exc}) -- the stalwart scrape will report "
                "down until it is removed by hand",
                file=sys.stderr,
            )
            return None

    secret = env.get(PROMETHEUS_PASSWORD_VAR)
    if not secret:
        path.unlink(missing_ok=True)
        print(
            f"render_alertmanager_config: {PROMETHEUS_PASSWORD_VAR} is unset -- "
            f"removed {path}; the stalwart scrape target will report down "
            "until it is set in /etc/branchleft/monitoring.env",
            file=sys.stderr,
        )
        return None

    # No trailing newline: Prometheus sends the file's bytes verbatim as the
    # password, so a newline here authenticates as a different string than the
    # one in monitoring.env and the endpoint answers 401.
    path.write_text(secret)
    path.chmod(0o600)
    if os.geteuid() == 0:
        os.chown(path, PROMETHEUS_UID, PROMETHEUS_UID)
    print(f"render_alertmanager_config: wrote {path}")
    return path


def main(argv: list[str]) -> int:
    del argv
    stack_dir = pathlib.Path(__file__).resolve().parent
    alertmanager_dir = stack_dir / "alertmanager"
    template_path = alertmanager_dir / TEMPLATE_NAME
    output_path = alertmanager_dir / OUTPUT_NAME

    try:
        rendered = render(template_path.read_text(), dict(os.environ))
    except ValueError as exc:
        print(f"render_alertmanager_config: {exc}", file=sys.stderr)
        return 1

    # 0600: the output carries the SMTP password and the heartbeat URL in
    # plaintext, unlike the template beside it. The mode alone is not enough --
    # see ALERTMANAGER_UID.
    output_path.write_text(rendered)
    output_path.chmod(0o600)
    if os.geteuid() == 0:
        os.chown(output_path, ALERTMANAGER_UID, ALERTMANAGER_UID)
    print(f"render_alertmanager_config: wrote {output_path}")

    write_prometheus_password(stack_dir, dict(os.environ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
