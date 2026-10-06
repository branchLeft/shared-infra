#!/usr/bin/env python3
"""Writes the monitoring stack's secret-bearing files from
`/etc/branchleft/monitoring.env`: `alertmanager.yml`, `ntfy/server.yml` and
`prometheus/mx1-metrics-password`. Why it is a plain string replace, and why its
name is wider than its remit, is in `render_alertmanager_config.md`.
"""

from __future__ import annotations

import os
import pathlib
import re
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

# The pager's credentials are optional here: a missing or malformed one disables
# the pager with a warning and never stops the rest of monitoring, email
# included. See `ntfy_problems` and `render_alertmanager_config.md`.
NTFY_PLACEHOLDERS: dict[str, str] = {
    "__NTFY_PAGER_TOKEN__": "NTFY_PAGER_TOKEN",
    "__NTFY_WATCHER_TOKEN__": "NTFY_WATCHER_TOKEN",
    "__NTFY_OWNER_PASSWORD_HASH__": "NTFY_OWNER_PASSWORD_HASH",
    "__NTFY_MACHINE_PASSWORD_HASH__": "NTFY_MACHINE_PASSWORD_HASH",
}
NTFY_DISABLED_VALUE = "ntfy-not-configured"

# ntfy refuses a token that is not `tk_` plus 29 lowercase alphanumerics, and a
# password slot holding anything but a bcrypt hash would put a plaintext
# password in the config. Checked here so the mistake fails at render, loudly,
# instead of as an ntfy that exits at start and takes the pager with it.
NTFY_TOKEN_VARS = ("NTFY_PAGER_TOKEN", "NTFY_WATCHER_TOKEN")
NTFY_TOKEN_PATTERN = re.compile(r"tk_[a-z0-9]{29}")
NTFY_HASH_VARS = ("NTFY_OWNER_PASSWORD_HASH", "NTFY_MACHINE_PASSWORD_HASH")
NTFY_HASH_PATTERN = re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}")

TEMPLATE_NAME = "alertmanager.yml.tmpl"
OUTPUT_NAME = "alertmanager.yml"
NTFY_TEMPLATE_NAME = "server.yml.tmpl"
NTFY_OUTPUT_NAME = "server.yml"

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
    problems = ntfy_problems(env)
    ntfy_values = (
        {ph: env[var] for ph, var in NTFY_PLACEHOLDERS.items()}
        if not problems
        else {ph: NTFY_DISABLED_VALUE for ph in NTFY_PLACEHOLDERS}
    )
    rendered = template
    for placeholder, var in PLACEHOLDERS.items():
        rendered = rendered.replace(placeholder, env[var])
    for placeholder, value in ntfy_values.items():
        rendered = rendered.replace(placeholder, value)
    return rendered


def ntfy_problems(env: dict[str, str]) -> list[str]:
    """Why the pager cannot be configured, or an empty list when it can.

    Values are never echoed: only the variable names and the rule broken.
    """
    problems = [
        f"{var} is not set"
        for var in NTFY_PLACEHOLDERS.values()
        if not env.get(var)
    ]
    if problems:
        return problems
    problems = [
        f"{v} is malformed (a token is tk_ plus 29 lowercase letters or digits)"
        for v in NTFY_TOKEN_VARS
        if not NTFY_TOKEN_PATTERN.fullmatch(env[v])
    ]
    problems += [
        f"{v} is malformed (it must be a bcrypt hash from `ntfy user hash`, never the password)"
        for v in NTFY_HASH_VARS
        if not NTFY_HASH_PATTERN.fullmatch(env[v])
    ]
    if env["NTFY_PAGER_TOKEN"] == env["NTFY_WATCHER_TOKEN"]:
        problems.append("NTFY_PAGER_TOKEN and NTFY_WATCHER_TOKEN must differ")
    if env["NTFY_OWNER_PASSWORD_HASH"] == env["NTFY_MACHINE_PASSWORD_HASH"]:
        problems.append("NTFY_OWNER_PASSWORD_HASH and NTFY_MACHINE_PASSWORD_HASH must differ")
    return problems


NTFY_AUTH_KEYS = ("auth-users:", "auth-access:", "auth-tokens:")


def lock_ntfy_config(template: str) -> str:
    """The template with every user, grant and token removed.

    What is left still denies all access by default, so a pager with no
    credentials starts healthy and answers 403 to everyone: it fails closed
    rather than crash-looping or opening up.
    """
    kept: list[str] = []
    dropping = False
    for line in template.split("\n"):
        if line.startswith(NTFY_AUTH_KEYS):
            dropping = True
            continue
        if dropping and line.startswith((" ", "-")):
            continue
        dropping = False
        kept.append(line)
    return "\n".join(kept)


# The image runs as `nobody`; the rendered file moves to that uid rather than
# the mode widening. The reasoning is in `render_alertmanager_config.md`.
ALERTMANAGER_UID = int(os.environ.get("ALERTMANAGER_UID", "65534"))

# Same reasoning and, today, the same uid: prom/prometheus also runs as
# `nobody`. Kept as its own constant rather than reusing the one above,
# because the two images are pinned and upgraded independently and a shared
# constant would silently carry one image's uid onto the other.
PROMETHEUS_UID = int(os.environ.get("PROMETHEUS_UID", "65534"))


def write_prometheus_password(stack_dir: pathlib.Path, env: dict[str, str]) -> pathlib.Path | None:
    """Writes the mx1 scrape credential, or removes it when there is none.

    Deliberately not fatal when unset; see `render_alertmanager_config.md`.
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

    # ntfy runs as root inside its container, so a root-owned 0600 file is
    # readable by the one process it exists for and by nothing else: no chown.
    ntfy_dir = stack_dir / "ntfy"
    ntfy_template = (ntfy_dir / NTFY_TEMPLATE_NAME).read_text()
    problems = ntfy_problems(dict(os.environ))
    if problems:
        print(
            "render_alertmanager_config: WARNING the ntfy pager is DISABLED, so page alerts "
            "reach nobody (email and the rest of monitoring are unaffected): "
            + "; ".join(problems),
            file=sys.stderr,
        )
        ntfy_template = lock_ntfy_config(ntfy_template)
    ntfy_rendered = render(ntfy_template, dict(os.environ))
    ntfy_output = ntfy_dir / NTFY_OUTPUT_NAME
    # An unrendered start leaves Docker's empty directory at a bind-mount
    # source; clear it so the next start self-heals instead of failing here.
    if ntfy_output.is_dir() and not ntfy_output.is_symlink():
        ntfy_output.rmdir()
    ntfy_output.write_text(ntfy_rendered)
    ntfy_output.chmod(0o600)
    print(f"render_alertmanager_config: wrote {ntfy_output}")

    write_prometheus_password(stack_dir, dict(os.environ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
