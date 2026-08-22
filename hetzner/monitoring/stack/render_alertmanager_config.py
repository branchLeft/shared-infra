#!/usr/bin/env python3
"""Writes `alertmanager.yml` from `alertmanager.yml.tmpl` and the four secrets
in `/etc/branchleft/monitoring.env`.

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
}

TEMPLATE_NAME = "alertmanager.yml.tmpl"
OUTPUT_NAME = "alertmanager.yml"


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


def main(argv: list[str]) -> int:
    del argv
    alertmanager_dir = pathlib.Path(__file__).resolve().parent / "alertmanager"
    template_path = alertmanager_dir / TEMPLATE_NAME
    output_path = alertmanager_dir / OUTPUT_NAME

    try:
        rendered = render(template_path.read_text(), dict(os.environ))
    except ValueError as exc:
        print(f"render_alertmanager_config: {exc}", file=sys.stderr)
        return 1

    # 0600: the output carries the SMTP password and the heartbeat URL in
    # plaintext, unlike the template beside it.
    output_path.write_text(rendered)
    output_path.chmod(0o600)
    print(f"render_alertmanager_config: wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
