# test_crowdsec_retention.py

This module pins three things about the edge's CrowdSec configuration. The
database flush bound in `crowdsec/config.yaml.local` must read `30d`, because
the edge keeps client addresses for 30 days and the bound has to live in our
tree. The `crowdsec` service in `compose.yml` must keep
`DISABLE_ONLINE_API: 'true'`, and the comment directly above that switch must
stay attached to it. That switch is off because online signal sharing sends
observed client addresses to a third party, a sub-processor and personal-data
decision, so nobody should flip it silently.

## Why the bound is pinned in our tree

CrowdSec's image ships its own default for how long it keeps alerts and
decisions: 7 days, or 5000 items, whichever the flush hits first. Leaving the
value to the image would mean an image bump could move the edge's retention
without a reviewed change here. The overlay sets `db_config.flush.max_age` to
`30d` explicitly, and this module fails if that value changes or disappears.

`max_items` is deliberately left at the image default, so the age bound is the
one this module pins.

## Why plain regexes over parsed YAML

Both files are hand-written in one consistent style, the same reasoning as
`test_compose_bind_mounts.md`. The module reads `key: value` lines and takes
nesting from indentation, so `max_age` only counts when it sits under `flush`
under top-level `db_config`. Comment lines are skipped before any key is read,
so a commented-out setting cannot satisfy the check. The signal-sharing check
looks only inside the `crowdsec` service block, so an identical line in another
service cannot satisfy it either.

The module is stdlib-only, so the CI job needs no install step.

## Why the pattern tests exist

A regex that matches nothing would make an equality assertion fail, but a
check written as "the value is not X" would pass vacuously. So the real-file
tests first assert that the parser finds keys and that the service block is
non-empty. The `PatternTests` class then shows each matcher giving the right
answer on samples that reproduce the failure shapes: a `max_age` under the
wrong block, a commented-out value, a `flush` at the wrong nesting, a `false`
switch, a switch in another service, and a decision comment separated from the
switch by a blank or non-comment line.

## Keeping the decision comment attached

The comment above `DISABLE_ONLINE_API` records why the switch is off. A reader
who wants to change it should meet that reasoning first. The check requires the
comment's wording to sit in the unbroken run of comment lines directly above
the switch. Moving the comment elsewhere, or inserting a line between it and the
switch, fails the suite.
