#!/usr/bin/env python3
"""The edge's CrowdSec retention bound and its signal-sharing switch stay pinned.

Full reasoning: `test_crowdsec_retention.md`.
"""

import pathlib
import re
import textwrap
import unittest

HETZNER = pathlib.Path(__file__).resolve().parent.parent
CONFIG_LOCAL = HETZNER / "edge" / "stack" / "crowdsec" / "config.yaml.local"
COMPOSE = HETZNER / "edge" / "stack" / "compose.yml"

# A `key: value` line. The indentation is captured because nesting is read from
# it: this YAML is hand-written, so a parser that trusts the indentation is
# enough, and no YAML library is needed.
KEY_LINE = re.compile(r"\A(?P<indent>\s*)(?P<key>[A-Za-z_][\w-]*):(?P<value>.*)\Z")

# Comment lines are skipped before any key is read, so a commented-out key
# never counts as a setting.
COMMENT_LINE = re.compile(r"\A\s*#")

# A service key sits at exactly two spaces under `services:`. A line starting
# in column one is a top-level key (`volumes:`, `networks:`) and ends a service.
SERVICE_KEY = re.compile(r"\A  (?P<name>[A-Za-z_][\w-]*):\s*\Z")
TOP_LEVEL_KEY = re.compile(r"\A[A-Za-z_]")

# The signal-sharing switch. Its value is read as written, quotes included, so a
# change from `'true'` to `false` or `"true"` shows up in the assertion message.
DISABLE_ONLINE_API = re.compile(r"\A\s*DISABLE_ONLINE_API:(?P<value>.*)\Z")

# Matched on the wording as written in compose.yml, not the whole sentence, so a
# reflowed comment still counts and a reworded decision does not.
SIGNAL_SHARING_COMMENT = re.compile(r"\A\s*#.*a sub-processor and a personal-data decision")


def values_by_path(text: str) -> dict[tuple[str, ...], str]:
    """Each `key: value` line keyed by the path of keys above it."""
    found: dict[tuple[str, ...], str] = {}
    open_keys: list[tuple[int, str]] = []
    for line in text.splitlines():
        if not line.strip() or COMMENT_LINE.match(line):
            continue
        match = KEY_LINE.match(line)
        if match is None:
            continue
        depth = len(match.group("indent"))
        while open_keys and open_keys[-1][0] >= depth:
            open_keys.pop()
        key = match.group("key")
        path = tuple(name for _, name in open_keys) + (key,)
        value = match.group("value").strip()
        if value:
            found[path] = value
        open_keys.append((depth, key))
    return found


def flush_max_age(config_text: str) -> str | None:
    """The value of `db_config.flush.max_age`, or None if that key is absent."""
    return values_by_path(config_text).get(("db_config", "flush", "max_age"))


def crowdsec_service_lines(compose_text: str) -> list[str]:
    """The body of the `crowdsec:` service, from its key to the next service."""
    block: list[str] = []
    inside = False
    for line in compose_text.splitlines():
        service = SERVICE_KEY.match(line)
        if service or TOP_LEVEL_KEY.match(line):
            if inside:
                break
            inside = service is not None and service.group("name") == "crowdsec"
        elif inside:
            block.append(line)
    return block


def disable_online_api_index(service_lines: list[str]) -> int | None:
    """The line index of the `DISABLE_ONLINE_API` setting in a service body."""
    return next(
        (index for index, line in enumerate(service_lines) if DISABLE_ONLINE_API.match(line)),
        None,
    )


def disable_online_api_value(service_lines: list[str]) -> str | None:
    """The raw value of `DISABLE_ONLINE_API`, quotes included, or None if absent."""
    index = disable_online_api_index(service_lines)
    if index is None:
        return None
    return DISABLE_ONLINE_API.match(service_lines[index]).group("value").strip()


def comment_run_ending_before(service_lines: list[str], index: int) -> list[str]:
    """The unbroken run of comment lines directly above `index`, nearest first."""
    run: list[str] = []
    for line in reversed(service_lines[:index]):
        if not COMMENT_LINE.match(line):
            break
        run.append(line)
    return run


def decision_comment_sits_above_switch(service_lines: list[str]) -> bool:
    """Whether the owner's decision comment is in the run directly above the switch."""
    index = disable_online_api_index(service_lines)
    if index is None:
        return False
    return any(
        SIGNAL_SHARING_COMMENT.match(line)
        for line in comment_run_ending_before(service_lines, index)
    )


class EdgeCrowdsecRetentionTests(unittest.TestCase):
    def test_the_config_parser_reads_keys_from_the_real_overlay(self):
        """A parser that read nothing would fail the flush test below for the wrong reason."""
        values = values_by_path(CONFIG_LOCAL.read_text(encoding="utf-8"))
        self.assertIn(("crowdsec_service", "acquisition_dir"), values)

    def test_the_overlay_flushes_decisions_after_thirty_days(self):
        found = flush_max_age(CONFIG_LOCAL.read_text(encoding="utf-8"))
        shown = found if found is not None else "no db_config.flush.max_age key"
        self.assertEqual(
            found,
            "30d",
            f"{CONFIG_LOCAL} sets db_config.flush.max_age to {shown}, not 30d. The edge "
            "keeps client addresses for 30 days; the image default is 7 days, so an "
            "unset or changed value moves that bound without any reviewed decision.",
        )

    def test_the_crowdsec_service_block_is_found_in_compose(self):
        """A block extractor that matched nothing would pass the checks below vacuously."""
        block = crowdsec_service_lines(COMPOSE.read_text(encoding="utf-8"))
        self.assertGreater(len(block), 0, f"no crowdsec service block found in {COMPOSE}")
        self.assertIsNotNone(
            disable_online_api_index(block),
            f"the crowdsec service in {COMPOSE} has no DISABLE_ONLINE_API line",
        )

    def test_the_crowdsec_service_keeps_online_signal_sharing_disabled(self):
        value = disable_online_api_value(crowdsec_service_lines(COMPOSE.read_text(encoding="utf-8")))
        self.assertEqual(
            value,
            "'true'",
            f"the crowdsec service in {COMPOSE} sets DISABLE_ONLINE_API to {value}, not "
            "'true'. Signal sharing sends client addresses to a third party, which is a "
            "sub-processor and personal-data decision, so it must not be flipped silently.",
        )

    def test_the_signal_sharing_switch_sits_under_the_decision_comment(self):
        block = crowdsec_service_lines(COMPOSE.read_text(encoding="utf-8"))
        self.assertTrue(
            decision_comment_sits_above_switch(block),
            f"the DISABLE_ONLINE_API line in {COMPOSE} is not directly under the comment "
            "recording why signal sharing is off. Either the comment moved away from the "
            "switch or something was put between them.",
        )


class PatternTests(unittest.TestCase):
    """Each matcher's failure direction, against shapes the real files lack."""

    def test_a_flush_max_age_reads_as_thirty_days(self):
        sample = textwrap.dedent("""\
            db_config:
              flush:
                max_age: 30d
            """)
        self.assertEqual(flush_max_age(sample), "30d")

    def test_a_file_without_max_age_yields_nothing(self):
        sample = textwrap.dedent("""\
            db_config:
              flush:
                max_items: 5000
            """)
        self.assertIsNone(flush_max_age(sample))

    def test_a_ninety_day_max_age_is_read_as_ninety_days(self):
        sample = textwrap.dedent("""\
            db_config:
              flush:
                max_age: 90d
            """)
        self.assertEqual(flush_max_age(sample), "90d")

    def test_a_max_age_under_another_block_is_not_read(self):
        sample = textwrap.dedent("""\
            cscli:
              flush:
                max_age: 30d
            db_config:
              flush:
                max_items: 5000
            """)
        self.assertIsNone(flush_max_age(sample))

    def test_a_commented_out_max_age_is_not_read(self):
        sample = textwrap.dedent("""\
            db_config:
              flush:
            #   max_age: 30d
            """)
        self.assertIsNone(flush_max_age(sample))

    def test_a_flush_at_the_top_level_is_not_read(self):
        sample = textwrap.dedent("""\
            flush:
              max_age: 30d
            db_config:
              max_items: 5000
            """)
        self.assertIsNone(flush_max_age(sample))

    def test_a_max_age_beside_flush_rather_than_inside_it_is_not_read(self):
        sample = textwrap.dedent("""\
            db_config:
              flush:
                max_items: 5000
              max_age: 30d
            """)
        self.assertIsNone(flush_max_age(sample))

    def test_a_true_switch_in_the_crowdsec_service_is_read(self):
        sample = "  crowdsec:\n    environment:\n      DISABLE_ONLINE_API: 'true'\n"
        self.assertEqual(disable_online_api_value(crowdsec_service_lines(sample)), "'true'")

    def test_a_false_switch_is_read_and_would_be_rejected(self):
        sample = "  crowdsec:\n    environment:\n      DISABLE_ONLINE_API: 'false'\n"
        self.assertEqual(disable_online_api_value(crowdsec_service_lines(sample)), "'false'")

    def test_a_true_switch_in_another_service_is_not_read(self):
        sample = textwrap.dedent("""\
            services:
              caddy:
                environment:
                  DISABLE_ONLINE_API: 'true'
              crowdsec:
                environment:
                  CUSTOM_HOSTNAME: edge1
            volumes:
              crowdsec-data:
            """)
        self.assertIsNone(disable_online_api_value(crowdsec_service_lines(sample)))

    def test_the_service_block_stops_at_a_top_level_key(self):
        sample = textwrap.dedent("""\
            services:
              crowdsec:
                environment:
                  CUSTOM_HOSTNAME: edge1
            volumes:
                  DISABLE_ONLINE_API: 'true'
            """)
        self.assertIsNone(disable_online_api_value(crowdsec_service_lines(sample)))

    def test_the_decision_comment_directly_above_passes(self):
        sample = textwrap.dedent("""\
              crowdsec:
                environment:
                  # Signal sharing sends observed client addresses to a third party. That is
                  # a sub-processor and a personal-data decision, not a configuration
                  # default, so it stays off until it has been taken deliberately.
                  DISABLE_ONLINE_API: 'true'
            """).splitlines()
        self.assertTrue(decision_comment_sits_above_switch(sample))

    def test_a_blank_line_between_comment_and_switch_fails(self):
        sample = textwrap.dedent("""\
              crowdsec:
                environment:
                  # a sub-processor and a personal-data decision, not a configuration

                  DISABLE_ONLINE_API: 'true'
            """).splitlines()
        self.assertFalse(decision_comment_sits_above_switch(sample))

    def test_a_non_comment_line_between_comment_and_switch_fails(self):
        sample = textwrap.dedent("""\
              crowdsec:
                environment:
                  # a sub-processor and a personal-data decision, not a configuration
                  CUSTOM_HOSTNAME: edge1
                  DISABLE_ONLINE_API: 'true'
            """).splitlines()
        self.assertFalse(decision_comment_sits_above_switch(sample))

    def test_a_missing_decision_comment_fails(self):
        sample = textwrap.dedent("""\
              crowdsec:
                environment:
                  # Some other remark about the container.
                  DISABLE_ONLINE_API: 'true'
            """).splitlines()
        self.assertFalse(decision_comment_sits_above_switch(sample))


if __name__ == "__main__":
    unittest.main()
