"""Tests for check_widget_pins.py. The live check runs in CI as a separate step."""

from __future__ import annotations

import json
import unittest

from check_widget_pins import (
    DEFAULT_DOCKERFILE,
    check,
    parse_dockerfile,
    sha256_hex,
    sha384_sri,
)

COMMIT = "7863b17996a9e59bf74b157339487c2a2a71faf2"
FILES = {
    "admin-toolbar.min.js": b"admin toolbar bytes",
    "announcement-bar.min.js": b"announcement bar bytes",
    "comments-ui.min.js": b"comments bytes",
    "portal.min.js": b"portal bytes",
    "signup-form.min.js": b"signup bytes",
    "sodo-search.min.css": b"sodo css bytes",
    "sodo-search.min.js": b"sodo js bytes",
}


def dockerfile_for(files: dict[str, bytes], commit: str = COMMIT) -> str:
    lines = [
        f"ARG WIDGET_SOURCE_COMMIT={commit}",
        "ARG WIDGET_BASE_URL=https://raw.githubusercontent.com/branchLeft/ghost-platform/${WIDGET_SOURCE_COMMIT}/widgets/dist",
    ]
    for name, data in sorted(files.items()):
        lines.append(
            f"ADD --checksum=sha256:{sha256_hex(data)} --chmod=0644 "
            f"${{WIDGET_BASE_URL}}/{name} /srv/bl-assets/{name}"
        )
    return "\n".join(lines) + "\n"


def pins_for(files: dict[str, bytes]) -> str:
    bundles = [
        {
            "servedPath": f"/bl-assets/{name}",
            "sha384": sha384_sri(data),
            "bytes": len(data),
        }
        for name, data in sorted(files.items())
    ]
    return json.dumps({"bundles": bundles})


def serve(files: dict[str, bytes]):
    def fetch(_commit: str, name: str) -> bytes:
        return files[name]

    return fetch


class WidgetPinsTest(unittest.TestCase):
    def test_matching_edge_and_pins_pass(self) -> None:
        problems = check(dockerfile_for(FILES), pins_for(FILES), serve(FILES))
        self.assertEqual(problems, [])

    def test_real_dockerfile_names_seven_files_and_one_commit(self) -> None:
        parsed = parse_dockerfile(DEFAULT_DOCKERFILE.read_text(encoding="utf-8"))
        self.assertEqual(len(parsed.sha256_by_name), 7)
        self.assertRegex(parsed.commit, r"^[0-9a-f]{40}$")

    def test_sabotaged_sha256_in_edge_is_red(self) -> None:
        tampered = dict(FILES)
        tampered["portal.min.js"] = b"a different portal"
        problems = check(dockerfile_for(FILES), pins_for(FILES), serve(tampered))
        self.assertTrue(any("portal.min.js: edge Dockerfile sha256" in p for p in problems), problems)

    def test_sha384_drift_in_pins_is_red(self) -> None:
        pins = json.loads(pins_for(FILES))
        pins["bundles"][0]["sha384"] = "sha384-" + "A" * 64
        problems = check(dockerfile_for(FILES), json.dumps(pins), serve(FILES))
        self.assertTrue(any("pins.json sha384" in p for p in problems), problems)

    def test_size_drift_in_pins_is_red(self) -> None:
        pins = json.loads(pins_for(FILES))
        pins["bundles"][1]["bytes"] = 1
        problems = check(dockerfile_for(FILES), json.dumps(pins), serve(FILES))
        self.assertTrue(any("pins.json bytes" in p for p in problems), problems)

    def test_file_added_to_edge_only_is_red(self) -> None:
        extra = dict(FILES)
        extra["extra.min.js"] = b"extra"
        problems = check(dockerfile_for(extra), pins_for(FILES), serve(FILES))
        self.assertTrue(any("file list differs" in p for p in problems), problems)

    def test_unrecognised_add_line_is_refused(self) -> None:
        text = dockerfile_for(FILES) + "ADD https://example.test/x.js /srv/bl-assets/x.js\n"
        with self.assertRaises(ValueError):
            parse_dockerfile(text)

    def test_missing_commit_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            parse_dockerfile(dockerfile_for(FILES).replace("ARG WIDGET_SOURCE_COMMIT", "ARG OTHER"))


if __name__ == "__main__":
    unittest.main()
