"""Tests of the drain sidecar's pin file, /etc/branchleft/demo-sidecar.image.env.

The role writes one line, DEMO_SIDECAR_IMAGE=<name>@<digest>, from the attested digest in
defaults/main.yml. Three programs of ghost-platform read that file and each holds its own
copy of the path, the variable and the name: the colour units' renderer (the path), the
sidecar launcher (the variable) and the slot wrapper (all three, and the line's shape). These
tests hold the role's constants to the vendored copies and run the line the role renders
through the vendored wrapper's own reader, so a name, path or shape that drifts is red here and
not a sidecar that is tagged as a slot image on the host.
"""

from __future__ import annotations

import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest import mock

import jinja2
import yaml

ROLE = Path(__file__).resolve().parent.parent.parent
PROVISION = ROLE / "files" / "ghost-platform" / "demo-host" / "provision"
NOT_A_MAPPING = "a role variables file is not a mapping"
NO_SPEC = "cannot load the vendored wrapper"
NO_CONSTANT = "a string constant the sidecar pin ties to is missing from a vendored program"
# The pin the role carried before the wrapper learned to read the pin file (ghost-platform#1120).
# A wrapper vendored at it has no reader to hold the role's line to. Delete this constant and the
# branch that uses it when the role is re-vendored at a commit that holds the reader.
PRE_READER_SHA = "5e20991adefcdb9edde4157c6a56d2796ec1da6c"
DIGEST = "sha256:d181d72055ab1e0c30c11c65595e1b79206fd5cdf519ab06d17271107eb0b954"
LINE = f"DEMO_SIDECAR_IMAGE=branchleft/drain-sidecar@{DIGEST}"


def load(name: str) -> dict[str, object]:
    """One role variables file, defaults or vars.

    Raises:
        TypeError: the file is not a mapping.
    """
    raw = yaml.safe_load((ROLE / name / "main.yml").read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise TypeError(NOT_A_MAPPING)
    return raw


def resolved() -> dict[str, object]:
    """Defaults then vars, the later winning, with the sidecar line rendered as Ansible does.

    Raises:
        TypeError: the sidecar line is not a string.
    """
    context = {**load("defaults"), **load("vars")}
    env = jinja2.Environment(undefined=jinja2.StrictUndefined, autoescape=False)  # noqa: S701 - not HTML
    line = context["demo1_build_sidecar_image_line"]
    if not isinstance(line, str):
        raise TypeError(NOT_A_MAPPING)
    context["demo1_build_sidecar_image_line"] = env.from_string(line).render(context)
    return context


def constant(path: Path, name: str) -> str:
    """The value of a module-level string constant, read without importing the program.

    Raises:
        LookupError: the program has no such constant.
    """
    match = re.search(rf'^{name} = (?:f?)"([^"]*)"', path.read_text(encoding="utf-8"), re.M)
    if match is None:
        raise LookupError(NO_CONSTANT)
    return match.group(1)


def wrapper() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "vendored_branchleft_slot", PROVISION / "branchleft_slot.py"
    )
    if spec is None or spec.loader is None:
        raise ImportError(NO_SPEC)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # a dataclass in the program looks its module up here
    spec.loader.exec_module(module)
    return module


class RoleTests(unittest.TestCase):
    def test_the_line_is_the_attested_digest_under_the_hosts_own_name(self) -> None:
        self.assertEqual(resolved()["demo1_build_sidecar_image_line"], LINE)

    def test_the_digest_pattern_takes_only_a_bare_lower_case_digest(self) -> None:
        pattern = re.compile(str(resolved()["demo1_build_sidecar_digest_pattern"]))
        self.assertIsNotNone(pattern.match(DIGEST))
        for bad in (
            "latest",
            DIGEST.upper(),
            DIGEST + "\n",
            DIGEST[:-1],
            DIGEST + "0",
            "branchleft/drain-sidecar@" + DIGEST,
            "ghcr.io/branchleft/drain-sidecar@" + DIGEST,
            DIGEST.replace("sha256:", "sha512:"),
            "",
        ):
            with self.subTest(bad=bad):
                self.assertIsNone(pattern.match(bad))

    def test_the_name_carries_no_registry_host(self) -> None:
        self.assertEqual(resolved()["demo1_build_sidecar_image_name"], "branchleft/drain-sidecar")


class VendoredTieTests(unittest.TestCase):
    def test_the_path_is_the_one_the_colour_units_name(self) -> None:
        text = (PROVISION / "render_colour_units.py").read_text(encoding="utf-8")
        etc = constant(PROVISION / "render_colour_units.py", "ETC_DIR")
        self.assertIn('SIDECAR_IMAGE_ENV = f"{ETC_DIR}/demo-sidecar.image.env"', text)
        self.assertEqual(
            f"{etc}/demo-sidecar.image.env", resolved()["demo1_build_sidecar_image_env_path"]
        )

    def test_the_variable_is_the_one_the_sidecar_launcher_reads(self) -> None:
        self.assertEqual(
            constant(PROVISION / "demo_sidecar.py", "IMAGE_VARIABLE"),
            resolved()["demo1_build_sidecar_image_variable"],
        )

    def test_the_wrapper_reads_the_line_the_role_writes(self) -> None:
        """The vendored wrapper's own reader accepts the role's line, as a root-owned 0644 file."""
        source_sha = str(resolved()["demo1_build_source_sha"])
        text = (PROVISION / "branchleft_slot.py").read_text(encoding="utf-8")
        if source_sha == PRE_READER_SHA:
            self.assertNotIn(
                "_pinned_sidecar_id", text, "re-vendored: delete PRE_READER_SHA and this branch"
            )
            return
        module = wrapper()
        self.assertEqual(module.SIDECAR_IMAGE_NAME, resolved()["demo1_build_sidecar_image_name"])
        self.assertEqual(
            module.SIDECAR_IMAGE_VARIABLE, resolved()["demo1_build_sidecar_image_variable"]
        )
        self.assertEqual(
            module.SIDECAR_IMAGE_ENV_PATH, resolved()["demo1_build_sidecar_image_env_path"]
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "demo-sidecar.image.env"
            path.write_text(
                str(resolved()["demo1_build_sidecar_image_line"]) + "\n", encoding="utf-8"
            )
            path.chmod(0o644)
            # The test runs as no particular uid; the wrapper's check is "owned by root".
            with mock.patch.object(module, "SIDECAR_IMAGE_ENV_OWNER_UID", os.getuid()):
                self.assertEqual(module._pinned_sidecar_id(str(path)), DIGEST)  # noqa: SLF001
                path.chmod(0o664)
                self.assertIsNone(module._pinned_sidecar_id(str(path)))  # noqa: SLF001


if __name__ == "__main__":
    unittest.main()
