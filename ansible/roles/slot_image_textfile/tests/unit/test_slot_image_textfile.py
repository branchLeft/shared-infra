"""Unit tests for the slot image digest writer: what it exports, what it refuses, and where.

The program is read from files/ and run in a temporary directory, so these tests need no host
and no Docker. They prove the refusal rule (a pin that is not a sha256 digest is not exported),
the output shape, the atomic replace, and that the unit, the program's defaults and the role's
paths name the same locations. The Molecule scenario proves the installed result on a container.
"""

import importlib.util
import io
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import ModuleType

ROLE = Path(__file__).resolve().parents[2]
PROGRAM = ROLE / "files" / "branchleft_slot_image_textfile.py"
UNIT = ROLE / "files" / "branchleft-slot-image-textfile.service"
ROLE_VARS = ROLE / "vars" / "main.yml"
EXPORTER_VARS = ROLE.parent / "node_exporter" / "vars" / "main.yml"

DIGEST = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64


def load_program() -> ModuleType:
    spec = importlib.util.spec_from_file_location("branchleft_slot_image_textfile", PROGRAM)
    if spec is None or spec.loader is None:
        raise ImportError(str(PROGRAM))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PROG = load_program()


def pin(directory: Path, stack: str, text: str) -> None:
    (directory / f"{stack}.image.env").write_text(text, encoding="utf-8")


def role_var(name: str) -> str:
    """Return a scalar variable of the role's vars file.

    Raises:
        KeyError: the variable is not in the file.
    """
    return variable_in(ROLE_VARS, name)


def exporter_var(name: str) -> str:
    """Return a scalar variable of node_exporter's vars file.

    Raises:
        KeyError: the variable is not in the file.
    """
    return variable_in(EXPORTER_VARS, name)


def variable_in(path: Path, name: str) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith(name + ":"):
            return line.split(":", 1)[1].strip()
    raise KeyError(name)


class ExportsOnlyDigests(unittest.TestCase):
    def test_a_digest_pin_is_exported_with_its_stack_and_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pin(Path(directory), "tenant-a", f"IMAGE=registry.example/ghost@{DIGEST}\n")
            pins, refusals = PROG.collect(Path(directory))
        self.assertEqual(pins, [("tenant-a", DIGEST)])
        self.assertEqual(refusals, [])

    def test_a_tag_is_refused_and_the_valid_stack_is_still_exported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pin(Path(directory), "tenant-a", f"IMAGE=registry.example/ghost@{DIGEST}\n")
            pin(Path(directory), "tenant-b", "IMAGE=registry.example/ghost:latest\n")
            pins, refusals = PROG.collect(Path(directory))
        self.assertEqual(pins, [("tenant-a", DIGEST)])
        self.assertEqual(len(refusals), 1)
        self.assertIn("tenant-b.image.env", refusals[0])
        self.assertNotIn("latest", refusals[0], "a refusal names the rule, never the value")

    def test_a_short_digest_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            short = "IMAGE=registry.example/ghost@sha256:" + "a" * 63 + "\n"
            pin(Path(directory), "tenant-a", short)
            pins, refusals = PROG.collect(Path(directory))
        self.assertEqual(pins, [])
        self.assertEqual(len(refusals), 1)

    def test_two_lines_are_refused_even_when_one_is_a_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            two = f"IMAGE=registry.example/ghost@{DIGEST}\nIMAGE=x@{OTHER}\n"
            pin(Path(directory), "tenant-a", two)
            pins, refusals = PROG.collect(Path(directory))
        self.assertEqual(pins, [])
        self.assertEqual(len(refusals), 1)

    def test_a_trailing_newline_inside_the_value_is_refused(self) -> None:
        # \Z, not $: a value that carries an extra newline must not pass as a digest.
        self.assertIsNone(PROG.PIN_LINE.match(f"IMAGE=registry.example/ghost@{DIGEST}\n"))

    def test_a_bad_stack_name_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pin(Path(directory), "Tenant_A", f"IMAGE=registry.example/ghost@{DIGEST}\n")
            pins, refusals = PROG.collect(Path(directory))
        self.assertEqual(pins, [])
        self.assertIn("rule: stack name", refusals[0])


class WritesOneAtomicFile(unittest.TestCase):
    def test_the_output_has_one_series_per_stack_and_no_leftover_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            pin(base, "tenant-b", f"IMAGE=registry.example/ghost@{OTHER}\n")
            pin(base, "tenant-a", f"IMAGE=registry.example/ghost@{DIGEST}\n")
            output = base / "branchleft_slot_image.prom"
            status = PROG.main(["--config-dir", str(base), "--output", str(output)])
            text = output.read_text(encoding="utf-8")
            leftovers = sorted(p.name for p in base.iterdir() if p.name.startswith("."))
        self.assertEqual(status, 0)
        series = [line for line in text.splitlines() if not line.startswith("#")]
        self.assertEqual(
            series,
            [
                f'branchleft_slot_image_info{{stack="tenant-a",digest="{DIGEST}"}} 1',
                f'branchleft_slot_image_info{{stack="tenant-b",digest="{OTHER}"}} 1',
            ],
        )
        self.assertEqual(leftovers, [])

    def test_a_refusal_exits_one_and_prints_the_file_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            pin(base, "tenant-b", "IMAGE=ghost:latest\n")
            output = base / "out.prom"
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                status = PROG.main(["--config-dir", str(base), "--output", str(output)])
            text = output.read_text(encoding="utf-8")
        self.assertEqual(status, 1)
        self.assertIn("tenant-b.image.env", stderr.getvalue())
        self.assertNotIn("branchleft_slot_image_info{", text)

    def test_the_output_file_is_world_readable_for_the_exporter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            output = base / "out.prom"
            PROG.main(["--config-dir", str(base), "--output", str(output)])
            mode = output.stat().st_mode & 0o777
        self.assertEqual(mode, 0o644)


class PathsAgree(unittest.TestCase):
    """The unit, the program's defaults, the role's vars and node_exporter's vars name one place."""

    def test_the_role_and_node_exporter_name_the_same_textfile_directory(self) -> None:
        self.assertEqual(
            role_var("slot_image_textfile_dir"), exporter_var("node_exporter_textfile_dir")
        )

    def test_the_unit_writes_into_that_directory_and_reads_the_config_dir(self) -> None:
        unit = UNIT.read_text(encoding="utf-8")
        exec_start = [line for line in unit.splitlines() if line.startswith("ExecStart=")]
        self.assertEqual(len(exec_start), 1)
        self.assertIn(f"--config-dir {role_var('slot_image_textfile_config_dir')}", exec_start[0])
        self.assertIn(
            f"--output {role_var('slot_image_textfile_dir')}/branchleft_slot_image.prom",
            exec_start[0],
        )
        self.assertIn(f"ReadWritePaths={role_var('slot_image_textfile_dir')}", unit)

    def test_the_unit_runs_the_installed_program(self) -> None:
        unit = UNIT.read_text(encoding="utf-8")
        self.assertIn(f"ExecStart={role_var('slot_image_textfile_program')} ", unit)

    def test_the_program_defaults_match_the_role(self) -> None:
        self.assertEqual(PROG.DEFAULT_CONFIG_DIR, role_var("slot_image_textfile_config_dir"))
        self.assertEqual(
            PROG.DEFAULT_OUTPUT,
            role_var("slot_image_textfile_dir") + "/branchleft_slot_image.prom",
        )


if __name__ == "__main__":
    unittest.main()
