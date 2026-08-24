#!/usr/bin/env python3
"""Unit tests for install-systemd-drop-ins.sh.

`test_compose_unit_contract.py`'s `drop_in_for()` proves a committed drop-in
is internally consistent -- the right EnvironmentFile reset, the right
secrets file re-added -- but never that it reaches a host. It also globs
`*/systemd/*.override.conf` anywhere under hetzner/, so a drop-in committed
in a directory no script or runbook references would still satisfy it.

This closes that gap from the other side: `committed_drop_ins()` below walks
the identical tree, and the tests prove that running
install-systemd-drop-ins.sh actually copies every one of them to its
instance's `.service.d` directory. If a future drop-in landed somewhere
`drop_in_for()` cannot see, both this file and that one would go blind
together -- but neither can drift ahead of the other on its own, because
they search exactly the same path.

The script itself talks to a real `ssh`/`scp` to a real host, neither of
which a test process may do. Both are replaced by fakes earlier on `PATH`
that record their own argv instead of connecting anywhere -- the same
technique test_00_harden_ssh.py and test_branchleft_nat.py use for `sshd`,
`systemctl`, `ip` and `iptables`.
"""

import os
import pathlib
import stat
import subprocess
import tempfile
import unittest

HETZNER = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = HETZNER / "provision" / "install-systemd-drop-ins.sh"
RUNBOOK = HETZNER / "RUNBOOK-monitoring.md"

FAKE_SSH = """#!/usr/bin/env bash
printf 'ssh %s\\n' "$*" >> "$CAPTURE"
exit 0
"""

FAKE_SCP = """#!/usr/bin/env bash
printf 'scp %s\\n' "$*" >> "$CAPTURE"
exit 0
"""

FAKE_SCP_FAILS = """#!/usr/bin/env bash
printf 'scp %s\\n' "$*" >> "$CAPTURE"
exit 1
"""


def committed_drop_ins() -> list[pathlib.Path]:
    """Every committed instance drop-in, found the same way drop_in_for() in
    test_compose_unit_contract.py finds one: searched rather than derived,
    because the drop-ins are committed beside the story that introduced them
    rather than under the stack directory they apply to."""
    return sorted(HETZNER.glob("*/systemd/*.override.conf"))


def stack_name(drop_in: pathlib.Path) -> str:
    return drop_in.name.removesuffix(".override.conf")


class InstallSystemdDropInsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

        bin_dir = os.path.join(self.tmp.name, "bin")
        os.makedirs(bin_dir)
        self._write_fake(os.path.join(bin_dir, "ssh"), FAKE_SSH)
        self._write_fake(os.path.join(bin_dir, "scp"), FAKE_SCP)
        self.bin_dir = bin_dir
        self.capture = os.path.join(self.tmp.name, "capture.log")

    @staticmethod
    def _write_fake(path, content):
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        mode = stat.S_IMODE(os.stat(path).st_mode)
        os.chmod(path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def run_script(self, *args, hetzner_root=None, extra_env=None):
        env = dict(os.environ)
        env["PATH"] = self.bin_dir + os.pathsep + env.get("PATH", "")
        env["CAPTURE"] = self.capture
        env["SSH_KEY"] = "/fake/id_ed25519_hetzner"
        if hetzner_root is not None:
            env["HETZNER_ROOT"] = hetzner_root
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            ["bash", str(SCRIPT), *args],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def make_drop_in_tree(self, layout: dict[str, str]) -> str:
        """A throwaway `*/systemd/*.override.conf` tree, keyed by relative
        path (e.g. "monitoring/systemd/edge.override.conf"), for tests that
        need a drop-in set the real committed tree does not have -- a
        collision, in particular, which the repository correctly has none
        of."""
        root = os.path.join(self.tmp.name, "hetzner-root")
        for relative_path, content in layout.items():
            full = os.path.join(root, relative_path)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as handle:
                handle.write(content)
        return root

    def captured(self) -> list[str]:
        if not os.path.exists(self.capture):
            return []
        with open(self.capture, encoding="utf-8") as handle:
            return [line.rstrip("\n") for line in handle]

    def test_the_repository_actually_has_committed_drop_ins(self):
        """A glob that matched nothing would pass every assertion below."""
        self.assertGreaterEqual(len(committed_drop_ins()), 2)
        self.assertIn("edge", [stack_name(d) for d in committed_drop_ins()])
        self.assertIn("monitoring", [stack_name(d) for d in committed_drop_ins()])

    def test_every_committed_drop_in_is_copied_to_its_instance_directory(self):
        result = self.run_script("root@testhost")
        self.assertEqual(result.returncode, 0, result.stderr)
        captured = self.captured()
        for drop_in in committed_drop_ins():
            stack = stack_name(drop_in)
            dest = (
                f"root@testhost:/etc/systemd/system/"
                f"branchleft-compose@{stack}.service.d/override.conf"
            )
            matches = [
                line
                for line in captured
                if line.startswith("scp ") and str(drop_in) in line and dest in line
            ]
            self.assertTrue(
                matches,
                f"no scp command copied {drop_in} to {dest}: {captured}",
            )

    def test_every_instance_directory_is_created_before_any_copy(self):
        result = self.run_script("root@testhost")
        self.assertEqual(result.returncode, 0, result.stderr)
        captured = self.captured()
        install_indexes = [
            i for i, line in enumerate(captured) if line.startswith("ssh ") and "install -d" in line
        ]
        self.assertEqual(len(install_indexes), 1, captured)
        install_line = captured[install_indexes[0]]
        for drop_in in committed_drop_ins():
            stack = stack_name(drop_in)
            self.assertIn(
                f"/etc/systemd/system/branchleft-compose@{stack}.service.d",
                install_line,
            )
        scp_indexes = [i for i, line in enumerate(captured) if line.startswith("scp ")]
        self.assertTrue(scp_indexes)
        self.assertLess(install_indexes[0], min(scp_indexes))

    def test_systemd_is_reloaded_exactly_once_after_every_copy(self):
        result = self.run_script("root@testhost")
        self.assertEqual(result.returncode, 0, result.stderr)
        captured = self.captured()
        reload_indexes = [i for i, line in enumerate(captured) if "daemon-reload" in line]
        self.assertEqual(len(reload_indexes), 1, captured)
        scp_indexes = [i for i, line in enumerate(captured) if line.startswith("scp ")]
        self.assertGreater(reload_indexes[0], max(scp_indexes))

    def test_refuses_to_run_with_no_target(self):
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("usage", result.stderr.lower())
        self.assertEqual(self.captured(), [])

    def test_refuses_to_run_with_extra_arguments(self):
        result = self.run_script("root@testhost", "extra")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("usage", result.stderr.lower())
        self.assertEqual(self.captured(), [])

    def test_two_drop_ins_for_the_same_stack_are_refused_rather_than_raced(self):
        # Two different committed paths both naming the "edge" instance --
        # exactly what drop_in_for() in test_compose_unit_contract.py already
        # raises AssertionError for. This script has no access to that
        # function, so it has to refuse the same shape on its own account
        # rather than silently letting the later scp win.
        root = self.make_drop_in_tree(
            {
                "monitoring/systemd/edge.override.conf": "[Service]\n",
                "edge/systemd/edge.override.conf": "[Service]\n",
            }
        )
        result = self.run_script("root@testhost", hetzner_root=root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("more than one drop-in for edge", result.stderr)
        self.assertFalse(
            [line for line in self.captured() if "daemon-reload" in line],
            "must not reach systemctl daemon-reload after refusing a collision",
        )

    def test_a_non_default_ifs_does_not_change_which_directories_are_created(self):
        # ${array[*]} joins with the first character of $IFS, not a literal
        # space -- an inherited IFS="" would silently concatenate every
        # instance directory into one bogus path. The install command must
        # list both real directories, space-separated, regardless.
        result = self.run_script("root@testhost", extra_env={"IFS": ""})
        self.assertEqual(result.returncode, 0, result.stderr)
        install_line = next(
            line for line in self.captured() if line.startswith("ssh ") and "install -d" in line
        )
        for drop_in in committed_drop_ins():
            stack = stack_name(drop_in)
            self.assertIn(
                f" /etc/systemd/system/branchleft-compose@{stack}.service.d",
                install_line,
                "expected a space-separated directory, not one concatenated with its neighbour",
            )

    def test_a_failed_copy_aborts_before_reload(self):
        self._write_fake(os.path.join(self.bin_dir, "scp"), FAKE_SCP_FAILS)
        result = self.run_script("root@testhost")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(
            [line for line in self.captured() if "daemon-reload" in line],
            "systemd must not be reloaded against a partially copied set of drop-ins",
        )


class RunbookInvokesTheScriptTests(unittest.TestCase):
    """RUNBOOK-monitoring.md step 5 must call this script rather than carry
    its own copy of the ssh/scp commands -- a doc that drifts back to raw
    commands would silently reintroduce the fixed, two-stack list this
    script exists to replace."""

    @staticmethod
    def _step_5_body() -> str:
        text = RUNBOOK.read_text(encoding="utf-8")
        lines = text.splitlines()
        start = next(i for i, line in enumerate(lines) if line.startswith("## 5. "))
        end = next(i for i in range(start + 1, len(lines)) if lines[i].startswith("## 6. "))
        return "\n".join(lines[start:end])

    def test_step_5_invokes_install_systemd_drop_ins(self):
        body = self._step_5_body()
        self.assertIn("hetzner/provision/install-systemd-drop-ins.sh", body)

    def test_step_5_no_longer_hardcodes_a_scp_per_drop_in(self):
        """The old step scp'd each of the two files by name in its own
        fenced command. Its return would mean a third drop-in is silently
        unreachable again, exactly the defect this script exists to close."""
        body = self._step_5_body()
        self.assertNotIn("scp -i", body)
        self.assertNotIn("ssh -i", body)


if __name__ == "__main__":
    unittest.main()
