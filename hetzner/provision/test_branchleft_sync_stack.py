#!/usr/bin/env python3
"""Tests for branchleft_sync_stack.py, the file-delivery half of the monitoring deploy.

Run against a scratch directory with a recording stand-in for systemctl. The
control cases matter as much as the happy path: every refusal test also checks
that the destination was left exactly as it was, since a refusal that had
already deleted half the stack would be worse than no check.
"""

from __future__ import annotations

import importlib.util
import io
import os
import pathlib
import stat
import sys
import tarfile
import tempfile
import unittest
import unittest.mock

HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("branchleft_sync_stack", HERE / "branchleft_sync_stack.py")
assert SPEC is not None and SPEC.loader is not None
sync = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = sync
SPEC.loader.exec_module(sync)

REQUIRED = {
    "compose.yml": b"services: {}\n",
    "render_alertmanager_config.py": b"#!/usr/bin/python3\n",
    "alertmanager/alertmanager.yml.tmpl": b"template\n",
    "alertmanager/email.gotmpl": b"email\n",
    "prometheus/prometheus.yml": b"global: {}\n",
    "prometheus/alerts.yml": b"groups: []\n",
}
RENDERED = {
    "alertmanager/alertmanager.yml": b"smtp_password: SECRET\n",
    "ntfy/server.yml": b"auth: SECRET\n",
    "prometheus/mx1-metrics-password": b"SECRET",
}
IDS = (os.getuid(), os.getgid())


def build(files, *, end=True, extra=None, modes=None):
    """A tar archive the way the workflow builds it: files, then END-OF-STACK."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name, data in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = (modes or {}).get(name, 0o600)
            info.uid = info.gid = 501
            tar.addfile(info, io.BytesIO(data))
        for info, data in extra or []:
            tar.addfile(info, io.BytesIO(data) if data is not None else None)
        if end:
            marker = tarfile.TarInfo("END-OF-STACK")
            tar.addfile(marker, io.BytesIO(b""))
    return io.BytesIO(buf.getvalue())


class Recorder:
    def __init__(self, enabled=True, restart_rc=0):
        self.calls = []
        self.enabled = enabled
        self.restart_rc = restart_rc

    def __call__(self, *args):
        self.calls.append(args)
        if args[0] == "is-enabled":
            return 0 if self.enabled else 1
        return self.restart_rc

    @property
    def restarts(self):
        return [c for c in self.calls if c[0] == "restart"]


def snapshot(root):
    out = {}
    for path in sorted(pathlib.Path(root).rglob("*")):
        st = path.lstat()
        body = path.read_bytes() if path.is_file() and not path.is_symlink() else None
        out[str(path.relative_to(root))] = (stat.S_IMODE(st.st_mode), body)
    return out


class SyncTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        self.dest = self.root / "monitoring"
        self.out = io.StringIO()

    def run_sync(self, archive, recorder=None, **kw):
        recorder = recorder or Recorder()
        kw.setdefault("owner", IDS)
        rc = sync.sync(
            "monitoring", archive, dest_root=str(self.root), systemctl=recorder, out=self.out, **kw
        )
        return rc, recorder

    def test_first_sync_installs_the_tree_with_set_modes_and_no_restart_in_a_rehearsal(self):
        rc, rec = self.run_sync(build(REQUIRED, modes={"compose.yml": 0o600, "render_alertmanager_config.py": 0o750}))
        self.assertEqual(rc, 0)
        self.assertEqual((self.dest / "prometheus/alerts.yml").read_bytes(), REQUIRED["prometheus/alerts.yml"])
        self.assertEqual(stat.S_IMODE((self.dest / "compose.yml").stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE((self.dest / "render_alertmanager_config.py").stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((self.dest / "prometheus").stat().st_mode), 0o755)
        self.assertEqual(rec.calls, [])
        self.assertFalse((self.dest / "END-OF-STACK").exists())

    def test_a_second_sync_of_the_same_archive_changes_nothing(self):
        archive = build(REQUIRED).getvalue()
        self.run_sync(io.BytesIO(archive))
        before = snapshot(self.dest)
        self.out.truncate(0)
        self.out.seek(0)
        rc, _ = self.run_sync(io.BytesIO(archive))
        self.assertEqual(rc, 0)
        self.assertEqual(snapshot(self.dest), before)
        self.assertIn("unchanged, no restart", self.out.getvalue())

    def test_a_changed_file_is_rewritten_and_only_that_file(self):
        self.run_sync(build(REQUIRED))
        changed = dict(REQUIRED, **{"prometheus/alerts.yml": b"groups: [new]\n"})
        self.out.truncate(0)
        self.out.seek(0)
        self.run_sync(build(changed))
        self.assertEqual((self.dest / "prometheus/alerts.yml").read_bytes(), b"groups: [new]\n")
        self.assertEqual(self.out.getvalue().count("wrote "), 1)
        self.assertIn("wrote prometheus/alerts.yml", self.out.getvalue())

    def test_a_file_dropped_from_the_archive_is_removed_from_the_host(self):
        self.run_sync(build(REQUIRED))
        smaller = {k: v for k, v in REQUIRED.items() if k != "alertmanager/email.gotmpl"}
        self.run_sync(build(smaller))
        self.assertFalse((self.dest / "alertmanager/email.gotmpl").exists())
        self.assertTrue((self.dest / "alertmanager/alertmanager.yml.tmpl").exists())

    def test_a_stray_file_and_a_stray_directory_on_the_host_are_removed(self):
        self.run_sync(build(REQUIRED))
        (self.dest / "stray").mkdir()
        (self.dest / "stray/inner").write_text("x")
        (self.dest / "prometheus/old.yml").write_text("x")
        self.run_sync(build(REQUIRED))
        self.assertFalse((self.dest / "stray").exists())
        self.assertFalse((self.dest / "prometheus/old.yml").exists())

    def test_host_rendered_files_survive_every_sync_untouched(self):
        self.run_sync(build(REQUIRED))
        for rel, data in RENDERED.items():
            (self.dest / rel).parent.mkdir(exist_ok=True)
            (self.dest / rel).write_bytes(data)
            (self.dest / rel).chmod(0o600)
        self.run_sync(build(dict(REQUIRED, **{"prometheus/alerts.yml": b"groups: [new]\n"})))
        for rel, data in RENDERED.items():
            self.assertEqual((self.dest / rel).read_bytes(), data, rel)
            self.assertEqual(stat.S_IMODE((self.dest / rel).stat().st_mode), 0o600, rel)

    def test_an_archive_carrying_a_host_rendered_file_is_refused_and_nothing_changes(self):
        self.run_sync(build(REQUIRED))
        before = snapshot(self.dest)
        for rel in RENDERED:
            with self.subTest(rel=rel), self.assertRaisesRegex(sync.SyncError, "rendered on the host"):
                self.run_sync(build(dict(REQUIRED, **{rel: b"overwrite"})))
        self.assertEqual(snapshot(self.dest), before)

    def test_a_mode_drift_on_the_host_is_repaired(self):
        self.run_sync(build(REQUIRED))
        os.chmod(self.dest / "prometheus/prometheus.yml", 0o600)
        self.out.truncate(0)
        self.out.seek(0)
        self.run_sync(build(REQUIRED))
        self.assertEqual(stat.S_IMODE((self.dest / "prometheus/prometheus.yml").stat().st_mode), 0o644)
        self.assertIn("fixed prometheus/prometheus.yml", self.out.getvalue())

    def test_a_file_where_a_directory_belongs_is_replaced(self):
        self.run_sync(build(REQUIRED))
        (self.dest / "alertmanager/email.gotmpl").unlink()
        (self.dest / "alertmanager/email.gotmpl").mkdir()
        self.run_sync(build(REQUIRED))
        self.assertTrue((self.dest / "alertmanager/email.gotmpl").is_file())

    def test_a_symlink_on_the_host_is_replaced_not_followed(self):
        self.run_sync(build(REQUIRED))
        target = self.root / "outside"
        target.write_text("keep")
        victim = self.dest / "prometheus/alerts.yml"
        victim.unlink()
        victim.symlink_to(target)
        self.run_sync(build(REQUIRED))
        self.assertFalse(victim.is_symlink())
        self.assertEqual(target.read_text(), "keep")


class RefusalTests(unittest.TestCase):
    """Each of these must refuse, and must leave an existing stack untouched."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        self.dest = self.root / "monitoring"
        sync.sync("monitoring", build(REQUIRED), dest_root=str(self.root), owner=IDS, out=io.StringIO())
        self.before = snapshot(self.dest)

    def refuses(self, archive, pattern):
        with self.assertRaisesRegex(sync.SyncError, pattern):
            sync.sync("monitoring", archive, dest_root=str(self.root), owner=IDS, out=io.StringIO())
        self.assertEqual(snapshot(self.dest), self.before)

    def member(self, name, type_, linkname=""):
        info = tarfile.TarInfo(name)
        info.type = type_
        info.linkname = linkname
        return (info, None)

    def test_path_traversal(self):
        self.refuses(build(dict(REQUIRED, **{"../escape.yml": b"x"})), "component")

    def test_absolute_path(self):
        self.refuses(build(dict(REQUIRED, **{"/etc/cron.d/x": b"x"})), "not a plain relative path")

    def test_dot_component_and_odd_characters(self):
        for name in ("a/../b.yml", "sp ace.yml", "semi;colon.yml", ".hidden", "a//b.yml"):
            with self.subTest(name=name):
                self.refuses(build(dict(REQUIRED, **{name: b"x"})), "refusing archive member")

    def test_a_symlink_a_hardlink_and_a_device(self):
        for type_, link in ((tarfile.SYMTYPE, "/etc/shadow"), (tarfile.LNKTYPE, "compose.yml"), (tarfile.CHRTYPE, "")):
            with self.subTest(type=type_):
                self.refuses(build(REQUIRED, extra=[self.member("evil", type_, link)]), "only regular files")

    def test_a_truncated_stream_with_no_end_marker(self):
        self.refuses(build(REQUIRED, end=False), "END-OF-STACK")

    def test_a_stream_cut_through_a_file(self):
        raw = build(REQUIRED).getvalue()
        self.refuses(io.BytesIO(raw[: len(raw) // 2]), "not a readable tar|END-OF-STACK|short read|required file")

    def test_an_empty_stream(self):
        self.refuses(io.BytesIO(b""), "not a readable tar|END-OF-STACK")

    def test_garbage_that_is_not_a_tar(self):
        self.refuses(io.BytesIO(b"this is not a tar archive" * 100), "not a readable tar|END-OF-STACK")

    def test_an_archive_missing_a_required_file(self):
        for missing in REQUIRED:
            if missing == "alertmanager/email.gotmpl":
                continue
            with self.subTest(missing=missing):
                self.refuses(build({k: v for k, v in REQUIRED.items() if k != missing}), "required file")

    def test_a_member_after_the_end_marker(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            for name, data in REQUIRED.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            tar.addfile(tarfile.TarInfo("END-OF-STACK"), io.BytesIO(b""))
            late = tarfile.TarInfo("late.yml")
            late.size = 1
            tar.addfile(late, io.BytesIO(b"x"))
        self.refuses(io.BytesIO(buf.getvalue()), "follows END-OF-STACK")

    def test_a_non_empty_end_marker(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            for name, data in REQUIRED.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            marker = tarfile.TarInfo("END-OF-STACK")
            marker.size = 1
            tar.addfile(marker, io.BytesIO(b"x"))
        self.refuses(io.BytesIO(buf.getvalue()), "not empty")

    def test_an_oversize_file(self):
        big = b"x" * (sync.MAX_FILE_BYTES + 1)
        self.refuses(build(dict(REQUIRED, **{"big.bin": big})), "larger than")

    def test_an_oversize_archive(self):
        extra = {f"f{i}.yml": b"x" * (1 << 20) for i in range(sync.MAX_ARCHIVE_BYTES // (1 << 20) + 2)}
        self.refuses(build(dict(REQUIRED, **extra)), "larger than")

    def test_too_many_entries(self):
        many = {f"d/f{i}.yml": b"x" for i in range(sync.MAX_ENTRIES + 1)}
        self.refuses(build(dict(REQUIRED, **many)), "more than")

    def test_too_deep(self):
        deep = "/".join(["d"] * (sync.MAX_DEPTH + 1)) + "/f.yml"
        self.refuses(build(dict(REQUIRED, **{deep: b"x"})), "deeper")

    def test_a_duplicate_member(self):
        info = tarfile.TarInfo("compose.yml")
        info.size = 1
        self.refuses(build(REQUIRED, extra=[(info, b"x")]), "appears twice")


class RestartTests(unittest.TestCase):
    """The production path: the unit check and the restart, with a recording systemctl."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dest = pathlib.Path(tmp.name) / "monitoring"
        self.stack = sync.Stack(
            dest=str(self.dest),
            unit=sync.STACKS["monitoring"].unit,
            required=sync.STACKS["monitoring"].required,
            host_rendered=sync.STACKS["monitoring"].host_rendered,
        )
        patcher = unittest.mock.patch.dict(sync.STACKS, {"monitoring": self.stack})
        patcher.start()
        self.addCleanup(patcher.stop)

    def go(self, archive, rec):
        return sync.sync("monitoring", archive, owner=IDS, systemctl=rec, out=io.StringIO())

    def test_a_change_restarts_the_unit_exactly_once(self):
        rec = Recorder()
        self.assertEqual(self.go(build(REQUIRED), rec), 0)
        self.assertEqual(rec.restarts, [("restart", "branchleft-compose@monitoring.service")])

    def test_no_change_does_not_restart(self):
        archive = build(REQUIRED).getvalue()
        self.go(io.BytesIO(archive), Recorder())
        rec = Recorder()
        self.assertEqual(self.go(io.BytesIO(archive), rec), 0)
        self.assertEqual(rec.restarts, [])

    def test_a_failed_restart_is_a_failed_run(self):
        rec = Recorder(restart_rc=1)
        self.assertEqual(self.go(build(REQUIRED), rec), 1)

    def test_a_unit_that_is_not_enabled_gets_its_files_but_is_never_started(self):
        rec = Recorder(enabled=False)
        out = io.StringIO()
        rc = sync.sync("monitoring", build(REQUIRED), owner=IDS, systemctl=rec, out=out)
        self.assertEqual(rc, 0)
        self.assertTrue((self.dest / "compose.yml").exists())
        self.assertEqual(rec.restarts, [])
        self.assertIn("NOT RESTARTED", out.getvalue())

    def test_a_refused_archive_never_reaches_the_unit_check_or_restart(self):
        rec = Recorder()
        with self.assertRaises(sync.SyncError):
            self.go(build(REQUIRED, end=False), rec)
        self.assertEqual(rec.calls, [])

    def test_owner_and_mode_are_enforced_when_an_owner_is_given(self):
        calls = []
        real = os.chown
        with unittest.mock.patch.object(sync.os, "chown", lambda p, u, g: (calls.append((str(p), u, g)), real(p, u, g))):
            self.go(build(REQUIRED), Recorder())
        self.assertTrue(calls)
        self.assertTrue(all((u, g) == IDS for _, u, g in calls))


class CommandLineTests(unittest.TestCase):
    def test_an_unknown_stack_is_refused(self):
        with self.assertRaisesRegex(sync.SyncError, "unknown stack"):
            sync.sync("edge", build(REQUIRED), dest_root=tempfile.gettempdir(), owner=None, out=io.StringIO())

    def test_only_the_two_documented_argument_shapes_are_accepted(self):
        for argv in ([], ["monitoring", "extra"], ["--rehearse", "x"], ["--rehearse"], ["--other", "x", "monitoring"]):
            with self.subTest(argv=argv):
                self.assertEqual(sync.main(argv), 2)

    def test_the_registry_names_only_the_monitoring_stack_and_its_secrets_stay_out_of_the_archive(self):
        self.assertEqual(set(sync.STACKS), {"monitoring"})
        self.assertEqual(
            sync.STACKS["monitoring"].host_rendered,
            frozenset(RENDERED),
            "keep this list equal to the host-rendered files in .gitignore and render_alertmanager_config.py",
        )


if __name__ == "__main__":
    unittest.main()
