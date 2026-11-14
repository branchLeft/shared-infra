"""Unit tests for edge_stack_apply: one lock across both phases, the exit-code contract, check mode.

Run from the role's directory with library/ on PYTHONPATH, the way
``ansible/checks/run_role_unit_tests.sh`` does. The module runs against a temporary tree.
``docker`` and ``systemctl`` are stand-ins on PATH: each logs its call and whether the deploy
lock was held by another process at that moment, so the lock is observed from outside, by a
second process, and not read from the module's own state.
"""

import base64
import contextlib
import fcntl
import grp
import hashlib
import importlib.util
import io
import json
import os
import pwd
import re
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import cast
from unittest import mock

import edge_stack_apply as module
from ansible.module_utils.testing import patch_module_args

PIN = "IMAGE=ghcr.io/example/edge@sha256:" + "0" * 63 + "1"
OTHER_PIN = "IMAGE=ghcr.io/example/edge@sha256:" + "f" * 63 + "e"
PATTERN = r"^IMAGE=[a-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}$"
UNIT = "example-compose@edge.service"
CADDYFILE = b"example.invalid {\n  respond 200\n}\n"
COMPOSE = b"services:\n  caddy: {}\n  crowdsec: {}\n"
CONFIG = b"api: {}\n"
ACQUIS = b"source: file\n"
MARKER = "THROWAWAY_CONTENT_MARKER_0001"
REPO = Path(__file__).resolve().parents[5]
USER = pwd.getpwuid(os.getuid()).pw_name
GROUP = grp.getgrgid(os.getgid()).gr_name

# Each call is logged with the kind below and whether another process could take the lock.
STUB = r"""
import fcntl
import json
import os
import sys
import time
from hashlib import sha256

CFG = json.load(open(os.environ["EDGE_STUB_CONFIG"]))
NAME = os.path.basename(sys.argv[0])
ARGS = sys.argv[1:]
STATE = CFG["state"]


def held():
    descriptor = os.open(CFG["lock"], os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return True
    else:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        return False
    finally:
        os.close(descriptor)


def log(kind):
    with open(CFG["log"], "a") as handle:
        state = "HELD" if held() else "FREE"
        handle.write(kind + " lock=" + state + " t=" + str(time.monotonic_ns()) + "\n")


def once(flag):
    marker = os.path.join(STATE, flag)
    if os.path.exists(marker):
        return False
    open(marker, "w").close()
    return True


def count(name):
    marker = os.path.join(STATE, "count-" + name)
    seen = int(open(marker).read()) if os.path.exists(marker) else 0
    open(marker, "w").write(str(seen + 1))
    return seen


def hold(kind):
    if CFG.get("hold") == kind and once("hold-" + kind):
        open(os.path.join(STATE, "entered"), "w").close()
        deadline = time.time() + 30
        while not os.path.exists(os.path.join(STATE, "release")) and time.time() < deadline:
            time.sleep(0.02)


def finish(kind, out=""):
    log(kind)
    hold(kind)
    if CFG.get("move_pin") == kind and once("move-pin"):
        open(CFG["image_env"], "w").write(CFG["other_pin"] + "\n")
    sys.stdout.write(CFG.get("output", {}).get(kind, out))
    sys.exit(CFG.get("fail", {}).get(kind, 0))


def digest(path):
    return sha256(open(path, "rb").read()).hexdigest()


def unknown():
    log("unknown " + NAME + " " + " ".join(ARGS))
    sys.exit(99)


if NAME == "systemctl":
    if ARGS[:1] == ["restart"]:
        finish("unit-restart")
    if ARGS[:2] == ["is-active", "--quiet"]:
        finish("unit-active")
    if ARGS == ["daemon-reload"]:
        finish("daemon-reload")
    unknown()
if ARGS[:1] == ["run"]:
    finish("validate-caddy", "Valid configuration\n")
if ARGS[:1] != ["compose"]:
    unknown()
rest = ARGS[1:]
project = None
env_files = []
while rest and rest[0] in ("--project-directory", "--env-file", "-f"):
    if rest[0] == "--project-directory":
        project = rest[1]
    if rest[0] == "--env-file":
        env_files.append(rest[1])
    rest = rest[2:]
if project != CFG["project"] or env_files != CFG["env_files"]:
    log("compose-called-without-the-project-or-both-env-files")
    sys.exit(2)
if rest == ["config", "-q"]:
    finish("validate-compose")
if rest[:1] == ["ps"]:
    finish("ps", "".join(item + "\n" for item in CFG.get("running", [])))
if rest == ["restart", "crowdsec"]:
    finish("restart-crowdsec")
if rest[:3] == ["exec", "-T", "crowdsec"]:
    tail = rest[3:]
    if tail == ["cscli", "lapi", "status"]:
        if count("lapi") < CFG.get("lapi_down", 0):
            log("lapi-down")
            sys.exit(1)
        finish("lapi")
    if tail[:1] == ["sha256sum"]:
        inside = tail[1]
        single = {
            "/etc/crowdsec/config.yaml.local": "config.yaml.local",
            "/etc/crowdsec/appsec-configs/branchleft-ghost-admin-previews.yaml":
                "ghost-admin-previews.yaml",
            "/etc/crowdsec/postoverflows/s01-whitelist/branchleft-ghost-admin-api.yaml":
                "ghost-admin-api-postoverflow.yaml",
        }
        if inside in single:
            source = project + "/crowdsec/" + single[inside]
        else:
            source = project + "/crowdsec/acquis.d/" + inside.rsplit("/", 1)[1]
        wrong = inside in CFG.get("inside_wrong", [])
        finish("sha-crowdsec", ("0" * 64 if wrong else digest(source)) + "  " + inside + "\n")
    if tail[:2] == ["ls", "-1"]:
        names = CFG.get("inside_listing")
        if names is None:
            names = sorted(
                name for name in os.listdir(project + "/crowdsec/acquis.d")
                if not name.startswith(".")
            )
        finish("ls-crowdsec", "".join(name + "\n" for name in names))
if rest[:3] == ["exec", "-T", "caddy"]:
    tail = rest[3:]
    if tail[:2] == ["caddy", "reload"]:
        finish("reload")
    if tail[:1] == ["sha256sum"]:
        stale = CFG.get("caddy_stale")
        found = "0" * 64 if stale else digest(project + "/caddy/Caddyfile")
        finish("sha-caddy", found + "  " + tail[1] + "\n")
unknown()
"""

HOLDER = r"""
import fcntl
import os
import sys

descriptor = os.open(sys.argv[1], os.O_CREAT | os.O_RDWR, 0o600)
fcntl.flock(descriptor, fcntl.LOCK_EX)
print("held", flush=True)
sys.stdin.readline()
"""

COMPETITOR = r"""
import fcntl
import os
import sys
import time

descriptor = os.open(sys.argv[1], os.O_CREAT | os.O_RDWR, 0o600)
fcntl.flock(descriptor, fcntl.LOCK_EX)
print(time.monotonic_ns(), flush=True)
"""


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_branchleft_deploy() -> ModuleType:
    """Import the deploy program from the repository, the other process that takes the lock.

    Raises:
        AssertionError: The program cannot be loaded.
    """
    path = REPO / "hetzner" / "provision" / "branchleft_deploy.py"
    spec = importlib.util.spec_from_file_location("branchleft_deploy_under_test", path)
    if spec is None or spec.loader is None:
        message = f"cannot load {path}"
        raise AssertionError(message)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


class FakeClock:
    """A clock that moves only when the module sleeps, so a wait for a lock costs no time."""

    def __init__(self) -> None:
        self.now = 0.0
        self.slept: list[float] = []

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds

    def context(self) -> module.Context:
        return module.Context(clock=self.clock, sleep=self.sleep)


class Result:
    """What one run of execute did: its report, the error that stopped it, and the logged calls."""

    def __init__(
        self, report: module.Report, error: module.StepError | None, calls: list[str]
    ) -> None:
        self.report = report
        self.error = error
        self.calls = calls

    @property
    def code(self) -> int:
        return 0 if self.error is None else self.error.code

    @property
    def kinds(self) -> list[str]:
        return [line.split(" lock=", 1)[0] for line in self.calls]

    @property
    def lock_states(self) -> list[str]:
        return [line.split(" lock=", 1)[1].split(" ", 1)[0] for line in self.calls]

    @property
    def last_call_at(self) -> int:
        return max(int(line.rsplit(" t=", 1)[1]) for line in self.calls)


class Tree:
    """A stack on a temporary disk, the stand-ins on PATH, and the arguments to run it."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.project = root / "opt" / "edge"
        self.etc = root / "etc"
        self.var = root / "var"
        self.bin = root / "bin"
        self.state = root / "state"
        self.candidates = self.var / "candidate"
        self.lock = self.etc / "edge.deploy.lock"
        self.image_env = self.etc / "edge.image.env"
        self.env_file = self.etc / "edge.env"
        self.log = root / "stub.log"
        self.config_path = root / "stub.json"
        for directory in (self.project / "caddy", self.project / "crowdsec" / "acquis.d"):
            directory.mkdir(parents=True)
        for directory in (self.etc, self.var, self.bin, self.state, self.candidates):
            directory.mkdir(parents=True, exist_ok=True)
        (self.project / "caddy" / "Caddyfile").write_bytes(b"old\n")
        (self.project / "compose.yml").write_bytes(b"old\n")
        (self.project / "crowdsec" / "config.yaml.local").write_bytes(CONFIG)
        (self.project / "crowdsec" / "ghost-admin-previews.yaml").write_bytes(b"name: a\n")
        (self.project / "crowdsec" / "ghost-admin-api-postoverflow.yaml").write_bytes(b"name: b\n")
        (self.project / "crowdsec" / "acquis.d" / "a.yaml").write_bytes(ACQUIS)
        self.image_env.write_text(PIN + "\n")
        self.env_file.write_text("KEY=throwaway\n")
        (self.candidates / "Caddyfile").write_bytes(CADDYFILE)
        (self.candidates / "compose.yml").write_bytes(COMPOSE)
        for name in ("docker", "systemctl"):
            stub = self.bin / name
            stub.write_text(f"#!{sys.executable}\n{STUB}")
            stub.chmod(0o755)
        self.stub()

    def stub(self, **config: object) -> None:
        """Write the stand-ins' configuration, replacing the last."""
        document: dict[str, object] = {
            "lock": str(self.lock),
            "log": str(self.log),
            "state": str(self.state),
            "project": str(self.project),
            "image_env": str(self.image_env),
            "other_pin": OTHER_PIN,
            "env_files": [str(self.image_env), str(self.env_file)],
            "running": ["caddy", "crowdsec"],
        }
        document.update(config)
        self.config_path.write_text(json.dumps(document))

    def params(self, **changes: object) -> dict[str, object]:
        """Return every argument the module has, as Ansible supplies them, with ``changes`` over."""
        base: dict[str, object] = {
            "project_dir": str(self.project),
            "image_env": str(self.image_env),
            "env_file": str(self.env_file),
            "image_pin_pattern": PATTERN,
            "unit": UNIT,
            "lock_file": str(self.lock),
            "lock_timeout": 600,
            "caddy_candidate": None,
            "compose_candidate": None,
            "caddy_write": False,
            "caddy_reload": False,
            "compose_restart": False,
            "crowdsec_restart": False,
            "wait_tries": 3,
            "wait_interval": 0.0,
            "owner": USER,
            "group": GROUP,
            "pending_stamps": [],
            "pending_text": "pending",
            "dirs": [],
            "files": [],
            "remove": [],
            "fix_modes": [],
            "daemon_reload_needed": False,
        }
        base.update(changes)
        return base

    def everything(self, **changes: object) -> dict[str, object]:
        """Return arguments for a run that validates both candidates and acts on every class."""
        placed = [
            {
                "dest": str(self.project / "compose.yml"),
                "src": str(self.candidates / "compose.yml"),
                "mode": "0644",
            },
            {
                "dest": str(self.project / "crowdsec" / "config.yaml.local"),
                "content_b64": "YXBpOiB7fQo=",
                "mode": "0644",
            },
            {
                "dest": str(self.var / "dropin" / "override.conf"),
                "content_b64": "W1NlcnZpY2VdCg==",
                "mode": "0644",
                "reload": True,
            },
        ]
        wanted: dict[str, object] = {
            "caddy_candidate": str(self.candidates / "Caddyfile"),
            "compose_candidate": str(self.candidates / "compose.yml"),
            "caddy_write": True,
            "caddy_reload": True,
            "compose_restart": True,
            "crowdsec_restart": True,
            "pending_stamps": [str(self.var / "caddy.applied"), str(self.var / "crowdsec.applied")],
            "dirs": [str(self.var / "dropin")],
            "files": placed,
        }
        wanted.update(changes)
        return self.params(**wanted)

    @contextlib.contextmanager
    def on_path(self) -> Iterator[None]:
        environment = {
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "EDGE_STUB_CONFIG": str(self.config_path),
        }
        with mock.patch.dict(os.environ, environment):
            yield

    def calls(self) -> list[str]:
        return self.log.read_text().splitlines() if self.log.exists() else []

    def run(
        self,
        params: dict[str, object],
        *,
        check_mode: bool = False,
        context: module.Context | None = None,
    ) -> Result:
        """Run execute on the arguments and return what happened, without raising."""
        report = module.Report()
        error: module.StepError | None = None
        with self.on_path():
            try:
                module.execute(
                    module.settings_from(params), report, check_mode=check_mode, context=context
                )
            except module.StepError as stopped:
                error = stopped
        return Result(report, error, self.calls())

    def lock_is_free(self) -> bool:
        """Whether another open file description can take the lock right now."""
        descriptor = os.open(self.lock, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                return False
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            return True
        finally:
            os.close(descriptor)

    def snapshot(self, *, ignore_lock: bool = False) -> dict[str, tuple[str, str]]:
        """Return every path under the tree except the stand-ins' own files, with kind and hash."""
        found: dict[str, tuple[str, str]] = {}
        skipped = {self.bin, self.state, self.log, self.config_path}
        if ignore_lock:
            skipped.add(self.lock)
        for path in sorted(self.root.rglob("*")):
            if path in skipped or self.bin in path.parents or self.state in path.parents:
                continue
            relative = path.relative_to(self.root).as_posix()
            if path.is_symlink():
                found[relative] = ("link", os.readlink(path))
            elif path.is_dir():
                found[relative] = ("dir", oct(stat.S_IMODE(path.stat().st_mode)))
            else:
                found[relative] = (
                    "file",
                    sha(path.read_bytes()) + oct(stat.S_IMODE(path.stat().st_mode)),
                )
        return found


class TreeCase(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.tree = Tree(Path(self.directory.name))


def run_main(
    params: dict[str, object], check_mode: bool = False
) -> tuple[bool, dict[str, object], str]:
    """Run main as Ansible would; return (failed, the JSON it printed, the raw text)."""
    arguments = {**params, "_ansible_check_mode": check_mode}
    buffer = io.StringIO()
    with patch_module_args(arguments), contextlib.redirect_stdout(buffer):
        try:
            module.main()
        except SystemExit:
            pass
    raw = buffer.getvalue()
    document: dict[str, object] = json.loads(raw)
    return bool(document.get("failed")), document, raw


def passing_params(tree: Tree) -> dict[str, object]:
    """Arguments of a run that goes all the way through."""
    return tree.everything()


class LockHeldAcrossBothPhases(TreeCase):
    def test_every_command_of_both_phases_and_the_place_between_runs_under_the_lock(self) -> None:
        result = self.tree.run(passing_params(self.tree))
        self.assertIsNone(result.error, result.error and result.error.message)
        self.assertEqual(
            [
                "validate-caddy",
                "validate-compose",
                "daemon-reload",
                "unit-restart",
                "unit-active",
                "ps",
                "ps",
                "ps",
                "restart-crowdsec",
                "lapi",
                # config.yaml.local, the two Ghost admin files, then a.yaml in acquis.d.
                "sha-crowdsec",
                "sha-crowdsec",
                "sha-crowdsec",
                "sha-crowdsec",
                "ls-crowdsec",
                "ps",
                "reload",
                "sha-caddy",
            ],
            result.kinds,
        )
        self.assertEqual(["HELD"] * len(result.calls), result.lock_states)
        self.assertTrue(self.tree.lock_is_free(), "the lock is let go when the module returns")

    def test_a_second_process_waits_whichever_phase_the_module_is_in(self) -> None:
        # The module stops inside one command of each phase: the validation, the placement
        # between the two (the systemd reload), and the apply (the unit restart). A second
        # process asks for the lock at that moment and must not get it until the module ends.
        for phase, kind in (
            ("validate", "validate-caddy"),
            ("between", "daemon-reload"),
            ("apply", "unit-restart"),
        ):
            with self.subTest(phase=phase):
                self.setUp()
                waited, acquired_at, last_command_at, errors = self.compete_while_stopped_in(kind)
                self.assertEqual([], errors)
                self.assertTrue(waited, f"the second process got the lock during {phase}")
                self.assertGreaterEqual(
                    acquired_at, last_command_at, "it got the lock after the module's last command"
                )

    def compete_while_stopped_in(self, kind: str) -> tuple[bool, int, int, list[BaseException]]:
        """Stop the module inside the command ``kind`` and ask for the lock from a second process.

        Returns whether the second process was still waiting half a second later, the time it
        got the lock, the time of the module's last command, and what went wrong in its thread.
        """
        self.tree.stub(hold=kind)
        errors: list[BaseException] = []
        tree = self.tree

        def work() -> None:
            try:
                self.assertIsNone(tree.run(passing_params(tree)).error)
            except BaseException as error:  # noqa: BLE001
                errors.append(error)

        worker = threading.Thread(target=work)
        worker.start()
        self.wait_for(tree.state / "entered")
        competitor = subprocess.Popen(  # noqa: S603
            [sys.executable, "-c", COMPETITOR, str(tree.lock)],
            stdout=subprocess.PIPE,
            text=True,
        )
        time.sleep(0.5)
        waited = competitor.poll() is None
        (tree.state / "release").write_text("")
        worker.join(30)
        output = (competitor.communicate(timeout=30)[0] or "").strip()
        last_command = max(int(line.rsplit(" t=", 1)[1]) for line in tree.calls())
        return waited, int(output), last_command, errors

    def wait_for(self, path: Path) -> None:
        deadline = time.monotonic() + 30
        while not path.exists():
            self.assertLess(time.monotonic(), deadline, f"{path} never appeared")
            time.sleep(0.02)

    def test_branchleft_deploy_cannot_take_the_lock_while_the_module_holds_it(self) -> None:
        deploy = load_branchleft_deploy()
        config_dir = str(self.tree.etc)
        self.assertEqual(str(self.tree.lock), deploy.deploy_lock_path("edge", config_dir))
        self.tree.stub(hold="daemon-reload")

        def work() -> None:
            self.tree.run(passing_params(self.tree))

        worker = threading.Thread(target=work)
        worker.start()
        self.wait_for(self.tree.state / "entered")
        try:
            with (
                self.assertRaises(deploy.DeployError),
                deploy.stack_deploy_lock("edge", config_dir, timeout=0.4, poll_interval=0.05),
            ):
                pass
        finally:
            (self.tree.state / "release").write_text("")
            worker.join(30)

    def test_the_module_cannot_take_the_lock_while_branchleft_deploy_holds_it(self) -> None:
        deploy = load_branchleft_deploy()
        clock = FakeClock()
        with deploy.stack_deploy_lock("edge", str(self.tree.etc), timeout=5):
            result = self.tree.run(passing_params(self.tree), context=clock.context())
        self.assertEqual(module.Code.LOCK_BUSY, result.code)
        self.assertEqual(module.PHASE_LOCK, result.report.phase)
        self.assertEqual([], result.calls)
        self.assertFalse(result.report.changed)

    def test_a_lock_held_by_another_process_is_waited_for_and_then_refused_with_75(self) -> None:
        holder = subprocess.Popen(  # noqa: S603
            [sys.executable, "-c", HOLDER, str(self.tree.lock)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(holder.kill)
        self.assertEqual("held", (holder.stdout.readline() if holder.stdout else "").strip())
        clock = FakeClock()
        before = self.tree.snapshot()
        result = self.tree.run(passing_params(self.tree), context=clock.context())
        self.assertEqual(module.Code.LOCK_BUSY, result.code)
        self.assertIn(
            "was not free within 600 seconds", result.error.message if result.error else ""
        )
        self.assertEqual(module.LOCK_POLL_INTERVAL, clock.slept[0])
        self.assertGreaterEqual(sum(clock.slept), 600)
        self.assertEqual([], result.calls, "no command ran")
        self.assertEqual(before, self.tree.snapshot(), "nothing was placed or marked")

    def test_a_lock_that_is_released_in_time_is_taken(self) -> None:
        holder = subprocess.Popen(  # noqa: S603
            [sys.executable, "-c", HOLDER, str(self.tree.lock)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(holder.kill)
        self.assertEqual("held", (holder.stdout.readline() if holder.stdout else "").strip())

        def release() -> None:
            time.sleep(0.5)
            if holder.stdin:
                holder.stdin.write("\n")
                holder.stdin.flush()

        threading.Thread(target=release).start()
        result = self.tree.run(passing_params(self.tree))
        self.assertEqual(0, result.code, result.error and result.error.message)

    def test_the_lock_is_let_go_after_a_failure_too(self) -> None:
        self.tree.stub(fail={"validate-caddy": 1})
        result = self.tree.run(passing_params(self.tree))
        self.assertEqual(module.Code.CADDY_REFUSED, result.code)
        self.assertTrue(self.tree.lock_is_free())

    def test_the_lock_is_let_go_after_an_unexpected_error_too(self) -> None:
        with mock.patch.object(module, "place", side_effect=RuntimeError("boom")):
            result = self.tree.run(passing_params(self.tree))
        self.assertEqual(module.Code.HOST_ERROR, result.code)
        self.assertEqual("unexpected RuntimeError", result.error.message if result.error else "")
        self.assertTrue(self.tree.lock_is_free())

    def test_a_lock_file_that_cannot_be_opened_is_76(self) -> None:
        self.tree.lock.mkdir()
        result = self.tree.run(passing_params(self.tree))
        self.assertEqual(module.Code.LOCK_UNUSABLE, result.code)
        self.assertEqual([], result.calls)

    def test_nothing_to_validate_or_act_on_takes_no_lock(self) -> None:
        params = self.tree.params(
            files=[{"dest": str(self.tree.var / "x.conf"), "content_b64": "eAo=", "mode": "0644"}]
        )
        result = self.tree.run(params)
        self.assertIsNone(result.error)
        self.assertFalse(self.tree.lock.exists(), "the lock file was not even opened")
        self.assertEqual(b"x\n", (self.tree.var / "x.conf").read_bytes())
        self.assertEqual([], result.calls)


class ExitCodeContract(TreeCase):
    def test_the_codes_are_the_documented_set_and_each_has_one_name(self) -> None:
        self.assertEqual({0, *range(64, 78)}, {int(code) for code in module.Code})
        names = [module.outcome_name(code) for code in module.Code]
        self.assertEqual(len(names), len(set(names)))
        for code in module.Code:
            if code is not module.Code.OK:
                documented = re.search(rf"\b{int(code)}\b", module.RETURN)
                self.assertIsNotNone(documented, f"{code.name} is not documented")

    def test_a_code_outside_the_set_has_no_outcome(self) -> None:
        for code in (1, 2, 63, 78, 99, 126, 127, 128, 255, 256, -1):
            with self.subTest(code=code):
                self.assertIsNone(module.outcome_of(code))

    def test_main_fails_a_code_outside_the_set_and_says_so(self) -> None:
        for code in (1, 63, 78, 255, -1):
            with self.subTest(code=code):
                stop = module.StepError(code, "a step stopped")
                with mock.patch.object(module, "execute", side_effect=stop):
                    failed, document, _ = run_main(self.tree.params())
                self.assertTrue(failed)
                self.assertEqual("unmapped", document["outcome"])
                self.assertEqual(code, document["code"])
                self.assertIn("is not in the contract", str(document["msg"]))

    def test_main_does_not_take_a_stop_with_code_zero_for_success(self) -> None:
        stop = module.StepError(0, "a step stopped with the success code")
        with mock.patch.object(module, "execute", side_effect=stop):
            failed, document, _ = run_main(self.tree.params())
        self.assertTrue(failed)
        self.assertEqual("unmapped", document["outcome"])

    def test_every_named_failure_is_reported_with_its_code_and_name(self) -> None:
        for code in module.Code:
            if code is module.Code.OK:
                continue
            with self.subTest(code=code.name):
                stop = module.StepError(code, "a step stopped")
                with mock.patch.object(module, "execute", side_effect=stop):
                    failed, document, _ = run_main(self.tree.params())
                self.assertTrue(failed)
                self.assertEqual(int(code), document["code"])
                self.assertEqual(module.outcome_name(code), document["outcome"])
                self.assertIn(f"exit code {int(code)}", str(document["msg"]))

    def test_success_is_code_zero_and_ok(self) -> None:
        failed, document, _ = run_main(self.tree.params())
        self.assertFalse(failed)
        self.assertEqual(0, document["code"])
        self.assertEqual("ok", document["outcome"])

    def expect(self, code: module.Code, params: dict[str, object] | None = None) -> Result:
        result = self.tree.run(params or passing_params(self.tree), context=FakeClock().context())
        self.assertEqual(
            code,
            result.code,
            result.error.message if result.error else "the run did not stop",
        )
        return result

    def test_64_the_pin_is_not_exactly_one_matching_line(self) -> None:
        for name, content in (
            ("tag", "IMAGE=ghcr.io/example/edge:latest\n"),
            ("two lines", PIN + "\n" + PIN + "\n"),
            ("trailing text", PIN + " x\n"),
            ("empty", ""),
            ("blank line", "\n"),
            ("no prefix", PIN.removeprefix("IMAGE=") + "\n"),
        ):
            with self.subTest(pin=name):
                self.setUp()
                self.tree.image_env.write_text(content)
                result = self.expect(module.Code.PIN_REFUSED)
                self.assertEqual(module.PHASE_VALIDATE, result.report.phase)
                self.assertEqual([], result.calls, "nothing was validated")
                self.assertEqual(b"old\n", (self.tree.project / "compose.yml").read_bytes())
                self.assertFalse((self.tree.var / "caddy.applied").exists())

    def test_64_a_pin_file_that_is_not_there(self) -> None:
        self.tree.image_env.unlink()
        self.expect(module.Code.PIN_REFUSED)

    def test_64_a_last_line_without_a_line_break_is_still_a_line(self) -> None:
        self.tree.image_env.write_text(PIN)
        self.assertIsNone(self.tree.run(passing_params(self.tree)).error)

    def test_65_the_candidate_caddyfile_is_refused(self) -> None:
        self.tree.stub(fail={"validate-caddy": 1}, output={"validate-caddy": "Error: broken\n"})
        result = self.expect(module.Code.CADDY_REFUSED)
        self.assertEqual("Error: broken", result.error.detail if result.error else "")
        self.assertEqual(["validate-caddy"], result.kinds)
        self.assertEqual(b"old\n", (self.tree.project / "caddy" / "Caddyfile").read_bytes())

    def test_65_a_validation_that_does_not_say_valid_is_refused_too(self) -> None:
        self.tree.stub(output={"validate-caddy": "nothing to say\n"})
        self.expect(module.Code.CADDY_REFUSED)

    def test_67_the_candidate_compose_file_is_refused(self) -> None:
        self.tree.stub(fail={"validate-compose": 1})
        result = self.expect(module.Code.COMPOSE_REFUSED)
        self.assertEqual(["validate-caddy", "validate-compose"], result.kinds)
        self.assertEqual(module.PHASE_VALIDATE, result.report.phase)
        self.assertEqual([], result.report.marked)
        self.assertFalse((self.tree.var / "dropin").exists(), "nothing was placed")

    def test_66_the_caddyfile_on_the_host_is_not_a_plain_file(self) -> None:
        caddyfile = self.tree.project / "caddy" / "Caddyfile"
        caddyfile.unlink()
        caddyfile.mkdir()
        result = self.expect(module.Code.CADDYFILE_WRITE)
        self.assertEqual(module.PHASE_APPLY, result.report.phase)
        self.assertEqual([], result.report.markers)

    def test_66_the_caddyfile_on_the_host_is_a_link(self) -> None:
        caddyfile = self.tree.project / "caddy" / "Caddyfile"
        target = self.tree.var / "elsewhere"
        target.write_bytes(b"elsewhere\n")
        caddyfile.unlink()
        caddyfile.symlink_to(target)
        self.expect(module.Code.CADDYFILE_WRITE)
        self.assertEqual(
            b"elsewhere\n", target.read_bytes(), "the write did not go through the link"
        )

    def test_66_a_caddyfile_that_is_not_there_is_made_and_written(self) -> None:
        (self.tree.project / "caddy" / "Caddyfile").unlink()
        self.assertIsNone(self.tree.run(passing_params(self.tree)).error)
        written = self.tree.project / "caddy" / "Caddyfile"
        self.assertEqual(CADDYFILE, written.read_bytes())
        self.assertEqual(0o644, stat.S_IMODE(written.stat().st_mode))

    def test_66_the_caddyfile_is_written_in_place_and_keeps_its_inode(self) -> None:
        caddyfile = self.tree.project / "caddy" / "Caddyfile"
        inode = caddyfile.stat().st_ino
        self.assertIsNone(self.tree.run(passing_params(self.tree)).error)
        self.assertEqual(inode, caddyfile.stat().st_ino)
        self.assertEqual(CADDYFILE, caddyfile.read_bytes())

    def test_68_the_unit_does_not_restart(self) -> None:
        self.tree.stub(fail={"unit-restart": 1})
        result = self.expect(module.Code.UNIT_RESTART)
        self.assertEqual(["caddy-written"], result.report.markers)

    def test_69_the_unit_is_not_active_after_the_restart(self) -> None:
        self.tree.stub(fail={"unit-active": 3})
        self.expect(module.Code.UNIT_NOT_UP)

    def test_69_a_service_is_not_running_after_the_restart(self) -> None:
        self.tree.stub(running=["caddy"])
        result = self.expect(module.Code.UNIT_NOT_UP)
        self.assertIn("crowdsec is not running", result.error.message if result.error else "")

    def test_70_the_crowdsec_restart_fails(self) -> None:
        self.tree.stub(fail={"restart-crowdsec": 1})
        result = self.expect(module.Code.CROWDSEC_RESTART)
        self.assertEqual(["caddy-written", "compose-restarted"], result.report.markers)

    def test_71_crowdsec_api_never_answers(self) -> None:
        self.tree.stub(lapi_down=99)
        clock = FakeClock()
        result = self.tree.run(
            passing_params(self.tree) | {"wait_tries": 3, "wait_interval": 5.0},
            context=clock.context(),
        )
        self.assertEqual(module.Code.CROWDSEC_READBACK, result.code)
        self.assertEqual([5.0, 5.0], clock.slept, "three asks, a wait between each")
        self.assertIn("after 3 tries", result.error.message if result.error else "")

    def test_71_the_api_answers_on_the_second_ask(self) -> None:
        self.tree.stub(lapi_down=1)
        result = self.tree.run(passing_params(self.tree), context=FakeClock().context())
        self.assertIsNone(result.error)
        self.assertIn("crowdsec-restarted", result.report.markers)

    def test_71_a_file_inside_crowdsec_is_not_the_file_on_the_host(self) -> None:
        self.tree.stub(inside_wrong=["/etc/crowdsec-acquis.d/a.yaml"])
        result = self.expect(module.Code.CROWDSEC_READBACK)
        self.assertEqual(["caddy-written", "compose-restarted"], result.report.markers)

    def test_71_the_acquisition_directory_inside_lists_other_files(self) -> None:
        self.tree.stub(inside_listing=["a.yaml", "stale.yaml"])
        self.expect(module.Code.CROWDSEC_READBACK)

    def test_71_a_failed_read_inside_crowdsec(self) -> None:
        self.tree.stub(fail={"sha-crowdsec": 1})
        self.expect(module.Code.CROWDSEC_READBACK)

    def test_72_the_caddy_reload_fails(self) -> None:
        self.tree.stub(fail={"reload": 1})
        result = self.expect(module.Code.CADDY_RELOAD)
        self.assertEqual(
            ["caddy-written", "compose-restarted", "crowdsec-restarted"], result.report.markers
        )

    def test_73_the_caddyfile_inside_caddy_is_not_the_one_on_the_host(self) -> None:
        self.tree.stub(caddy_stale=True)
        result = self.expect(module.Code.CADDY_READBACK)
        self.assertNotIn("caddy-reloaded", result.report.markers)

    def test_74_the_pin_moved_after_the_validation(self) -> None:
        self.tree.stub(move_pin="validate-caddy")
        result = self.expect(module.Code.PIN_MOVED)
        self.assertEqual(module.PHASE_APPLY, result.report.phase)
        self.assertEqual(
            "changed since the candidates were validated",
            (result.error.message if result.error else "").split(" ", 1)[1],
        )
        self.assertEqual([], result.report.markers, "no action was taken on the new pin")
        self.assertEqual(b"old\n", (self.tree.project / "caddy" / "Caddyfile").read_bytes())
        self.assertNotIn("unit-restart", result.kinds)
        self.assertEqual(
            "pending",
            (self.tree.var / "caddy.applied").read_text().strip(),
            "the class stays pending, so the next run acts",
        )

    def test_74_a_pin_that_is_no_longer_valid_at_the_apply_is_64(self) -> None:
        self.tree.stub(move_pin="validate-caddy", other_pin="IMAGE=not-a-digest")
        result = self.expect(module.Code.PIN_REFUSED)
        self.assertEqual(module.PHASE_APPLY, result.report.phase)

    def test_77_a_file_to_remove_cannot_be_removed(self) -> None:
        stuck = self.tree.var / "stuck"
        stuck.mkdir()
        (stuck / "file").write_text("x")
        stuck.chmod(0o500)
        self.addCleanup(stuck.chmod, 0o700)
        if os.geteuid() == 0:
            self.skipTest("root removes it")
        params = passing_params(self.tree) | {"remove": [str(stuck)]}
        result = self.expect(module.Code.HOST_ERROR, params)
        self.assertEqual(module.PHASE_PLACE, result.report.phase)
        self.assertEqual(["validate-caddy", "validate-compose"], result.kinds, "no action ran")
        self.assertEqual(COMPOSE, (self.tree.project / "compose.yml").read_bytes())

    def test_77_a_source_that_is_not_there(self) -> None:
        files = [
            {"dest": str(self.tree.var / "x"), "src": str(self.tree.var / "none"), "mode": "0644"}
        ]
        result = self.expect(module.Code.HOST_ERROR, passing_params(self.tree) | {"files": files})
        self.assertEqual(module.PHASE_PLACE, result.report.phase)

    def test_77_a_destination_that_is_a_link(self) -> None:
        target = self.tree.var / "target"
        target.write_bytes(b"x")
        destination = self.tree.var / "x"
        destination.symlink_to(target)
        files = [{"dest": str(destination), "content_b64": "eQ==", "mode": "0644"}]
        self.expect(module.Code.HOST_ERROR, passing_params(self.tree) | {"files": files})
        self.assertEqual(b"x", target.read_bytes())

    def test_77_the_reload_of_systemd_fails(self) -> None:
        self.tree.stub(fail={"daemon-reload": 1})
        result = self.expect(module.Code.HOST_ERROR)
        self.assertEqual(module.PHASE_PLACE, result.report.phase)

    def test_the_markers_of_a_full_run_come_in_the_order_the_script_printed_them(self) -> None:
        result = self.tree.run(passing_params(self.tree), context=FakeClock().context())
        self.assertIsNone(result.error)
        self.assertEqual(
            [
                "caddy-written",
                "compose-restarted",
                "crowdsec-restarted",
                "caddy-reloaded",
            ],
            result.report.markers,
        )
        self.assertEqual(["caddy-validated", "compose-validated"], result.report.validated)
        self.assertEqual(PIN.removeprefix("IMAGE="), result.report.pin)

    def test_a_class_that_is_not_running_is_skipped_and_said(self) -> None:
        params = passing_params(self.tree) | {"compose_restart": False}
        self.tree.stub(running=[])
        result = self.tree.run(params, context=FakeClock().context())
        self.assertIsNone(result.error)
        self.assertEqual(
            ["caddy-written", "crowdsec-not-running", "caddy-not-running"], result.report.markers
        )


class Placement(TreeCase):
    def test_a_refused_candidate_leaves_the_host_as_it_was(self) -> None:
        self.tree.stub(fail={"validate-compose": 1})
        before = self.tree.snapshot(ignore_lock=True)
        result = self.tree.run(passing_params(self.tree))
        self.assertEqual(module.Code.COMPOSE_REFUSED, result.code)
        self.assertEqual(before, self.tree.snapshot(ignore_lock=True))

    def test_files_stamps_and_directories_are_placed_with_their_modes(self) -> None:
        result = self.tree.run(passing_params(self.tree), context=FakeClock().context())
        self.assertIsNone(result.error)
        self.assertEqual(COMPOSE, (self.tree.project / "compose.yml").read_bytes())
        self.assertEqual(b"[Service]\n", (self.tree.var / "dropin" / "override.conf").read_bytes())
        self.assertEqual(
            0o755, stat.S_IMODE((self.tree.var / "dropin").stat().st_mode), "directory mode"
        )
        for stamp in ("caddy.applied", "crowdsec.applied"):
            path = self.tree.var / stamp
            self.assertEqual("pending\n", path.read_text())
            self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))

    def test_a_second_run_with_nothing_to_act_on_changes_nothing(self) -> None:
        params = passing_params(self.tree) | {
            "caddy_candidate": None,
            "compose_candidate": None,
            "caddy_write": False,
            "caddy_reload": False,
            "compose_restart": False,
            "crowdsec_restart": False,
        }
        first = self.tree.run(params)
        second = self.tree.run(params)
        self.assertTrue(first.report.changed)
        self.assertFalse(second.report.changed)
        self.assertEqual([], second.report.placed + second.report.marked)

    def test_a_file_with_the_right_bytes_keeps_its_inode_and_has_its_mode_set(self) -> None:
        target = self.tree.var / "kept.conf"
        target.write_bytes(b"x\n")
        target.chmod(0o600)
        inode = target.stat().st_ino
        files = [{"dest": str(target), "content_b64": "eAo=", "mode": "0644"}]
        result = self.tree.run(self.tree.params(files=files))
        self.assertEqual([str(target)], result.report.placed)
        self.assertEqual(inode, target.stat().st_ino)
        self.assertEqual(0o644, stat.S_IMODE(target.stat().st_mode))

    def test_a_file_with_other_bytes_is_replaced_by_rename(self) -> None:
        target = self.tree.var / "replaced.conf"
        target.write_bytes(b"old\n")
        files = [{"dest": str(target), "content_b64": "eAo=", "mode": "0644"}]
        self.assertIsNone(self.tree.run(self.tree.params(files=files)).error)
        self.assertEqual(b"x\n", target.read_bytes())
        self.assertEqual(
            [], [p for p in self.tree.var.iterdir() if p.name.startswith(".edge-stack-")]
        )

    def test_systemd_is_reloaded_when_a_flagged_file_changed_and_not_otherwise(self) -> None:
        dropin = self.tree.var / "override.conf"
        files = [{"dest": str(dropin), "content_b64": "eAo=", "mode": "0644", "reload": True}]
        first = self.tree.run(self.tree.params(files=files))
        second = self.tree.run(self.tree.params(files=files))
        self.assertTrue(first.report.reloaded)
        self.assertFalse(second.report.reloaded)
        self.assertEqual(["daemon-reload"], first.kinds)
        self.assertEqual(["daemon-reload"], second.kinds, "the second run made no second reload")

    def test_systemd_is_reloaded_when_it_says_it_is_behind_even_if_no_file_changed(self) -> None:
        result = self.tree.run(self.tree.params(daemon_reload_needed=True))
        self.assertTrue(result.report.reloaded)
        self.assertFalse(result.report.changed, "a reload alone is not a change")

    def test_a_pruned_path_is_removed_and_one_that_is_not_there_is_fine(self) -> None:
        gone = self.tree.project / "crowdsec" / "acquis.d" / "stale.yaml"
        gone.write_text("x")
        result = self.tree.run(self.tree.params(remove=[str(gone), str(gone) + ".none"]))
        self.assertFalse(gone.exists())
        self.assertEqual([str(gone)], result.report.placed)

    def test_the_mode_of_a_file_that_is_there_is_set_and_one_that_is_not_is_left(self) -> None:
        caddyfile = self.tree.project / "caddy" / "Caddyfile"
        caddyfile.chmod(0o600)
        missing = self.tree.var / "none"
        result = self.tree.run(
            self.tree.params(
                fix_modes=[
                    {"path": str(caddyfile), "mode": "0644"},
                    {"path": str(missing), "mode": "0644"},
                ]
            )
        )
        self.assertEqual(0o644, stat.S_IMODE(caddyfile.stat().st_mode))
        self.assertEqual([str(caddyfile)], result.report.placed)
        self.assertFalse(missing.exists())

    def test_content_that_is_not_the_sha256_given_for_it_refuses_the_call(self) -> None:
        files = [
            {
                "dest": str(self.tree.var / "x"),
                "content_b64": "eAo=",
                "sha256": sha(b"y\n"),
                "mode": "0644",
            }
        ]
        with self.assertRaises(module.SettingsError):
            module.settings_from(self.tree.params(files=files))

    def test_content_that_is_the_sha256_given_for_it_is_placed(self) -> None:
        files = [
            {
                "dest": str(self.tree.var / "x"),
                "content_b64": "eAo=",
                "sha256": sha(b"x\n"),
                "mode": "0644",
            }
        ]
        self.assertIsNone(self.tree.run(self.tree.params(files=files)).error)

    def test_arguments_that_are_not_usable_refuse_the_call_before_anything_is_done(self) -> None:
        bad: list[dict[str, object]] = [
            {"image_pin_pattern": "("},
            {"owner": "no-such-user-xyz"},
            {"files": [{"dest": "/x", "content_b64": "not base64!", "mode": "0644"}]},
            {"files": [{"dest": "/x", "content_b64": "eAo=", "mode": "rw-r--r--"}]},
            {"fix_modes": [{"path": "/x", "mode": "999"}]},
        ]
        for changes in bad:
            with self.subTest(changes=list(changes)):
                with self.assertRaises(module.SettingsError):
                    module.settings_from(self.tree.params(**changes))

    def test_a_refusal_of_the_arguments_through_main_is_a_failure_with_no_outcome_code(
        self,
    ) -> None:
        failed, document, _ = run_main(self.tree.params(image_pin_pattern="("))
        self.assertTrue(failed)
        self.assertEqual("unusable-arguments", document["outcome"])
        self.assertEqual([], self.tree.calls())

    def test_a_write_of_the_caddyfile_without_a_candidate_is_refused_by_the_argument_check(
        self,
    ) -> None:
        failed, _, _ = run_main(self.tree.params(caddy_write=True))
        self.assertTrue(failed)

    def test_no_content_comes_back_in_the_result(self) -> None:
        secret = MARKER.encode()
        files = [
            {
                "dest": str(self.tree.var / "marker.conf"),
                "content_b64": base64.b64encode(secret).decode(),
                "mode": "0644",
            }
        ]
        failed, _, raw = run_main(self.tree.params(files=files))
        self.assertFalse(failed)
        self.assertNotIn(MARKER, raw)
        self.assertNotIn(base64.b64encode(secret).decode(), raw)
        self.assertEqual(secret, (self.tree.var / "marker.conf").read_bytes())


class CheckMode(TreeCase):
    def test_check_mode_changes_nothing_takes_no_lock_and_runs_no_command(self) -> None:
        self.tree.lock.unlink(missing_ok=True)
        before = self.tree.snapshot()
        failed, document, _ = run_main(passing_params(self.tree), check_mode=True)
        self.assertFalse(failed)
        self.assertEqual(before, self.tree.snapshot(), "no file, directory, stamp or lock appeared")
        self.assertEqual([], self.tree.calls(), "no command ran")
        self.assertTrue(document["changed"], "it says a change would be made")
        self.assertEqual([], document["markers"])
        self.assertEqual(False, document["reloaded"])

    def test_check_mode_does_not_wait_for_a_lock_that_is_held(self) -> None:
        holder = subprocess.Popen(  # noqa: S603
            [sys.executable, "-c", HOLDER, str(self.tree.lock)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(holder.kill)
        self.assertEqual("held", (holder.stdout.readline() if holder.stdout else "").strip())
        started = time.monotonic()
        failed, _, _ = run_main(passing_params(self.tree) | {"lock_timeout": 30}, check_mode=True)
        self.assertFalse(failed)
        self.assertLess(time.monotonic() - started, 5)

    def test_check_mode_reports_no_change_for_a_host_that_already_matches(self) -> None:
        params = self.tree.params(
            pending_stamps=[str(self.tree.var / "caddy.applied")],
            files=[{"dest": str(self.tree.var / "x"), "content_b64": "eAo=", "mode": "0644"}],
        )
        self.assertFalse(run_main(params)[0])
        before = self.tree.snapshot()
        failed, document, _ = run_main(params, check_mode=True)
        self.assertFalse(failed)
        self.assertFalse(document["changed"])
        self.assertEqual(before, self.tree.snapshot())

    def test_check_mode_with_a_candidate_that_is_not_yet_on_disk_does_not_fail(self) -> None:
        (self.tree.candidates / "compose.yml").unlink()
        failed, document, _ = run_main(passing_params(self.tree), check_mode=True)
        self.assertFalse(failed)
        self.assertTrue(document["changed"])

    def test_check_mode_reports_the_same_paths_a_real_run_changes(self) -> None:
        _, planned, _ = run_main(passing_params(self.tree), check_mode=True)
        with self.tree.on_path():
            failed, applied, _ = run_main(passing_params(self.tree))
        self.assertFalse(failed, applied.get("msg"))
        self.assertNotEqual([], planned["placed"])
        self.assertEqual(
            sorted(cast("list[str]", planned["placed"])),
            sorted(cast("list[str]", applied["placed"])),
        )
        self.assertEqual(planned["marked"], applied["marked"])


if __name__ == "__main__":
    unittest.main()
