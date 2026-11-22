#!/usr/bin/env python3
"""Tests for tenants_state_rewrap: unit tests, and a real pulumi on a throwaway file backend.

The real-pulumi tests skip with no binary on PATH; REWRAP_REQUIRE_PULUMI=1 makes that a failure.
Narrative: scripts/tenants_state_rewrap.md.
"""

from __future__ import annotations

import contextlib
import copy
import datetime
import io
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Iterator, Sequence
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import tenants_state_rewrap as rw

PULUMI = shutil.which("pulumi")
REQUIRE_PULUMI = os.environ.get("REWRAP_REQUIRE_PULUMI") == "1"

FAKE_SALT_OLD = "v1:OLDSALTAAAA=:v1:OLDNONCEAAAAAAA:OLDWRAPPEDKNOWNPLAINTEXT=="
FAKE_SALT_NEW = "v1:NEWSALTBBBB=:v1:NEWNONCEBBBBBBB:NEWWRAPPEDKNOWNPLAINTEXT=="
SIG = {rw.SECRET_SIG_KEY: rw.SECRET_SIG_VALUE}


def export_doc(*, resources: list[dict[str, object]] | None = None) -> dict[str, object]:
    """A `pulumi stack export` shaped document with fake, obviously non-real content."""
    if resources is None:
        resources = [
            {
                "urn": "urn:pulumi:production::proj::pulumi:pulumi:Stack::proj-production",
                "type": "pulumi:pulumi:Stack",
                "outputs": {"ip": "203.0.113.7"},
            },
            {
                "urn": "urn:pulumi:production::proj::hcloud:index/server:Server::edge",
                "type": "hcloud:index/server:Server",
                "id": "111",
                "inputs": {"name": "edge"},
                "outputs": {"ipv4": "203.0.113.7"},
            },
        ]
    return {
        "version": 3,
        "deployment": {
            "manifest": {"time": "2026-11-08T23:28:00Z", "magic": "m", "version": "v3.255.0"},
            "secrets_providers": {"type": "passphrase", "state": {"salt": FAKE_SALT_OLD}},
            "resources": resources,
            "metadata": {},
        },
    }


def new_block() -> dict[str, object]:
    return {"type": "passphrase", "state": {"salt": FAKE_SALT_NEW}}


def deployment(doc: dict[str, object]) -> dict[str, object]:
    return rw.deployment_of(doc)


def child(obj: dict[str, object], key: str) -> dict[str, object]:
    value = obj[key]
    assert isinstance(value, dict)  # noqa: S101
    return value


def resource(doc: dict[str, object], index: int) -> dict[str, object]:
    resources = deployment(doc)["resources"]
    assert isinstance(resources, list)  # noqa: S101
    item = resources[index]
    assert isinstance(item, dict)  # noqa: S101
    return item


class CountEncryptedTests(unittest.TestCase):
    def test_a_clean_document_has_none(self) -> None:
        self.assertEqual(rw.count_encrypted(export_doc()), 0)

    def test_a_ciphertext_key_is_counted(self) -> None:
        doc = export_doc()
        child(resource(doc, 1), "outputs")["token"] = {"ciphertext": "v1:FAKE"}
        self.assertEqual(rw.count_encrypted(doc), 1)

    def test_the_secret_signature_is_counted_even_without_a_ciphertext_key(self) -> None:
        doc = export_doc()
        child(resource(doc, 1), "inputs")["token"] = dict(SIG)
        self.assertEqual(rw.count_encrypted(doc), 1)

    def test_a_secret_nested_in_a_list_is_counted(self) -> None:
        doc = export_doc()
        child(resource(doc, 0), "outputs")["many"] = [
            [{"ciphertext": "a"}],
            {"x": {"ciphertext": "b"}},
        ]
        self.assertEqual(rw.count_encrypted(doc), 2)

    def test_a_signature_with_another_value_is_not_a_secret(self) -> None:
        doc = export_doc()
        child(resource(doc, 0), "outputs")["asset"] = {rw.SECRET_SIG_KEY: "something-else"}
        self.assertEqual(rw.count_encrypted(doc), 0)

    def test_the_salt_in_the_provider_block_is_not_an_encrypted_value(self) -> None:
        self.assertEqual(rw.count_encrypted(export_doc()), 0)
        self.assertIn("salt", json.dumps(export_doc()))

    def test_a_plaintext_export_is_counted_apart(self) -> None:
        doc = export_doc()
        child(resource(doc, 0), "outputs")["t"] = {"plaintext": '"x"'}
        self.assertEqual(rw.count_plaintext(doc), 1)


class GateTests(unittest.TestCase):
    def test_a_clean_state_passes(self) -> None:
        found = rw.inspect_export(export_doc())
        self.assertEqual(rw.gate_problems(found), [])
        self.assertEqual(found.resource_count, 2)
        self.assertEqual(found.resource_types["hcloud:index/server:Server"], 1)

    def test_one_encrypted_value_stops_it(self) -> None:
        doc = export_doc()
        child(resource(doc, 1), "outputs")["k"] = {"ciphertext": "v1:FAKE"}
        problems = rw.gate_problems(rw.inspect_export(doc))
        self.assertEqual(len(problems), 1)
        self.assertIn("encrypted value", problems[0])

    def test_pending_operations_stop_it(self) -> None:
        doc = export_doc()
        deployment(doc)["pending_operations"] = [{"type": "creating", "resource": {}}]
        self.assertTrue(any("pending" in p for p in rw.gate_problems(rw.inspect_export(doc))))

    def test_a_non_passphrase_provider_stops_it(self) -> None:
        doc = export_doc()
        deployment(doc)["secrets_providers"] = {"type": "service", "state": {}}
        self.assertTrue(any("provider" in p for p in rw.gate_problems(rw.inspect_export(doc))))

    def test_an_empty_state_stops_it(self) -> None:
        self.assertTrue(rw.gate_problems(rw.inspect_export(export_doc(resources=[]))))

    def test_a_document_that_is_not_an_export_is_refused(self) -> None:
        with self.assertRaises(rw.RefusalError):
            rw.inspect_export({"hello": "world"})

    def test_the_description_names_counts_and_types_and_never_a_value(self) -> None:
        report = rw.Report()
        with contextlib.redirect_stdout(io.StringIO()):
            rw.describe(rw.inspect_export(export_doc()), report)
        text = "\n".join(report.lines)
        self.assertIn("1 x hcloud:index/server:Server", text)
        for private in ("203.0.113.7", "urn:pulumi", FAKE_SALT_OLD, '"111"', "edge"):
            self.assertNotIn(private, text)


class SwapTests(unittest.TestCase):
    def with_new_block(self, doc: dict[str, object]) -> dict[str, object]:
        new = copy.deepcopy(doc)
        deployment(new)["secrets_providers"] = new_block()
        return new

    def test_only_the_provider_block_changes(self) -> None:
        old = export_doc()
        new = rw.swap_secrets_provider(old, new_block())
        self.assertEqual(deployment(new)["secrets_providers"], new_block())
        self.assertEqual(
            rw.canonical(rw.without_secrets_providers(old)),
            rw.canonical(rw.without_secrets_providers(new)),
        )
        self.assertEqual(old, export_doc(), "the input document is not mutated")

    def test_a_second_changed_key_is_refused(self) -> None:
        old = export_doc()
        new = self.with_new_block(old)
        child(deployment(new), "manifest")["time"] = "2026-11-21T00:00:00Z"
        with self.assertRaises(rw.RefusalError) as caught:
            rw.require_only_provider_changed(old, new)
        self.assertIn("more than", str(caught.exception))

    def test_a_dropped_resource_is_refused(self) -> None:
        old = export_doc()
        new = self.with_new_block(old)
        resources = deployment(new)["resources"]
        assert isinstance(resources, list)  # noqa: S101
        del resources[1]
        with self.assertRaises(rw.RefusalError):
            rw.require_only_provider_changed(old, new)

    def test_a_top_level_key_added_is_refused(self) -> None:
        old = export_doc()
        new = self.with_new_block(old)
        new["features"] = ["x"]
        with self.assertRaises(rw.RefusalError):
            rw.require_only_provider_changed(old, new)

    def test_true_is_not_one(self) -> None:
        old = export_doc()
        resource(old, 0)["protect"] = True
        new = self.with_new_block(old)
        resource(new, 0)["protect"] = 1
        self.assertEqual(resource(old, 0)["protect"], resource(new, 0)["protect"])
        with self.assertRaises(rw.RefusalError):
            rw.require_only_provider_changed(old, new)

    def test_an_unchanged_block_is_refused(self) -> None:
        with self.assertRaises(rw.RefusalError):
            rw.swap_secrets_provider(export_doc(), deployment(export_doc())["secrets_providers"])

    def test_a_block_without_a_salt_or_of_another_type_is_refused(self) -> None:
        for bad in ({"type": "passphrase", "state": {}}, {"type": "service"}, None, "x"):
            with self.subTest(bad=bad), self.assertRaises(rw.RefusalError):
                rw.swap_secrets_provider(export_doc(), bad)


def step(op: str, kind: str, name: str = "n") -> dict[str, str]:
    return {"op": op, "urn": f"urn:pulumi:production::proj::{kind}::{name}"}


class PlanTests(unittest.TestCase):
    def plan(self, *steps: dict[str, str]) -> str:
        return json.dumps({"steps": list(steps), "changeSummary": {}})

    def test_same_steps_and_a_stackreference_read_pass(self) -> None:
        counts, problems = rw.plan_problems(
            self.plan(
                step("same", "pulumi:pulumi:Stack"), step("read", "pulumi:pulumi:StackReference")
            )
        )
        self.assertEqual((counts, problems), ({"same": 1, "read": 1}, []))

    def test_a_parent_chain_in_the_urn_is_read_by_its_last_type(self) -> None:
        _, problems = rw.plan_problems(
            self.plan(
                step("same", "pulumi:pulumi:Stack"),
                step("read", "x:y:Component$pulumi:pulumi:StackReference"),
            )
        )
        self.assertEqual(problems, [])

    def test_every_other_op_is_named_by_op_and_type(self) -> None:
        for op in (
            "create",
            "update",
            "replace",
            "delete",
            "create-replacement",
            "discard",
            "refresh",
        ):
            with self.subTest(op=op):
                _, problems = rw.plan_problems(
                    self.plan(
                        step("same", "pulumi:pulumi:Stack"), step(op, "hcloud:index/server:Server")
                    )
                )
                self.assertEqual(problems, [f"{op} of a hcloud:index/server:Server"])

    def test_a_read_of_anything_but_a_stackreference_is_refused(self) -> None:
        _, problems = rw.plan_problems(
            self.plan(
                step("same", "pulumi:pulumi:Stack"), step("read", "hcloud:index/server:Server")
            )
        )
        self.assertEqual(len(problems), 1)

    def test_a_plan_with_no_unchanged_resource_is_refused(self) -> None:
        self.assertTrue(rw.plan_problems(self.plan())[1])

    def test_garbage_is_refused(self) -> None:
        for text in ("", "not json", "[]", '{"steps": 3}'):
            with self.subTest(text=text):
                self.assertTrue(rw.plan_problems(text)[1])


class RefreshTests(unittest.TestCase):
    def refresh(self, summary: dict[str, int], diff: dict[str, object] | None = None) -> str:
        urn = "urn:pulumi:production::proj::pulumi:pulumi:Stack::proj-production"
        return json.dumps(
            {
                "steps": [{"op": "refresh", "urn": urn, "detailedDiff": diff or {}}],
                "changeSummary": summary,
            }
        )

    def test_a_refresh_with_no_drift_passes_although_every_step_says_refresh(self) -> None:
        counts, problems = rw.refresh_problems(self.refresh({"same": 2}))
        self.assertEqual((counts, problems), ({"same": 2}, []))

    def test_drift_is_named_by_count_and_op(self) -> None:
        _, problems = rw.refresh_problems(self.refresh({"same": 1, "delete": 1, "update": 2}))
        self.assertEqual(
            problems, ["1 delete against the live project", "2 update against the live project"]
        )

    def test_a_step_with_a_detailed_diff_is_drift_even_when_the_summary_is_quiet(self) -> None:
        _, problems = rw.refresh_problems(
            self.refresh({"same": 1}, {"outputs": {"kind": "UPDATE"}})
        )
        self.assertEqual(problems, ["a pulumi:pulumi:Stack differs from live"])

    def test_garbage_and_a_missing_summary_are_refused(self) -> None:
        for text in ("", "nope", "{}", '{"steps": []}', '{"changeSummary": {}, "steps": []}'):
            with self.subTest(text=text):
                self.assertTrue(rw.refresh_problems(text)[1])


class FakeAws:
    """An `aws` executable over a directory: enough of `s3 cp` and `s3api list-objects-v2`."""

    SCRIPT = """#!{python}
import json, os, pathlib, sys
root = pathlib.Path(os.environ["FAKE_AWS_ROOT"])
args = sys.argv[1:]
with open(os.environ["FAKE_AWS_LOG"], "a") as log:
    log.write(json.dumps(args) + "\\n")
assert args[:2] == ["--endpoint-url", os.environ["FAKE_AWS_ENDPOINT"]], args
assert args[2:4] == ["--region", "hel1"], args
rest = args[5:]
if rest[:2] == ["s3", "cp"]:
    src, dst = rest[2], rest[3]
    if src == "-":
        key = dst.split("/", 3)[3]
        (root / key).parent.mkdir(parents=True, exist_ok=True)
        (root / key).write_bytes(sys.stdin.buffer.read())
    else:
        key = src.split("/", 3)[3]
        if not (root / key).is_file():
            sys.stderr.write("An error occurred (NoSuchKey)")
            sys.exit(1)
        sys.stdout.buffer.write((root / key).read_bytes())
elif rest[:2] == ["s3api", "list-objects-v2"]:
    prefix = rest[rest.index("--prefix") + 1]
    keys = sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())
    keys = [k for k in keys if k.startswith(prefix)]
    if keys:
        print(json.dumps({{"Contents": [{{"Key": k}} for k in keys]}}))
else:
    sys.exit(2)
"""

    def __init__(self, tmp: pathlib.Path) -> None:
        self.root = tmp / "bucket"
        self.root.mkdir()
        self.log = tmp / "aws.log"
        self.path = tmp / "aws"
        self.path.write_text(self.SCRIPT.format(python=sys.executable), encoding="utf-8")
        self.path.chmod(self.path.stat().st_mode | stat.S_IXUSR)

    @contextlib.contextmanager
    def environment(self, endpoint: str) -> Iterator[None]:
        env = {
            "FAKE_AWS_ROOT": str(self.root),
            "FAKE_AWS_LOG": str(self.log),
            "FAKE_AWS_ENDPOINT": endpoint,
        }
        with mock.patch.dict(os.environ, env):
            yield


class StoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="rewrap-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_the_dir_store_round_trips_and_lists_without_attrs_files(self) -> None:
        store = rw.DirStore(self.tmp)
        store.write("a/b.json", b"1")
        (self.tmp / "a" / "b.json.attrs").write_text("x")
        self.assertEqual(store.read("a/b.json"), b"1")
        self.assertEqual(store.keys("a/"), ["a/b.json"])
        with self.assertRaises(rw.ToolError):
            store.read("missing")

    def test_put_back_reports_a_mismatch_as_false(self) -> None:
        class Lossy(rw.DirStore):
            def write(self, key: str, data: bytes) -> None:
                super().write(key, data[:-1])

        self.assertFalse(rw.put_back(Lossy(self.tmp), "k", b"abc"))
        self.assertTrue(rw.put_back(rw.DirStore(self.tmp), "k", b"abc"))

    def test_the_aws_store_passes_endpoint_region_and_path_style_and_round_trips(self) -> None:
        fake = FakeAws(self.tmp)
        with fake.environment("https://objects.example.test"):
            store = rw.AwsCliStore(
                bucket="example-bucket",
                endpoint_url="https://objects.example.test",
                region="hel1",
                path_style=True,
                config_dir=self.tmp,
                aws=str(fake.path),
            )
            store.write("x/y.json", b"payload")
            self.assertEqual(store.read("x/y.json"), b"payload")
            self.assertEqual(store.keys("x/"), ["x/y.json"])
            self.assertEqual(store.keys("nothing/"), [])
            with self.assertRaises(rw.ToolError) as caught:
                store.read("x/none.json")
        self.assertNotIn("none.json", str(caught.exception))
        self.assertIn("addressing_style = path", (self.tmp / "aws-config").read_text())
        self.assertEqual(store.env["AWS_REQUEST_CHECKSUM_CALCULATION"], "when_required")

    def test_the_aws_store_has_no_way_to_delete(self) -> None:
        self.assertFalse(hasattr(rw.AwsCliStore, "delete"))
        self.assertFalse(hasattr(rw.DirStore, "delete"))

    def test_the_backend_is_read_from_pulumi_yaml_and_nothing_else_is_named_here(self) -> None:
        (self.tmp / "Pulumi.yaml").write_text(
            "name: p\nruntime: nodejs\nbackend:\n  url: 's3://example-bucket?endpoint=objects.example.test&s3ForcePathStyle=true&region=hel1'\n",
            encoding="utf-8",
        )
        backend = rw.resolve_backend(self.tmp, {}, self.tmp)
        self.assertIsInstance(backend.store, rw.AwsCliStore)
        self.assertEqual(backend.resolved_prefix, "s3://example-bucket")
        self.assertIsNone(backend.backend_url)
        store = backend.store
        assert isinstance(store, rw.AwsCliStore)  # noqa: S101
        self.assertEqual(
            (store.bucket, store.endpoint_url, store.region),
            ("example-bucket", "https://objects.example.test", "hel1"),
        )

    def test_a_backend_override_other_than_a_file_backend_is_refused(self) -> None:
        with self.assertRaises(rw.ToolError):
            rw.resolve_backend(self.tmp, {"PULUMI_BACKEND_URL": "s3://somewhere"}, self.tmp)

    def test_a_project_without_a_pinned_s3_backend_is_refused(self) -> None:
        (self.tmp / "Pulumi.yaml").write_text("name: p\nruntime: nodejs\n", encoding="utf-8")
        with self.assertRaises(rw.ToolError):
            rw.resolve_backend(self.tmp, {}, self.tmp)

    def test_the_real_tenants_project_pins_the_backend_this_tool_can_read(self) -> None:
        project_dir = pathlib.Path(__file__).resolve().parent.parent / "hetzner" / "tenants"
        backend = rw.resolve_backend(project_dir, {}, self.tmp)
        store = backend.store
        assert isinstance(store, rw.AwsCliStore)  # noqa: S101
        self.assertTrue(store.endpoint_url.startswith("https://"))
        self.assertTrue(store.env["AWS_CONFIG_FILE"].endswith("aws-config"))
        text = (project_dir / "Pulumi.yaml").read_text(encoding="utf-8")
        self.assertEqual(rw.read_top_level_scalar(text, "name"), "branchleft-hetzner-tenants")


class ChildEnvTests(unittest.TestCase):
    def test_the_inspect_environment_has_no_passphrase_and_no_service_token(self) -> None:
        env = rw.child_env(
            {
                "PULUMI_CONFIG_PASSPHRASE": "x",
                "PULUMI_CONFIG_PASSPHRASE_FILE": "/p",
                "PULUMI_ACCESS_TOKEN": "t",
            },
            backend_url=None,
            with_passphrase=False,
        )
        for name in (
            "PULUMI_CONFIG_PASSPHRASE",
            "PULUMI_CONFIG_PASSPHRASE_FILE",
            "PULUMI_ACCESS_TOKEN",
        ):
            self.assertNotIn(name, env)

    def test_skip_confirmations_is_removed_because_it_breaks_the_refresh_preview(self) -> None:
        env = rw.child_env(
            {"PULUMI_SKIP_CONFIRMATIONS": "true"}, backend_url=None, with_passphrase=True
        )
        self.assertNotIn("PULUMI_SKIP_CONFIRMATIONS", env)

    def test_classification_never_returns_the_stream(self) -> None:
        self.assertEqual(rw.classify_stderr("error: incorrect passphrase"), "passphrase")
        self.assertEqual(rw.classify_stderr("AccessDenied: key 1234"), "state bucket access")
        self.assertEqual(rw.classify_stderr("something about 174988976"), "other")


# ---------------------------------------------------------------------------
# A real pulumi binary on a throwaway file backend
# ---------------------------------------------------------------------------

OLD_PASSPHRASE = "old-passphrase-nobody-remembers"  # noqa: S105
NEW_PASSPHRASE = "new-passphrase-for-the-rewrap"  # noqa: S105
OTHER_PASSPHRASE = "the-estate-stacks-own-passphrase"  # noqa: S105

ESTATE_PROGRAM = "name: otherfixture\nruntime: yaml\noutputs:\n  edgeIp: 203.0.113.9\n"

# The tenants program's shape: a StackReference to the estate stack, whose
# preview step is a `read`, and a stack output.
TENANTS_PROGRAM = """name: tenantsfixture
runtime: yaml
resources:
  estate:
    type: pulumi:pulumi:StackReference
    properties:
      name: organization/otherfixture/production
outputs:
  note: plain-text-output
"""
TENANTS_PROGRAM_WITH_SECRET = TENANTS_PROGRAM.replace(
    "note: plain-text-output", "note: plain-text-output\n  hidden:\n    fn::secret: shh-value"
)
TENANTS_PROGRAM_WITHOUT_REFERENCE = (
    "name: tenantsfixture\nruntime: yaml\noutputs:\n  note: plain-text-output\n"
)


@unittest.skipUnless(PULUMI or REQUIRE_PULUMI, "no pulumi binary on PATH")
class RealPulumiTests(unittest.TestCase):
    def setUp(self) -> None:
        if PULUMI is None:
            self.fail("REWRAP_REQUIRE_PULUMI=1 but no pulumi binary is on PATH")
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="rewrap-real-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.state = self.tmp / "state"
        self.state.mkdir()
        (self.tmp / "home").mkdir()
        self.proj = self.tmp / "tenants"
        self.other = self.tmp / "estate"
        for d in (self.proj, self.other):
            d.mkdir()

    def env(self, passphrase: str | None) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items() if not k.startswith("PULUMI_")}
        env.update(
            PULUMI_HOME=str(self.tmp / "home"),
            PULUMI_BACKEND_URL=f"file://{self.state}",
            PULUMI_SKIP_UPDATE_CHECK="true",
        )
        if passphrase is not None:
            env["PULUMI_CONFIG_PASSPHRASE"] = passphrase
        return env

    def pulumi(
        self, cwd: pathlib.Path, passphrase: str | None, *args: str
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603
            [PULUMI or "pulumi", *args],
            cwd=cwd,
            env=self.env(passphrase),
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            check=False,
        )

    def build(self, program: str) -> bytes:
        """The estate stack, then the tenants stack applied under the old passphrase, then the old passphrase forgotten.

        Returns the raw bytes of the tenants state object, which is what a restore must give back.
        """
        (self.other / "Pulumi.yaml").write_text(ESTATE_PROGRAM, encoding="utf-8")
        for cwd, passphrase in ((self.other, OTHER_PASSPHRASE),):
            self.pulumi(
                cwd, passphrase, "stack", "init", "production", "--secrets-provider", "passphrase"
            ).check_returncode()
            self.pulumi(
                cwd, passphrase, "up", "--stack", "production", "--yes", "--skip-preview"
            ).check_returncode()
        (self.proj / "Pulumi.yaml").write_text(program, encoding="utf-8")
        self.pulumi(
            self.proj,
            OLD_PASSPHRASE,
            "stack",
            "init",
            "production",
            "--secrets-provider",
            "passphrase",
        ).check_returncode()
        self.pulumi(
            self.proj, OLD_PASSPHRASE, "up", "--stack", "production", "--yes", "--skip-preview"
        ).check_returncode()
        # The old passphrase opens it now; this is the control for the refusal below.
        self.preview_in(self.proj, OLD_PASSPHRASE).check_returncode()
        # The CI shape: the committed stack config carries no salt, and the old passphrase is gone.
        (self.proj / "Pulumi.production.yaml").unlink(missing_ok=True)
        return self.state_object().read_bytes()

    def state_object(self) -> pathlib.Path:
        return self.state / ".pulumi" / "stacks" / "tenantsfixture" / "production.json"

    def export(self, passphrase: str | None = None) -> dict[str, object]:
        done = self.pulumi(self.proj, passphrase, "stack", "export", "--stack", "production")
        done.check_returncode()
        return json.loads(done.stdout)  # type: ignore[no-any-return]

    def run_tool(
        self,
        command: str = "rewrap",
        *,
        passphrase: str | None = NEW_PASSPHRASE,
        extra: Sequence[str] = (),
    ) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = rw.main(
                [command, "--project-dir", str(self.proj), "--run-tag", "test-1", *extra],
                environ=self.env(passphrase),
            )
        return code, out.getvalue()

    def preview_in(self, cwd: pathlib.Path, passphrase: str) -> subprocess.CompletedProcess[str]:
        return self.pulumi(
            cwd, passphrase, "preview", "--stack", "production", "--json", "--expect-no-changes"
        )

    def preview(self, passphrase: str) -> subprocess.CompletedProcess[str]:
        return self.preview_in(self.proj, passphrase)

    def assert_nothing_private(self, text: str, *extra: str) -> None:
        salt = child(child(deployment(self.export()), "secrets_providers"), "state")["salt"]
        assert isinstance(salt, str)  # noqa: S101
        self.assertNotIn(salt, text)
        for private in (
            "urn:pulumi",
            "203.0.113.9",
            OLD_PASSPHRASE,
            NEW_PASSPHRASE,
            "plain-text-output",
            *extra,
        ):
            self.assertNotIn(private, text)

    def test_a_plaintext_only_state_is_re_keyed_and_plans_clean_under_the_new_passphrase_only(
        self,
    ) -> None:
        original = self.build(TENANTS_PROGRAM)
        before = self.export()
        self.assertEqual(rw.count_encrypted(before), 0)

        code, out = self.run_tool()
        self.assertEqual(code, rw.EXIT_OK, out)

        after = self.export()
        # Everything but the provider block is what it was: the resources, their ids and outputs.
        self.assertEqual(
            rw.canonical(deployment(before)["resources"]),
            rw.canonical(deployment(after)["resources"]),
        )
        self.assertEqual(
            rw.canonical(rw.without_secrets_providers(before)),
            rw.canonical(rw.without_secrets_providers(after)),
        )
        self.assertNotEqual(
            deployment(before)["secrets_providers"], deployment(after)["secrets_providers"]
        )

        under_new = self.preview(NEW_PASSPHRASE)
        self.assertEqual(under_new.returncode, 0, under_new.stderr[:200])
        counts, problems = rw.plan_problems(under_new.stdout)
        self.assertEqual(problems, [])
        self.assertGreaterEqual(counts["same"], 1)

        under_old = self.preview(OLD_PASSPHRASE)
        self.assertNotEqual(under_old.returncode, 0)
        self.assertIn("incorrect passphrase", under_old.stderr)

        aside = list((self.state / "aside" / "tenantsfixture").glob("production.*.test-1.json"))
        self.assertEqual(len(aside), 1)
        self.assertEqual(aside[0].read_bytes(), original)
        self.assertIn("refresh preview", out)
        self.assertIn("DONE", out)
        self.assert_nothing_private(out)

    def test_the_document_handed_to_import_differs_from_the_old_export_in_one_key_only(
        self,
    ) -> None:
        self.build(TENANTS_PROGRAM)
        before = self.export()
        handed: list[dict[str, object]] = []

        class Capturing(rw.Pulumi):
            def call(self, *args: str, stdout_to: pathlib.Path | None = None) -> rw.Completed:
                if args[:2] == ("stack", "import"):
                    text = pathlib.Path(args[args.index("--file") + 1]).read_text(encoding="utf-8")
                    handed.append(json.loads(text))
                return super().call(*args, stdout_to=stdout_to)

        with contextlib.redirect_stdout(io.StringIO()):
            code = rw.run_rewrap(self.context(Capturing))
        self.assertEqual(code, rw.EXIT_OK)
        self.assertEqual(len(handed), 1)
        self.assertEqual(
            rw.canonical(rw.without_secrets_providers(before)),
            rw.canonical(rw.without_secrets_providers(handed[0])),
        )
        self.assertNotEqual(
            deployment(before)["secrets_providers"], deployment(handed[0])["secrets_providers"]
        )

    def test_a_state_with_one_encrypted_value_is_refused_and_left_exactly_as_it_was(self) -> None:
        original = self.build(TENANTS_PROGRAM_WITH_SECRET)
        before = self.export()
        self.assertEqual(rw.count_encrypted(before), 1)

        code, out = self.run_tool()

        self.assertEqual(code, rw.EXIT_REFUSED, out)
        self.assertIn("1 encrypted value", out)
        self.assertEqual(self.state_object().read_bytes(), original)
        self.assertFalse(
            (self.state / "aside").exists(), "nothing was copied aside: nothing was going to change"
        )
        self.assertEqual(self.export(), before)
        self.assert_nothing_private(out)

    def test_inspect_reports_the_counts_without_a_passphrase_and_changes_nothing(self) -> None:
        original = self.build(TENANTS_PROGRAM)
        code, out = self.run_tool("inspect", passphrase=None)
        self.assertEqual(code, rw.EXIT_OK, out)
        self.assertIn("CLEAN", out)
        self.assertIn("encrypted values: 0", out)
        self.assertEqual(self.state_object().read_bytes(), original)
        self.assert_nothing_private(out)

    def test_inspect_of_a_state_with_a_secret_exits_refused(self) -> None:
        self.build(TENANTS_PROGRAM_WITH_SECRET)
        code, out = self.run_tool("inspect", passphrase=None)
        self.assertEqual(code, rw.EXIT_REFUSED, out)
        self.assertIn("encrypted values: 1", out)

    def test_a_stack_config_that_already_carries_a_salt_is_refused(self) -> None:
        original = self.build(TENANTS_PROGRAM)
        (self.proj / "Pulumi.production.yaml").write_text(
            "encryptionsalt: v1:whatever\n", encoding="utf-8"
        )
        code, out = self.run_tool()
        self.assertEqual(code, rw.EXIT_REFUSED, out)
        self.assertEqual(self.state_object().read_bytes(), original)

    def test_no_new_passphrase_is_an_error_before_anything_changes(self) -> None:
        original = self.build(TENANTS_PROGRAM)
        code, out = self.run_tool(passphrase=None)
        self.assertEqual(code, rw.EXIT_ERROR, out)
        self.assertEqual(self.state_object().read_bytes(), original)

    def test_a_plan_that_shows_a_change_after_the_rewrite_puts_the_original_back(self) -> None:
        original = self.build(TENANTS_PROGRAM)
        # The program no longer declares the StackReference the state holds.
        (self.proj / "Pulumi.yaml").write_text(TENANTS_PROGRAM_WITHOUT_REFERENCE, encoding="utf-8")
        code, out = self.run_tool()
        self.assertEqual(code, rw.EXIT_RESTORED, out)
        self.assertIn("not allowed", out)
        self.assertIn("RESTORED", out)
        self.assertEqual(self.state_object().read_bytes(), original)
        self.assert_nothing_private(out)

    def test_drift_from_the_live_project_after_the_rewrite_puts_the_original_back(self) -> None:
        original = self.build(TENANTS_PROGRAM)
        # The estate stack's output moves on, as a hand change to a live project would: the
        # refresh of the StackReference sees it, the state does not.
        (self.other / "Pulumi.yaml").write_text(
            ESTATE_PROGRAM.replace("203.0.113.9", "203.0.113.10"), encoding="utf-8"
        )
        self.pulumi(
            self.other, OTHER_PASSPHRASE, "up", "--stack", "production", "--yes", "--skip-preview"
        ).check_returncode()
        code, out = self.run_tool()
        self.assertEqual(code, rw.EXIT_RESTORED, out)
        self.assertIn("against the live project", out)
        self.assertIn("RESTORED", out)
        self.assertEqual(self.state_object().read_bytes(), original)
        self.assert_nothing_private(out, "203.0.113.10")

    def context(self, pulumi_cls: type[rw.Pulumi]) -> rw.Context:
        scratch = self.tmp / "scratch"
        scratch.mkdir(exist_ok=True)
        env = rw.child_env(
            self.env(NEW_PASSPHRASE), backend_url=f"file://{self.state}", with_passphrase=True
        )
        return rw.Context(
            pulumi=pulumi_cls(binary=PULUMI or "pulumi", project_dir=self.proj, env=env),
            store=rw.DirStore(self.state),
            project="tenantsfixture",
            stack="production",
            project_dir=self.proj,
            scratch=scratch,
            run_tag="test-2",
            report=rw.Report(),
            now=lambda: datetime.datetime(2026, 11, 21, 12, 0, 0, tzinfo=datetime.UTC),
        )

    def test_a_failed_import_after_the_removal_restores_the_original_bytes(self) -> None:
        original = self.build(TENANTS_PROGRAM)

        class FailsImport(rw.Pulumi):
            def call(self, *args: str, stdout_to: pathlib.Path | None = None) -> rw.Completed:
                if args[:2] == ("stack", "import"):
                    return rw.Completed(1, "other")
                return super().call(*args, stdout_to=stdout_to)

        with contextlib.redirect_stdout(io.StringIO()):
            code = rw.run_rewrap(self.context(FailsImport))
        self.assertEqual(code, rw.EXIT_RESTORED)
        self.assertEqual(self.state_object().read_bytes(), original)

    def test_an_interrupt_after_the_removal_restores_and_propagates(self) -> None:
        original = self.build(TENANTS_PROGRAM)

        class Interrupted(rw.Pulumi):
            def call(self, *args: str, stdout_to: pathlib.Path | None = None) -> rw.Completed:
                if args[:2] == ("stack", "init"):
                    raise KeyboardInterrupt
                return super().call(*args, stdout_to=stdout_to)

        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(KeyboardInterrupt):
            rw.run_rewrap(self.context(Interrupted))
        self.assertEqual(self.state_object().read_bytes(), original)

    def test_a_restore_that_cannot_write_exits_broken_and_names_the_aside_key(self) -> None:
        self.build(TENANTS_PROGRAM)

        class FailsImport(rw.Pulumi):
            def call(self, *args: str, stdout_to: pathlib.Path | None = None) -> rw.Completed:
                if args[:2] == ("stack", "import"):
                    return rw.Completed(1, "other")
                return super().call(*args, stdout_to=stdout_to)

        ctx = self.context(FailsImport)

        class WriteOnce(rw.DirStore):
            writes = 0

            def write(self, key: str, data: bytes) -> None:
                WriteOnce.writes += 1
                if WriteOnce.writes > 1:
                    raise rw.ToolError("the bucket went away")  # noqa: TRY003
                super().write(key, data)

        ctx.store = WriteOnce(self.state)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = rw.run_rewrap(ctx)
        self.assertEqual(code, rw.EXIT_BROKEN)
        self.assertIn("NOT RESTORED", out.getvalue())
        self.assertIn("aside/tenantsfixture/production.", out.getvalue())

    def test_the_restore_command_puts_this_runs_aside_copy_back_after_a_hard_kill(self) -> None:
        original = self.build(TENANTS_PROGRAM)
        store = rw.DirStore(self.state)
        store.write("aside/tenantsfixture/production.20261121T120000Z.test-1.json", original)
        store.write(
            "aside/tenantsfixture/production.20261121T110000Z.test-0.json", b"another run's copy"
        )
        # The kill landed after the removal: the state object is gone.
        self.pulumi(
            self.proj,
            NEW_PASSPHRASE,
            "stack",
            "rm",
            "production",
            "--force",
            "--yes",
            "--preserve-config",
        ).check_returncode()
        self.assertFalse(self.state_object().exists())
        code, out = self.run_tool("restore", passphrase=None)
        self.assertEqual(code, rw.EXIT_OK, out)
        self.assertEqual(self.state_object().read_bytes(), original)

    def test_the_restore_command_with_no_aside_copy_does_nothing(self) -> None:
        original = self.build(TENANTS_PROGRAM)
        code, out = self.run_tool("restore", passphrase=None)
        self.assertEqual(code, rw.EXIT_OK, out)
        self.assertIn("nothing to put back", out)
        self.assertEqual(self.state_object().read_bytes(), original)

    def test_assert_backend_refuses_a_backend_that_is_not_the_one_this_run_is_for(self) -> None:
        self.build(TENANTS_PROGRAM)
        ctx = self.context(rw.Pulumi)
        wrong = rw.Backend(rw.DirStore(self.state), None, "s3://some-other-bucket")
        with self.assertRaises(rw.ToolError):
            rw.assert_backend(ctx.pulumi, wrong, ctx.scratch)
        right = rw.Backend(rw.DirStore(self.state), None, f"file://{self.state}")
        rw.assert_backend(ctx.pulumi, right, ctx.scratch)


if __name__ == "__main__":
    unittest.main()
