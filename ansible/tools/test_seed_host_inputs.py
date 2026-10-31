"""Tests for the owner-run seeding tool of a host's private inputs file.

The tool runs on a host as root and writes /etc/branchleft/host-inputs.json from the values the
hand install left in the host's own files. These tests run it against a temporary directory that
stands in for /etc/branchleft, with the user id and the prompts injected. Three groups: the
tool's one table is held to its authorities (the loader's rows and the roles that write the live
files), the fill and the write are held to the contract, and a leak test scans every output for
sentinel values planted in the live files and in the typed answers.
"""

from __future__ import annotations

import io
import json
import os
import re
import stat
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path
from unittest import mock

import seed_host_inputs as tool
import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[2]
ROLES = ROOT / "ansible" / "roles"

# Hosts whose private inputs file exists already and which this tool does not seed: they have no
# live files to read. A new host in the loader's rows fails until it is named here or in the tool.
UNSUPPORTED = frozenset({"db1", "app1"})

PEM = "-----BEGIN CERTIFICATE-----\nMIIBsentinelcertbody\n-----END CERTIFICATE-----\n"
RECIPIENT_A = "age1" + "q" * 58
RECIPIENT_B = "age1" + "p" * 58

# Each input, with the live file and the name in it that the hand install left. Written here by
# hand, not read from the tool, so a wrong table in the tool is not agreed with by its own test.
EDGE1_LIVE: dict[str, tuple[str, str]] = {
    "monitoring_stack_smtp_username": ("monitoring.env", "SMTP_USERNAME"),
    "monitoring_stack_smtp_password": ("monitoring.env", "SMTP_PASSWORD"),
    "monitoring_stack_healthchecks_ping_url": ("monitoring.env", "HEALTHCHECKS_PING_URL"),
    "monitoring_stack_alert_recipient_email": ("monitoring.env", "ALERT_RECIPIENT_EMAIL"),
    "monitoring_stack_mailhost_ping_url": ("monitoring.env", "MAILHOST_PING_URL"),
    "monitoring_stack_grafana_admin_password": ("monitoring.env", "GRAFANA_ADMIN_PASSWORD"),
    "monitoring_stack_snds_data_url": ("monitoring.env", "SNDS_DATA_URL"),
    "ntfy_pager_pager_token": ("ntfy-pager.env", "NTFY_PAGER_TOKEN"),
    "ntfy_pager_watcher_token": ("ntfy-pager.env", "NTFY_WATCHER_TOKEN"),
    "ntfy_pager_owner_password_hash": ("ntfy-pager.env", "NTFY_OWNER_PASSWORD_HASH"),
    "ntfy_pager_machine_password_hash": ("ntfy-pager.env", "NTFY_MACHINE_PASSWORD_HASH"),
}
OPS1_LIVE: dict[str, tuple[str, str]] = {
    "backup_worker_db_host": ("backup-worker.env", "BACKUP_WORKER_DB_HOST"),
    "backup_worker_db_user": ("backup-worker.env", "BACKUP_WORKER_MYSQL_USER"),
    "backup_worker_db_password": ("backup-worker.env", "DB_DUMP_MYSQL_PWD"),
    "backup_worker_bucket": ("backup-worker.env", "BACKUP_WORKER_COPY_PRIMARY_BUCKET"),
    "backup_worker_s3_endpoint": ("backup-worker.env", "BACKUP_WORKER_COPY_PRIMARY_ENDPOINT"),
    "backup_worker_s3_region": ("backup-worker.env", "BACKUP_WORKER_COPY_PRIMARY_REGION"),
    "backup_worker_s3_access_key_id": (
        "backup-worker.env",
        "BACKUP_WORKER_COPY_PRIMARY_ACCESS_KEY_ID",
    ),
    "backup_worker_s3_secret_access_key": (
        "backup-worker.env",
        "BACKUP_WORKER_COPY_PRIMARY_SECRET_ACCESS_KEY",
    ),
    "backup_restore_state_copy_recipient": ("state-copy.env", "STATE_COPY_RECIPIENT"),
    "backup_restore_state_copy_dest_access_key_id": (
        "state-copy.env",
        "STATE_COPY_DEST_ACCESS_KEY_ID",
    ),
    "backup_restore_state_copy_estate_bucket": ("state-copy.env", "STATE_COPY_ESTATE_BUCKET"),
    "backup_restore_state_copy_estate_endpoint": ("state-copy.env", "STATE_COPY_ESTATE_ENDPOINT"),
    "backup_restore_state_copy_estate_region": ("state-copy.env", "STATE_COPY_ESTATE_REGION"),
    "backup_restore_state_copy_estate_access_key_id": (
        "state-copy.env",
        "STATE_COPY_ESTATE_ACCESS_KEY_ID",
    ),
    "backup_restore_state_copy_tenant_bucket": ("state-copy.env", "STATE_COPY_TENANT_BUCKET"),
    "backup_restore_state_copy_tenant_endpoint": ("state-copy.env", "STATE_COPY_TENANT_ENDPOINT"),
    "backup_restore_state_copy_tenant_region": ("state-copy.env", "STATE_COPY_TENANT_REGION"),
    "backup_restore_state_copy_tenant_access_key_id": (
        "state-copy.env",
        "STATE_COPY_TENANT_ACCESS_KEY_ID",
    ),
}
CA_KEY = "backup_worker_db_ca_pem"
TENANTS_KEY = "backup_worker_tenants"
TENANTS = [
    {"slug": "alpha", "recipient": RECIPIENT_A},
    {"slug": "beta", "recipient": RECIPIENT_B},
]
EDGE1_KEYS = tuple(EDGE1_LIVE)
OPS1_KEYS = (*OPS1_LIVE, CA_KEY, TENANTS_KEY)


def value_for(key: str) -> str:
    """A distinct value per key, with the characters a URL or a secret really carries."""
    return f"SENT-{key}-a=b&c=d%2F=="


def mapping_of(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise TypeError(type(value).__name__)
    return {str(key): item for key, item in value.items()}


def list_of(value: object) -> list[object]:
    if not isinstance(value, list):
        raise TypeError(type(value).__name__)
    return list(value)


def yaml_of(path: Path) -> dict[str, object]:
    return mapping_of(yaml.safe_load(path.read_text(encoding="utf-8")))


def template_pairs(path: Path) -> set[tuple[str, str]]:
    """(variable, NAME) of each NAME={{ variable }} line of an env template."""
    found: set[tuple[str, str]] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)=\{\{ (\w+) \}\}", line)
        if match:
            found.add((match.group(2), match.group(1)))
    return found


def tool_pairs(filename: str) -> set[tuple[str, str]]:
    return {
        (key, source.name)
        for key, sources in tool.SOURCES.items()
        for source in sources
        if source.kind == tool.ENV and source.filename == filename
    }


def input_of(expression: object) -> str:
    match = re.fullmatch(r"\{\{ (\w+) \}\}", str(expression))
    if match is None:
        raise ValueError(str(expression))
    return match.group(1)


def table_problems(rows: Mapping[str, Sequence[str]]) -> list[str]:
    """Every way the tool's rows and table disagree with the loader's rows."""
    found: list[str] = []
    for host, keys in rows.items():
        if host in tool.HOSTS:
            if set(tool.HOSTS[host]) != set(keys):
                found.append(f"{host}: the tool's row differs from the loader's row")
        elif host not in UNSUPPORTED:
            found.append(f"{host}: a host with a loader row that the tool does not classify")
    for host in tool.HOSTS:
        if host not in rows:
            found.append(f"{host}: a host of the tool with no loader row")
    return found


class TableTests(unittest.TestCase):
    """The tool's one table, held to the loader's rows and to the roles that write the files."""

    def setUp(self) -> None:
        self.loader = yaml_of(ROLES / "host_inputs" / "vars" / "main.yml")
        rows = mapping_of(self.loader["host_inputs_required_by_host"])
        self.rows = {host: [str(key) for key in list_of(keys)] for host, keys in rows.items()}

    def test_the_rows_of_the_tool_equal_the_loaders_rows_both_ways(self) -> None:
        self.assertEqual([], table_problems(self.rows))
        for host, keys in tool.HOSTS.items():
            self.assertEqual(len(keys), len(set(keys)), host)

    def test_a_new_loader_key_without_a_tool_mapping_is_found(self) -> None:
        rows = {host: [*keys] for host, keys in self.rows.items()}
        rows["edge1"].append("monitoring_stack_a_new_input")
        self.assertEqual(
            ["edge1: the tool's row differs from the loader's row"], table_problems(rows)
        )

    def test_a_new_loader_host_is_found_until_it_is_classified(self) -> None:
        rows = {**self.rows, "mx9": ["mx9_input"]}
        self.assertEqual(
            ["mx9: a host with a loader row that the tool does not classify"],
            table_problems(rows),
        )

    def test_every_key_of_a_row_has_a_source_and_no_source_is_orphaned(self) -> None:
        in_rows = {key for keys in tool.HOSTS.values() for key in keys}
        self.assertEqual(in_rows, set(tool.SOURCES))
        for key, sources in tool.SOURCES.items():
            self.assertTrue(sources, key)

    def test_the_unsupported_hosts_are_real_hosts_of_the_loader(self) -> None:
        self.assertEqual(set(), UNSUPPORTED - set(self.rows))
        self.assertEqual(set(), UNSUPPORTED & set(tool.HOSTS))

    def test_the_destination_and_its_rules_are_the_loaders(self) -> None:
        self.assertEqual(
            str(self.loader["host_inputs_path"]), f"{tool.CONFIG_DIR}/{tool.DEST_NAME}"
        )
        self.assertEqual(list(self.loader["host_inputs_ancestors"]), list(tool.ANCESTORS))  # type: ignore[call-overload]
        self.assertEqual(self.loader["host_inputs_owner_uid"], tool.ROOT_UID)
        self.assertEqual(self.loader["host_inputs_group_gid"], tool.ROOT_GID)
        self.assertEqual(str(self.loader["host_inputs_file_mode"]), f"{tool.FILE_MODE:04o}")

    def test_monitoring_env_names_equal_the_roles(self) -> None:
        monitoring = yaml_of(ROLES / "monitoring_stack" / "vars" / "main.yml")
        keys = [mapping_of(item) for item in list_of(monitoring["monitoring_stack_env_keys"])]
        role = {(input_of(item["value"]), str(item["key"])) for item in keys}
        pager = self.pager_pairs()
        # The hand runbook put the four NTFY_ lines in monitoring.env before the role wrote
        # them to the pager's own file, so that file is the second place to look for them.
        self.assertEqual(role | pager, tool_pairs("monitoring.env"))
        self.assertEqual(
            f"{tool.CONFIG_DIR}/monitoring.env", str(monitoring["monitoring_stack_env_file"])
        )

    def pager_pairs(self) -> set[tuple[str, str]]:
        pager = yaml_of(ROLES / "ntfy_pager" / "vars" / "main.yml")
        names = mapping_of(pager["ntfy_pager_env_names"])
        pairs: set[tuple[str, str]] = set()
        for entry in list_of(pager["ntfy_pager_env_lines"]):
            item = mapping_of(entry)
            match = re.fullmatch(r"\{\{ ntfy_pager_env_names\.(\w+) \}\}", str(item["key"]))
            if match is None:
                raise ValueError(str(item["key"]))
            pairs.add((input_of(item["value"]), str(names[match.group(1)])))
        return pairs

    def test_pager_env_names_equal_the_role_and_come_first(self) -> None:
        pager = yaml_of(ROLES / "ntfy_pager" / "vars" / "main.yml")
        self.assertEqual(self.pager_pairs(), tool_pairs("ntfy-pager.env"))
        self.assertEqual(f"{tool.CONFIG_DIR}/ntfy-pager.env", str(pager["ntfy_pager_env_file"]))
        for _, name in self.pager_pairs():
            key = next(k for k, ss in tool.SOURCES.items() for s in ss if s.name == name)
            self.assertEqual(
                ["ntfy-pager.env", "monitoring.env"], [s.filename for s in tool.SOURCES[key]]
            )

    def test_backup_worker_env_names_equal_the_role(self) -> None:
        worker = yaml_of(ROLES / "backup_worker" / "vars" / "main.yml")
        ops1 = set(self.rows["ops1"])
        role = {
            pair
            for pair in template_pairs(
                ROLES / "backup_worker" / "templates" / "backup-worker.env.j2"
            )
            if pair[0] in ops1
        }
        self.assertEqual(role, tool_pairs("backup-worker.env"))
        self.assertEqual(
            f"{tool.CONFIG_DIR}/backup-worker.env", str(worker["backup_worker_env_file"])
        )

    def test_state_copy_env_names_equal_the_role(self) -> None:
        restore = yaml_of(ROLES / "backup_restore" / "vars" / "main.yml")
        # The bucket, endpoint and region of the destination are the worker's inputs repeated
        # on a line of the file; the file is not their source.
        role = {
            pair
            for pair in template_pairs(ROLES / "backup_restore" / "templates" / "state-copy.env.j2")
            if pair[0].startswith("backup_restore_state_copy_")
        }
        self.assertEqual(role, tool_pairs("state-copy.env"))
        self.assertEqual(
            f"{tool.CONFIG_DIR}/state-copy.env", str(restore["backup_restore_state_copy_env_file"])
        )

    def test_the_ca_and_recipients_files_are_the_workers(self) -> None:
        worker = yaml_of(ROLES / "backup_worker" / "vars" / "main.yml")
        self.assertEqual((tool.Source(tool.WHOLE, "db1-ca.pem"),), tool.SOURCES[CA_KEY])
        self.assertEqual(
            (tool.Source(tool.RECIPIENTS, "backup-worker-recipients"),), tool.SOURCES[TENANTS_KEY]
        )
        self.assertEqual(f"{tool.CONFIG_DIR}/db1-ca.pem", str(worker["backup_worker_ca_file"]))
        self.assertEqual(
            f"{tool.CONFIG_DIR}/backup-worker-recipients",
            str(worker["backup_worker_recipients_file"]),
        )
        template = ROLES / "backup_worker" / "templates" / "backup-worker-recipients.j2"
        self.assertIn(
            "{{ tenant['slug'] }} {{ tenant['recipient'] }}", template.read_text(encoding="utf-8")
        )


class Rig:
    """A temporary /etc/branchleft, a context for the tool, and the answers it will be given."""

    def __init__(
        self,
        test: unittest.TestCase,
        answers: Sequence[str] = (),
        path_answers: Sequence[str] = (),
        euid: int | None = None,
    ) -> None:
        holder = tempfile.TemporaryDirectory()
        test.addCleanup(holder.cleanup)
        self.base = Path(holder.name)
        self.cfg = self.base / "branchleft"
        self.cfg.mkdir()
        self.cfg.chmod(0o755)
        self.answers = list(answers)
        self.path_answers = list(path_answers)
        self.prompts: list[str] = []
        self.out = io.StringIO()
        self.err = io.StringIO()
        self.uid = os.getuid()
        self.ctx = tool.Context(
            config_dir=self.cfg,
            ancestors=(self.cfg,),
            euid=self.uid if euid is None else euid,
            root_uid=self.uid,
            root_gid=self.cfg.stat().st_gid,
            ask_secret=self.secret,
            ask_path=self.path,
            out=self.out,
            err=self.err,
        )

    def secret(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if not self.answers:
            raise EOFError
        return self.answers.pop(0)

    def path(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if not self.path_answers:
            raise EOFError
        return self.path_answers.pop(0)

    def run(self, *argv: str) -> int:
        return tool.main(list(argv), self.ctx)

    @property
    def dest(self) -> Path:
        return self.cfg / tool.DEST_NAME

    @property
    def stdout(self) -> str:
        return self.out.getvalue()

    @property
    def everything(self) -> str:
        return self.out.getvalue() + self.err.getvalue() + "".join(self.prompts)

    def put(self, name: str, text: str, mode: int = 0o600) -> Path:
        path = self.cfg / name
        path.write_text(text, encoding="utf-8")
        path.chmod(mode)
        return path

    def seed_edge1(self, skip: Sequence[str] = (), pager_in_monitoring: bool = False) -> None:
        files: dict[str, list[str]] = {"monitoring.env": [], "ntfy-pager.env": []}
        for key, (filename, name) in EDGE1_LIVE.items():
            if key in skip:
                continue
            if pager_in_monitoring and filename == "ntfy-pager.env":
                filename = "monitoring.env"
            files[filename].append(f"{name}={value_for(key)}\n")
        for filename, lines in files.items():
            if lines:
                self.put(filename, "".join(lines))

    def seed_ops1(self, skip: Sequence[str] = ()) -> None:
        files: dict[str, list[str]] = {"backup-worker.env": [], "state-copy.env": []}
        for key, (filename, name) in OPS1_LIVE.items():
            if key not in skip:
                files[filename].append(f"{name}={value_for(key)}\n")
        for filename, lines in files.items():
            if lines:
                self.put(filename, "".join(lines))
        if CA_KEY not in skip:
            self.put("db1-ca.pem", PEM)
        if TENANTS_KEY not in skip:
            self.put(
                "backup-worker-recipients",
                "".join(f"{t['slug']} {t['recipient']}\n" for t in TENANTS),
            )

    def document(self) -> dict[str, object]:
        return mapping_of(json.loads(self.dest.read_text(encoding="utf-8")))


def edge1_document() -> dict[str, object]:
    return {key: value_for(key) for key in EDGE1_KEYS}


def ops1_document() -> dict[str, object]:
    document: dict[str, object] = {key: value_for(key) for key in OPS1_LIVE}
    document[CA_KEY] = PEM
    document[TENANTS_KEY] = TENANTS
    return {key: document[key] for key in OPS1_KEYS}


class FillTests(unittest.TestCase):
    def test_edge1_is_filled_from_the_live_files_with_no_prompt(self) -> None:
        rig = Rig(self)
        rig.seed_edge1()
        self.assertEqual(0, rig.run("--host", "edge1"))
        self.assertEqual(edge1_document(), rig.document())
        self.assertEqual([], rig.prompts)
        for key in EDGE1_KEYS:
            self.assertIn(key, rig.stdout)
        self.assertIn("still missing (0): none", rig.stdout)
        self.assertIn("typed (0): none", rig.stdout)

    def test_the_pager_keys_are_found_in_monitoring_env_when_the_pager_file_is_absent(self) -> None:
        rig = Rig(self)
        rig.seed_edge1(pager_in_monitoring=True)
        self.assertFalse((rig.cfg / "ntfy-pager.env").exists())
        self.assertEqual(0, rig.run("--host", "edge1"))
        self.assertEqual(edge1_document(), rig.document())

    def test_the_pager_file_wins_over_monitoring_env(self) -> None:
        rig = Rig(self)
        rig.seed_edge1()
        rig.put(
            "monitoring.env", (rig.cfg / "monitoring.env").read_text() + "NTFY_PAGER_TOKEN=old\n"
        )
        self.assertEqual(0, rig.run("--host", "edge1"))
        self.assertEqual(
            value_for("ntfy_pager_pager_token"), rig.document()["ntfy_pager_pager_token"]
        )

    def test_a_value_is_taken_raw_after_the_first_equals_sign(self) -> None:
        rig = Rig(self)
        rig.seed_edge1(skip=["monitoring_stack_snds_data_url"])
        url = "https://example.invalid/d?key=A%2FB&format=csv&pad=="
        rig.put(
            "monitoring.env", (rig.cfg / "monitoring.env").read_text() + f"SNDS_DATA_URL={url}\n"
        )
        self.assertEqual(0, rig.run("--host", "edge1"))
        self.assertEqual(url, rig.document()["monitoring_stack_snds_data_url"])

    def test_comments_and_blank_lines_are_ignored(self) -> None:
        rig = Rig(self)
        rig.seed_edge1()
        text = (rig.cfg / "monitoring.env").read_text()
        rig.put("monitoring.env", f"# the stack's secrets\n\n{text}\n# end\n")
        self.assertEqual(0, rig.run("--host", "edge1"))
        self.assertEqual(edge1_document(), rig.document())

    def test_ops1_is_filled_from_the_five_live_sources(self) -> None:
        rig = Rig(self)
        rig.seed_ops1()
        self.assertEqual(0, rig.run("--host", "ops1"))
        document = rig.document()
        self.assertEqual(ops1_document(), document)
        self.assertEqual(TENANTS, document[TENANTS_KEY])
        self.assertEqual(PEM, document[CA_KEY])
        self.assertEqual([], rig.prompts)

    def test_every_value_but_the_tenants_is_a_string(self) -> None:
        rig = Rig(self)
        rig.seed_ops1()
        rig.run("--host", "ops1")
        for key, value in rig.document().items():
            if key != TENANTS_KEY:
                self.assertIsInstance(value, str, key)

    def test_a_key_missing_live_is_asked_with_a_hidden_prompt_naming_it(self) -> None:
        rig = Rig(self, answers=["typed-snds-value"])
        rig.seed_edge1(skip=["monitoring_stack_snds_data_url"])
        self.assertEqual(0, rig.run("--host", "edge1"))
        self.assertEqual(1, len(rig.prompts))
        self.assertIn("monitoring_stack_snds_data_url", rig.prompts[0])
        self.assertEqual("typed-snds-value", rig.document()["monitoring_stack_snds_data_url"])
        self.assertIn("typed (1): monitoring_stack_snds_data_url", rig.stdout)
        self.assertNotIn("typed-snds-value", rig.everything)

    def test_a_live_value_is_never_prompted_over(self) -> None:
        rig = Rig(self, answers=["typed"])
        rig.seed_edge1()
        rig.run("--host", "edge1")
        self.assertEqual([], rig.prompts)
        self.assertEqual(["typed"], rig.answers)

    def test_an_empty_answer_writes_nothing_and_names_the_key(self) -> None:
        rig = Rig(self, answers=[""])
        rig.seed_edge1(skip=["monitoring_stack_snds_data_url"])
        self.assertEqual(1, rig.run("--host", "edge1"))
        self.assertFalse(rig.dest.exists())
        self.assertIn("still missing (1): monitoring_stack_snds_data_url", rig.stdout)
        self.assertIn("nothing written", rig.stdout)

    def test_a_blank_answer_counts_as_empty(self) -> None:
        rig = Rig(self, answers=["   "])
        rig.seed_edge1(skip=["monitoring_stack_snds_data_url"])
        self.assertEqual(1, rig.run("--host", "edge1"))
        self.assertFalse(rig.dest.exists())

    def test_no_terminal_writes_nothing_and_lists_every_missing_key(self) -> None:
        rig = Rig(self)
        self.assertEqual(1, rig.run("--host", "edge1"))
        self.assertFalse(rig.dest.exists())
        self.assertIn(f"still missing ({len(EDGE1_KEYS)}):", rig.stdout)
        for key in EDGE1_KEYS:
            self.assertIn(key, rig.stdout)

    def test_nothing_is_written_when_one_of_twenty_is_missing(self) -> None:
        rig = Rig(self)
        rig.seed_ops1(skip=["backup_restore_state_copy_recipient"])
        self.assertEqual(1, rig.run("--host", "ops1"))
        self.assertFalse(rig.dest.exists())
        self.assertIn("still missing (1): backup_restore_state_copy_recipient", rig.stdout)
        self.assertIn("filled from live (19)", rig.stdout)
        self.assertEqual([], list(rig.cfg.glob("*.tmp")))

    def test_a_value_empty_in_the_live_file_is_missing(self) -> None:
        rig = Rig(self, answers=["typed"])
        rig.seed_edge1()
        text = (
            (rig.cfg / "monitoring.env")
            .read_text()
            .replace(value_for("monitoring_stack_smtp_username"), "")
        )
        rig.put("monitoring.env", text)
        self.assertEqual(0, rig.run("--host", "edge1"))
        self.assertEqual("typed", rig.document()["monitoring_stack_smtp_username"])

    def test_tenants_are_typed_as_lines_until_an_empty_one(self) -> None:
        answers = [f"alpha {RECIPIENT_A}", "not-two-fields", f"beta {RECIPIENT_B}", ""]
        rig = Rig(self, answers=answers)
        rig.seed_ops1(skip=[TENANTS_KEY])
        self.assertEqual(0, rig.run("--host", "ops1"))
        self.assertEqual(TENANTS, rig.document()[TENANTS_KEY])
        self.assertNotIn(RECIPIENT_A, rig.everything)

    def test_no_tenant_typed_is_missing(self) -> None:
        rig = Rig(self, answers=[""])
        rig.seed_ops1(skip=[TENANTS_KEY])
        self.assertEqual(1, rig.run("--host", "ops1"))
        self.assertIn(f"still missing (1): {TENANTS_KEY}", rig.stdout)

    def test_the_ca_is_asked_as_a_path_to_a_pem_file(self) -> None:
        rig = Rig(self)
        rig.seed_ops1(skip=[CA_KEY])
        pem_file = rig.base / "ca.pem"
        pem_file.write_text(PEM, encoding="utf-8")
        pem_file.chmod(0o600)
        rig.path_answers = [str(pem_file)]
        self.assertEqual(0, rig.run("--host", "ops1"))
        self.assertEqual(PEM, rig.document()[CA_KEY])

    def test_a_ca_file_holding_a_private_key_is_refused(self) -> None:
        rig = Rig(self)
        rig.seed_ops1(skip=[CA_KEY])
        pem_file = rig.base / "ca.pem"
        pem_file.write_text(PEM + "-----BEGIN PRIVATE KEY-----\nSENTKEY\n", encoding="utf-8")
        pem_file.chmod(0o600)
        rig.path_answers = [str(pem_file)]
        self.assertEqual(1, rig.run("--host", "ops1"))
        self.assertIn(f"still missing (1): {CA_KEY}", rig.stdout)
        self.assertFalse(rig.dest.exists())

    def test_a_ca_path_that_does_not_exist_is_missing(self) -> None:
        rig = Rig(self, path_answers=[str(Path(tempfile.gettempdir()) / "absent-ca.pem")])
        rig.seed_ops1(skip=[CA_KEY])
        self.assertEqual(1, rig.run("--host", "ops1"))
        self.assertIn(f"still missing (1): {CA_KEY}", rig.stdout)

    def test_a_live_ca_that_is_not_a_certificate_is_not_used(self) -> None:
        rig = Rig(self)
        rig.seed_ops1()
        rig.put("db1-ca.pem", "-----BEGIN PRIVATE KEY-----\nSENTKEY\n")
        self.assertEqual(1, rig.run("--host", "ops1"))
        self.assertIn(CA_KEY, rig.stdout)
        self.assertNotIn("SENTKEY", rig.everything)


class SourceSafetyTests(unittest.TestCase):
    def test_a_key_found_twice_is_not_guessed_and_is_reported_by_file_and_key(self) -> None:
        rig = Rig(self, answers=["typed"])
        rig.seed_edge1()
        text = (rig.cfg / "monitoring.env").read_text() + "SMTP_USERNAME=second-SENT\n"
        rig.put("monitoring.env", text)
        self.assertEqual(0, rig.run("--host", "edge1"))
        self.assertEqual("typed", rig.document()["monitoring_stack_smtp_username"])
        self.assertIn("monitoring.env SMTP_USERNAME (duplicate)", rig.stdout)
        self.assertNotIn("second-SENT", rig.everything)

    def test_a_live_file_that_is_a_link_is_not_read(self) -> None:
        rig = Rig(self, answers=["typed"])
        rig.seed_edge1(skip=["monitoring_stack_snds_data_url"])
        real = rig.base / "elsewhere.env"
        real.write_text("SNDS_DATA_URL=SENT-linked\n", encoding="utf-8")
        real.chmod(0o600)
        (rig.cfg / "monitoring.env").unlink()
        (rig.cfg / "monitoring.env").symlink_to(real)
        self.assertEqual(1, rig.run("--host", "edge1"))
        self.assertNotIn("SENT-linked", rig.everything)
        self.assertIn("monitoring.env (link or unreadable)", rig.stdout)

    def test_a_live_file_that_others_can_write_is_not_read(self) -> None:
        rig = Rig(self)
        rig.seed_edge1()
        (rig.cfg / "monitoring.env").chmod(0o666)
        self.assertEqual(1, rig.run("--host", "edge1"))
        self.assertIn("monitoring.env (writable by others)", rig.stdout)
        self.assertNotIn("SENT-", rig.everything)

    def test_malformed_recipients_are_not_used(self) -> None:
        rig = Rig(self)
        rig.seed_ops1()
        rig.put("backup-worker-recipients", "alpha\n")
        self.assertEqual(1, rig.run("--host", "ops1"))
        self.assertIn(TENANTS_KEY, rig.stdout)

    def test_parse_env_reports_duplicates_and_keeps_the_text_after_the_first_equals(self) -> None:
        values, duplicates = tool.parse_env("A=1=2\nB=x\nB=y\n#C=z\n\nnot a pair\n")
        self.assertEqual({"A": "1=2", "B": "y"}, values)
        self.assertEqual({"B"}, duplicates)


class WriteTests(unittest.TestCase):
    def test_the_file_is_a_regular_root_file_closed_to_everyone_else(self) -> None:
        rig = Rig(self)
        rig.seed_edge1()
        rig.run("--host", "edge1")
        info = rig.dest.lstat()
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(0o600, stat.S_IMODE(info.st_mode))
        self.assertEqual(rig.uid, info.st_uid)
        self.assertEqual(rig.ctx.root_gid, info.st_gid)
        self.assertEqual([], [p.name for p in rig.cfg.iterdir() if p.name.endswith(".tmp")])

    def test_an_existing_file_is_left_byte_for_byte_without_replace(self) -> None:
        rig = Rig(self)
        rig.seed_edge1()
        rig.put(tool.DEST_NAME, '{"keep": "this"}\n')
        self.assertEqual(1, rig.run("--host", "edge1"))
        self.assertEqual('{"keep": "this"}\n', rig.dest.read_text())
        self.assertIn("already exists", rig.stdout)
        self.assertEqual([], rig.prompts)

    def test_replace_replaces_an_existing_file_and_keeps_the_mode(self) -> None:
        rig = Rig(self)
        rig.seed_edge1()
        rig.put(tool.DEST_NAME, '{"keep": "this"}\n', mode=0o644)
        self.assertEqual(0, rig.run("--host", "edge1", "--replace"))
        self.assertEqual(edge1_document(), rig.document())
        self.assertEqual(0o600, stat.S_IMODE(rig.dest.stat().st_mode))

    def test_a_file_that_appears_while_the_owner_is_typing_is_not_overwritten(self) -> None:
        rig = Rig(self)
        rig.seed_edge1(skip=["monitoring_stack_snds_data_url"])

        def appears(prompt: str) -> str:
            rig.prompts.append(prompt)
            rig.put(tool.DEST_NAME, '{"appeared": "meanwhile"}\n')
            return "typed"

        rig.ctx.ask_secret = appears
        self.assertEqual(1, rig.run("--host", "edge1"))
        self.assertEqual('{"appeared": "meanwhile"}\n', rig.dest.read_text())
        self.assertEqual([], [p.name for p in rig.cfg.iterdir() if p.name.endswith(".tmp")])

    def test_a_link_at_the_destination_is_replaced_not_followed(self) -> None:
        rig = Rig(self)
        rig.seed_edge1()
        target = rig.base / "target.json"
        target.write_text("target-untouched", encoding="utf-8")
        rig.dest.symlink_to(target)
        self.assertEqual(1, rig.run("--host", "edge1"))
        self.assertEqual("target-untouched", target.read_text())
        self.assertEqual(0, rig.run("--host", "edge1", "--replace"))
        self.assertFalse(rig.dest.is_symlink())
        self.assertEqual("target-untouched", target.read_text())

    def test_a_failed_install_leaves_no_file_and_no_temporary_file(self) -> None:
        rig = Rig(self)
        rig.seed_edge1()
        with mock.patch("os.link", side_effect=OSError(5, "SENT-LINKFAIL")):
            self.assertEqual(1, rig.run("--host", "edge1"))
        self.assertFalse(rig.dest.exists())
        self.assertEqual([], [p.name for p in rig.cfg.iterdir() if p.name.endswith(".tmp")])
        self.assertIn("OSError", rig.err.getvalue())

    def test_the_json_is_the_documents_keys_and_nothing_else(self) -> None:
        rig = Rig(self)
        rig.seed_ops1()
        rig.run("--host", "ops1")
        self.assertEqual(set(OPS1_KEYS), set(rig.document()))

    def test_a_non_root_user_is_refused_before_anything_is_read_or_asked(self) -> None:
        rig = Rig(self, euid=os.getuid() + 1, answers=["x"])
        rig.seed_edge1()
        self.assertEqual(1, rig.run("--host", "edge1"))
        self.assertFalse(rig.dest.exists())
        self.assertEqual([], rig.prompts)
        self.assertIn("must run as root", rig.err.getvalue())

    def test_a_directory_others_can_write_is_refused(self) -> None:
        rig = Rig(self)
        rig.seed_edge1()
        rig.cfg.chmod(0o775)
        self.assertEqual(1, rig.run("--host", "edge1"))
        self.assertFalse(rig.dest.exists())
        self.assertIn("directory", rig.err.getvalue())

    def test_a_directory_that_is_a_link_is_refused(self) -> None:
        rig = Rig(self)
        rig.seed_edge1()
        linked = rig.base / "linked"
        linked.symlink_to(rig.cfg)
        rig.ctx.config_dir = linked
        rig.ctx.ancestors = (linked,)
        self.assertEqual(1, rig.run("--host", "edge1"))
        self.assertFalse(rig.dest.exists())

    def test_a_directory_not_owned_by_root_is_refused(self) -> None:
        rig = Rig(self)
        rig.seed_edge1()
        rig.ctx.root_uid = rig.uid + 1
        self.assertEqual(1, rig.run("--host", "edge1"))
        self.assertFalse(rig.dest.exists())

    def test_an_unknown_host_is_refused(self) -> None:
        for host in ("db1", "app1", "demo1"):
            rig = Rig(self)
            self.assertEqual(1, rig.run("--host", host), host)
            self.assertFalse(rig.dest.exists())

    def test_there_is_no_path_flag_and_no_value_flag(self) -> None:
        for extra in (["--path", "x/y"], ["--value", "x"], ["--dest", "x/y"]):
            rig = Rig(self)
            with self.assertRaises(SystemExit):
                rig.run("--host", "edge1", *extra)


class SetTests(unittest.TestCase):
    KEY = "monitoring_stack_snds_data_url"

    def seeded(self, answers: Sequence[str] = ("rotated-value",)) -> Rig:
        rig = Rig(self, answers=answers)
        rig.put(tool.DEST_NAME, json.dumps(edge1_document()))
        return rig

    def test_set_changes_the_one_key_and_no_other(self) -> None:
        rig = self.seeded()
        self.assertEqual(0, rig.run("--host", "edge1", "--set", self.KEY))
        expected = {**edge1_document(), self.KEY: "rotated-value"}
        self.assertEqual(expected, rig.document())
        self.assertEqual(0o600, stat.S_IMODE(rig.dest.stat().st_mode))
        self.assertIn(self.KEY, rig.stdout)
        self.assertIn(f"{len('rotated-value')} bytes", rig.stdout)
        self.assertNotIn("rotated-value", rig.everything)
        self.assertEqual([], [p.name for p in rig.cfg.iterdir() if p.name.endswith(".tmp")])

    def test_set_prompts_with_the_key_name(self) -> None:
        rig = self.seeded()
        rig.run("--host", "edge1", "--set", self.KEY)
        self.assertEqual(1, len(rig.prompts))
        self.assertIn(self.KEY, rig.prompts[0])

    def test_set_refuses_a_key_outside_the_hosts_row_and_does_not_echo_it(self) -> None:
        rig = self.seeded()
        before = rig.dest.read_bytes()
        for key in ("pull_trigger_signers", "backup_worker_db_host", "SENT-pasted-secret"):
            self.assertEqual(1, rig.run("--host", "edge1", "--set", key), key)
        self.assertEqual(before, rig.dest.read_bytes())
        self.assertEqual([], rig.prompts)
        self.assertNotIn("SENT-pasted-secret", rig.everything)

    def test_set_refuses_a_missing_file(self) -> None:
        rig = Rig(self, answers=["x"])
        self.assertEqual(1, rig.run("--host", "edge1", "--set", self.KEY))
        self.assertFalse(rig.dest.exists())
        self.assertEqual([], rig.prompts)

    def test_set_refuses_a_file_with_the_wrong_mode(self) -> None:
        rig = self.seeded()
        rig.dest.chmod(0o644)
        before = rig.dest.read_bytes()
        self.assertEqual(1, rig.run("--host", "edge1", "--set", self.KEY))
        self.assertEqual(before, rig.dest.read_bytes())

    def test_set_refuses_a_file_holding_a_key_outside_the_row(self) -> None:
        rig = Rig(self, answers=["x"])
        rig.put(tool.DEST_NAME, json.dumps({**edge1_document(), "pull_trigger_signers": "x"}))
        before = rig.dest.read_bytes()
        self.assertEqual(1, rig.run("--host", "edge1", "--set", self.KEY))
        self.assertEqual(before, rig.dest.read_bytes())

    def test_set_refuses_a_file_that_is_not_one_json_object(self) -> None:
        for text in ("[1]", '{"a": "SENT-BADJSON', ""):
            rig = Rig(self, answers=["x"])
            rig.put(tool.DEST_NAME, text)
            self.assertEqual(1, rig.run("--host", "edge1", "--set", self.KEY), text)
            self.assertEqual(text, rig.dest.read_text())
            self.assertNotIn("SENT-BADJSON", rig.everything)

    def test_set_refuses_an_empty_answer(self) -> None:
        rig = self.seeded(answers=[""])
        before = rig.dest.read_bytes()
        self.assertEqual(1, rig.run("--host", "edge1", "--set", self.KEY))
        self.assertEqual(before, rig.dest.read_bytes())

    def test_set_with_no_terminal_changes_nothing(self) -> None:
        rig = self.seeded(answers=[])
        before = rig.dest.read_bytes()
        self.assertEqual(1, rig.run("--host", "edge1", "--set", self.KEY))
        self.assertEqual(before, rig.dest.read_bytes())

    def test_set_cannot_be_combined_with_replace(self) -> None:
        rig = self.seeded()
        with self.assertRaises(SystemExit):
            rig.run("--host", "edge1", "--set", self.KEY, "--replace")

    def test_set_by_a_non_root_user_is_refused(self) -> None:
        rig = Rig(self, euid=os.getuid() + 1, answers=["x"])
        rig.put(tool.DEST_NAME, json.dumps(edge1_document()))
        before = rig.dest.read_bytes()
        self.assertEqual(1, rig.run("--host", "edge1", "--set", self.KEY))
        self.assertEqual(before, rig.dest.read_bytes())
        self.assertEqual([], rig.prompts)

    def test_set_of_the_tenants_takes_lines_and_keeps_the_list_shape(self) -> None:
        rig = Rig(self, answers=[f"gamma {RECIPIENT_A}", ""])
        rig.put(tool.DEST_NAME, json.dumps(ops1_document()))
        self.assertEqual(0, rig.run("--host", "ops1", "--set", TENANTS_KEY))
        self.assertEqual([{"slug": "gamma", "recipient": RECIPIENT_A}], rig.document()[TENANTS_KEY])


class LeakTests(unittest.TestCase):
    """No value reaches stdout, stderr or a prompt, on any path."""

    def sentinels(self) -> list[str]:
        values = [value_for(key) for key in (*EDGE1_KEYS, *OPS1_LIVE)]
        return [
            *values,
            "MIIBsentinelcertbody",
            RECIPIENT_A,
            RECIPIENT_B,
            "SENT-TYPED",
            "SENT-LINKFAIL",
        ]

    def assert_clean(self, rig: Rig, label: str) -> None:
        for sentinel in self.sentinels():
            self.assertNotIn(sentinel, rig.everything, f"{label}: {sentinel}")

    def test_success_paths(self) -> None:
        rig = Rig(self, answers=["SENT-TYPED"])
        rig.seed_edge1(skip=["monitoring_stack_snds_data_url"])
        self.assertEqual(0, rig.run("--host", "edge1"))
        self.assert_clean(rig, "edge1 fill")
        rig = Rig(self)
        rig.seed_ops1()
        self.assertEqual(0, rig.run("--host", "ops1"))
        self.assert_clean(rig, "ops1 fill")

    def test_set_paths(self) -> None:
        rig = Rig(self, answers=["SENT-TYPED"])
        rig.put(tool.DEST_NAME, json.dumps(edge1_document()))
        self.assertEqual(0, rig.run("--host", "edge1", "--set", "monitoring_stack_snds_data_url"))
        self.assert_clean(rig, "set")

    def test_failure_paths(self) -> None:
        cases: list[tuple[str, Rig, tuple[str, ...]]] = []
        missing = Rig(self)
        missing.seed_edge1(skip=["monitoring_stack_snds_data_url"])
        cases.append(("missing", missing, ("--host", "edge1")))
        exists = Rig(self)
        exists.seed_edge1()
        exists.put(tool.DEST_NAME, json.dumps(edge1_document()))
        cases.append(("exists", exists, ("--host", "edge1")))
        duplicate = Rig(self, answers=["SENT-TYPED"])
        duplicate.seed_edge1()
        duplicate.put(
            "monitoring.env",
            (duplicate.cfg / "monitoring.env").read_text() + f"SMTP_USERNAME={value_for('x')}\n",
        )
        cases.append(("duplicate", duplicate, ("--host", "edge1", "--replace")))
        stranger = Rig(self, euid=os.getuid() + 1)
        stranger.seed_edge1()
        cases.append(("non-root", stranger, ("--host", "edge1")))
        bad = Rig(self, answers=["SENT-TYPED"])
        bad.put(tool.DEST_NAME, '{"monitoring_stack_snds_data_url": "' + value_for("bad"))
        cases.append(
            ("bad json", bad, ("--host", "edge1", "--set", "monitoring_stack_snds_data_url"))
        )
        for label, rig, argv in cases:
            rig.run(*argv)
            self.assert_clean(rig, label)

    def test_an_exception_whose_text_holds_a_value_is_not_printed(self) -> None:
        # The link installs a new file, so it is tried with no file there; a rename needs one.
        for target, existing, flags in (
            ("os.link", False, ()),
            ("os.fsync", False, ()),
            ("os.replace", True, ("--replace",)),
        ):
            rig = Rig(self)
            rig.seed_edge1()
            if existing:
                rig.put(tool.DEST_NAME, "{}")
            with mock.patch(target, side_effect=OSError(5, "SENT-LINKFAIL")):
                rig.run("--host", "edge1", *flags)
            self.assert_clean(rig, target)
            self.assertIn("OSError", rig.err.getvalue(), target)

    def test_a_value_is_never_an_argument_of_a_process(self) -> None:
        rig = Rig(self)
        rig.seed_edge1()
        with (
            mock.patch("subprocess.run") as run,
            mock.patch("subprocess.Popen") as popen,
            mock.patch("os.system") as system,
        ):
            rig.run("--host", "edge1")
        self.assertFalse(run.called or popen.called or system.called)


class ProductionContextTests(unittest.TestCase):
    def test_the_production_context_points_at_the_real_directory_and_the_real_prompts(self) -> None:
        ctx = tool.production_context()
        self.assertEqual(Path(tool.CONFIG_DIR), ctx.config_dir)
        self.assertEqual(tuple(Path(p) for p in tool.ANCESTORS), ctx.ancestors)
        self.assertEqual(os.geteuid(), ctx.euid)
        self.assertEqual(tool.ROOT_UID, ctx.root_uid)
        self.assertEqual(tool.ROOT_GID, ctx.root_gid)


if __name__ == "__main__":
    unittest.main()
