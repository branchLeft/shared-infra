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
import subprocess
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path
from unittest import mock

import seed_host_inputs as tool
import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[2]
ROLES = ROOT / "ansible" / "roles"

# The host whose private inputs file exists already and which this tool does not seed: db1 has
# no live file to read. A new host in the loader's rows fails until it is named here or in the tool.
UNSUPPORTED = frozenset({"db1"})

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
APP1_LIVE: dict[str, tuple[str, str]] = {
    "website_app1_smtp_host": ("website.env", "CONTACT_SMTP_HOST"),
    "website_app1_smtp_port": ("website.env", "CONTACT_SMTP_PORT"),
    "website_app1_smtp_user": ("website.env", "CONTACT_SMTP_USER"),
    "website_app1_smtp_password": ("website.env", "CONTACT_SMTP_PASSWORD"),
}
STACKS_KEY = "tenant_compose_stacks"
APP1_KEYS = (*APP1_LIVE, STACKS_KEY)
# Two made-up tenants and their uids, in the order the volume program lists them.
STACK_CLAIMS = (("tenant-a", 30901), ("tenant-b", 30902))
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


def stack_texts(slug: str) -> dict[str, str]:
    """The three files of a made-up tenant's stack, as the role would deliver them. Every text
    carries a sentinel, and the compose file of tenant-b has Windows line ends and no final
    newline, so a copy that tidied a file would not equal what is live."""
    compose = (
        f"# SENT-compose-{slug}\nname: {slug}\nservices:\n  ghost:\n    image: ${{IMAGE}}\n"
        "    environment:\n      database__connection__password: "
        "${GHOST_database__connection__password}\n"
    )
    if slug == "tenant-b":
        compose = compose.replace("\n", "\r\n").rstrip("\r\n")
    return {
        "compose_text": compose,
        "secrets_env_text": f"GHOST_database__connection__password=SENT-secret-{slug}-a=b&c==\n",
        "image_env_text": f"IMAGE=registry.example/{slug}@sha256:{'ab' * 32}\n",
    }


def stacks_document() -> list[dict[str, object]]:
    return [{"slug": slug, "uid": uid, **stack_texts(slug)} for slug, uid in STACK_CLAIMS]


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

    def test_website_env_names_equal_the_role(self) -> None:
        website = yaml_of(ROLES / "website_app1" / "defaults" / "main.yml")
        role = template_pairs(ROLES / "website_app1" / "templates" / "website.env.j2")
        self.assertEqual(role, tool_pairs("website.env"))
        self.assertEqual(f"{tool.CONFIG_DIR}/website.env", str(website["website_app1_env_file"]))

    def test_the_stack_paths_and_the_volume_program_are_the_tenant_compose_roles(self) -> None:
        role = yaml_of(ROLES / "tenant_compose" / "vars" / "main.yml")
        self.assertEqual(str(role["tenant_compose_stack_root"]), tool.STACK_ROOT)
        self.assertEqual(str(role["tenant_compose_config_root"]), tool.CONFIG_DIR)
        # One home: the program's path is the role's, and the key's one source is that program.
        self.assertEqual(str(role["tenant_compose_volume_program"]), tool.VOLUME_PROGRAM)
        self.assertEqual((tool.Source(tool.STACKS, tool.VOLUME_PROGRAM),), tool.SOURCES[STACKS_KEY])
        tasks = (ROLES / "tenant_compose" / "tasks" / "_stack.yml").read_text(encoding="utf-8")
        main = (ROLES / "tenant_compose" / "tasks" / "main.yml").read_text(encoding="utf-8")
        self.assertIn("- --list-claims", main)
        for expected in (
            "tenant_compose_env_path: "
            "'{{ tenant_compose_config_root }}/{{ tenant_compose_stack.slug }}.env'",
            "tenant_compose_image_env_path: "
            "'{{ tenant_compose_config_root }}/{{ tenant_compose_stack.slug }}.image.env'",
            "dest: '{{ tenant_compose_project_dir }}/compose.yml'",
        ):
            self.assertIn(expected, tasks)

    def test_the_slug_uid_and_claim_rules_are_the_roles_module(self) -> None:
        module = (ROLES / "tenant_compose" / "library" / "tenant_compose_check.py").read_text(
            encoding="utf-8"
        )
        self.assertIn(f'SLUG_PATTERN = re.compile(r"{tool.SLUG_PATTERN.pattern}")', module)
        self.assertIn(f"SLUG_MAX_LENGTH = {tool.SLUG_MAX_LENGTH}", module)
        self.assertIn(f'SPOOL_SLUG = "{tool.SPOOL_SLUG}"', module)
        self.assertIn(f'CLAIM_LINE_PATTERN = re.compile(r"{tool.CLAIM_PATTERN.pattern}")', module)
        self.assertIn(f"UID_MIN = {tool.UID_RANGE.start}", module)
        self.assertIn(f"UID_MAX = {tool.UID_RANGE.stop - 1}", module)

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
        self.opt = self.base / "opt"
        self.opt.mkdir()
        self.opt.chmod(0o755)
        # What the volume program lists; None stands for a program that cannot be run.
        self.claims_text: str | None = ""
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
            stack_root=self.opt,
            list_claims=self.claims,
        )

    def claims(self) -> str:
        if self.claims_text is None:
            raise tool.SeedError("claims")
        return self.claims_text

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

    def seed_app1(self, skip: Sequence[str] = ()) -> None:
        lines = [
            f"{name}={app1_value(key)}\n" for key, (_, name) in APP1_LIVE.items() if key not in skip
        ]
        if lines:
            self.put("website.env", "".join(lines))
        if STACKS_KEY not in skip:
            self.seed_stacks()

    def seed_stacks(self, claims: Sequence[tuple[str, int]] = STACK_CLAIMS) -> None:
        """List the tenants as claimed, and lay each one's three files out as they are live."""
        self.claims_text = "".join(f"{slug}={uid}\n" for slug, uid in claims)
        for slug, _ in claims:
            texts = stack_texts(slug)
            directory = self.opt / slug
            directory.mkdir()
            directory.chmod(0o755)
            (directory / "compose.yml").write_bytes(texts["compose_text"].encode("utf-8"))
            (directory / "compose.yml").chmod(0o644)
            self.put(f"{slug}.env", texts["secrets_env_text"])
            self.put(f"{slug}.image.env", texts["image_env_text"])

    def document(self) -> dict[str, object]:
        return mapping_of(json.loads(self.dest.read_text(encoding="utf-8")))


def edge1_document() -> dict[str, object]:
    return {key: value_for(key) for key in EDGE1_KEYS}


def ops1_document() -> dict[str, object]:
    document: dict[str, object] = {key: value_for(key) for key in OPS1_LIVE}
    document[CA_KEY] = PEM
    document[TENANTS_KEY] = TENANTS
    return {key: document[key] for key in OPS1_KEYS}


def app1_value(key: str) -> str:
    """The host, port and user are made-up names, the port as the text a file holds; the password
    is a sentinel, so the leak test covers it."""
    plain = {
        "website_app1_smtp_host": "smtp.example.test",
        "website_app1_smtp_port": "587",
        "website_app1_smtp_user": "mailer.example.test",
    }
    return plain.get(key, value_for(key))


def app1_document() -> dict[str, object]:
    document: dict[str, object] = {key: app1_value(key) for key in APP1_LIVE}
    document[STACKS_KEY] = stacks_document()
    return document


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

    def test_app1_is_filled_from_website_env_with_no_prompt(self) -> None:
        rig = Rig(self)
        rig.seed_app1()
        self.assertEqual(0, rig.run("--host", "app1"))
        self.assertEqual(app1_document(), rig.document())
        self.assertEqual([], rig.prompts)
        self.assertIn(
            "filled from live (5): website_app1_smtp_host, website_app1_smtp_port, "
            "website_app1_smtp_user, website_app1_smtp_password, tenant_compose_stacks",
            rig.stdout,
        )
        self.assertIn("still missing (0): none", rig.stdout)

    def test_app1_port_stays_a_string(self) -> None:
        rig = Rig(self)
        rig.seed_app1()
        self.assertEqual(0, rig.run("--host", "app1"))
        port = rig.document()["website_app1_smtp_port"]
        self.assertEqual("587", port)
        self.assertIsInstance(port, str)

    def test_an_app1_key_missing_from_website_env_is_still_missing_and_nothing_is_written(
        self,
    ) -> None:
        rig = Rig(self)
        rig.seed_app1(skip=["website_app1_smtp_port"])
        self.assertEqual(1, rig.run("--host", "app1"))
        self.assertIn("still missing (1): website_app1_smtp_port", rig.stdout)
        self.assertFalse(rig.dest.exists())


class StackTests(unittest.TestCase):
    """app1's tenant stacks: the tenants the volume program lists, from the files that are live."""

    def test_the_stacks_equal_the_live_files_byte_for_byte_in_the_claimed_order(self) -> None:
        rig = Rig(self)
        rig.seed_app1()
        self.assertEqual(0, rig.run("--host", "app1"))
        stacks = list_of(rig.document()[STACKS_KEY])
        self.assertEqual(stacks_document(), stacks)
        for entry in stacks:
            self.assertIsInstance(mapping_of(entry)["uid"], int)
        # The odd one is kept as it is: Windows line ends, no final newline.
        self.assertEqual(
            stack_texts("tenant-b")["compose_text"], mapping_of(stacks[1])["compose_text"]
        )
        self.assertFalse(str(mapping_of(stacks[1])["compose_text"]).endswith("\n"))

    def test_a_stack_is_never_prompted_for(self) -> None:
        rig = Rig(self)
        rig.seed_app1()
        self.assertEqual(0, rig.run("--host", "app1"))
        self.assertEqual([], rig.prompts)

    def test_the_report_names_the_tenants_and_no_value(self) -> None:
        rig = Rig(self)
        rig.seed_app1()
        self.assertEqual(0, rig.run("--host", "app1"))
        self.assertIn(
            "tenant stacks seeded (2): tenant-a, tenant-b; "
            "claimed with no stack on the host, left out (0): none",
            rig.stdout,
        )

    def test_a_tenant_claimed_with_no_stack_on_the_host_is_left_out_by_name(self) -> None:
        rig = Rig(self)
        rig.seed_app1()
        rig.claims_text = (rig.claims_text or "") + "tenant-c=30903\n"
        self.assertEqual(0, rig.run("--host", "app1"))
        self.assertEqual(stacks_document(), rig.document()[STACKS_KEY])
        self.assertIn("left out (1): tenant-c", rig.stdout)

    def test_a_tenant_with_only_some_of_its_three_files_is_not_guessed(self) -> None:
        for gone in ("tenant-a.env", "tenant-a.image.env"):
            with self.subTest(gone=gone):
                rig = Rig(self)
                rig.seed_app1()
                (rig.cfg / gone).unlink()
                self.assertEqual(1, rig.run("--host", "app1"))
                self.assertIn("tenant-a (some of the stack's three files are missing)", rig.stdout)
                self.assertIn("still missing (1): tenant_compose_stacks", rig.stdout)
                self.assertFalse(rig.dest.exists())

    def test_a_tenant_whose_compose_file_is_missing_is_not_guessed(self) -> None:
        rig = Rig(self)
        rig.seed_app1()
        (rig.opt / "tenant-a" / "compose.yml").unlink()
        self.assertEqual(1, rig.run("--host", "app1"))
        self.assertFalse(rig.dest.exists())

    def test_an_empty_stack_file_is_not_used(self) -> None:
        for name in ("tenant-a.env", "tenant-a.image.env"):
            with self.subTest(name=name):
                rig = Rig(self)
                rig.seed_app1()
                rig.put(name, "  \n")
                self.assertEqual(1, rig.run("--host", "app1"))
                self.assertIn("tenant-a (a stack file is empty)", rig.stdout)
                self.assertFalse(rig.dest.exists())

    def test_a_stack_file_that_is_a_link_is_not_read(self) -> None:
        rig = Rig(self)
        rig.seed_app1()
        target = rig.base / "elsewhere"
        target.write_text("GHOST_x=SENT-linked\n", encoding="utf-8")
        (rig.cfg / "tenant-a.env").unlink()
        (rig.cfg / "tenant-a.env").symlink_to(target)
        self.assertEqual(1, rig.run("--host", "app1"))
        self.assertIn("tenant-a.env (link or unreadable)", rig.stdout)
        self.assertNotIn("SENT-linked", rig.everything)
        self.assertFalse(rig.dest.exists())

    def test_a_stack_file_others_can_write_is_not_read(self) -> None:
        rig = Rig(self)
        rig.seed_app1()
        (rig.opt / "tenant-b" / "compose.yml").chmod(0o666)
        self.assertEqual(1, rig.run("--host", "app1"))
        self.assertIn("tenant-b compose.yml (writable by others)", rig.stdout)
        self.assertFalse(rig.dest.exists())

    def test_a_stack_directory_that_is_a_link_or_open_to_others_is_not_read(self) -> None:
        rig = Rig(self)
        rig.seed_app1()
        (rig.opt / "tenant-a").rename(rig.base / "moved")
        (rig.opt / "tenant-a").symlink_to(rig.base / "moved")
        self.assertEqual(1, rig.run("--host", "app1"))
        self.assertIn(
            "tenant-a directory (not a real directory owned by root and closed)", rig.stdout
        )
        self.assertFalse(rig.dest.exists())
        rig = Rig(self)
        rig.seed_app1()
        (rig.opt / "tenant-b").chmod(0o777)
        self.assertEqual(1, rig.run("--host", "app1"))
        self.assertIn("tenant-b directory (not a real directory", rig.stdout)

    def test_a_program_that_cannot_run_writes_nothing_and_asks_nothing(self) -> None:
        rig = Rig(self)
        rig.seed_app1()
        rig.claims_text = None
        self.assertEqual(1, rig.run("--host", "app1"))
        self.assertIn("volume claims (the program could not be run)", rig.stdout)
        self.assertIn("still missing (1): tenant_compose_stacks", rig.stdout)
        self.assertEqual([], rig.prompts)
        self.assertFalse(rig.dest.exists())

    def test_no_claims_at_all_writes_nothing(self) -> None:
        rig = Rig(self)
        rig.seed_app1()
        rig.claims_text = ""
        self.assertEqual(1, rig.run("--host", "app1"))
        self.assertIn("still missing (1): tenant_compose_stacks", rig.stdout)
        self.assertFalse(rig.dest.exists())

    def test_a_claim_the_role_would_refuse_never_names_a_path(self) -> None:
        bad = (
            "tenant-a",
            "Tenant-a=30901",
            "../etc=30901",
            "tenant-a/../x=30901",
            "tenant-a=29999",
            "tenant-a=31000",
            "tenant-a=30901\ntenant-b=30901",
            "tenant-a=30901\ntenant-a=30902",
            "mail-spool=30903",
            "a" * 27 + "=30903",
            "-tenant=30903",
            "tenant-=30903",
            "tenant-a=30901 ",
        )
        for text in bad:
            with self.subTest(claims=text):
                rig = Rig(self)
                rig.seed_app1()
                rig.claims_text = text + "\n"
                self.assertEqual(1, rig.run("--host", "app1"))
                self.assertIn("volume claims (malformed)", rig.stdout)
                self.assertFalse(rig.dest.exists())

    def test_a_stack_cannot_be_set_at_a_prompt(self) -> None:
        rig = Rig(self, answers=["SENT-TYPED"])
        rig.seed_app1()
        self.assertEqual(0, rig.run("--host", "app1"))
        before = rig.dest.read_bytes()
        self.assertEqual(1, rig.run("--host", "app1", "--set", STACKS_KEY))
        self.assertIn(
            "a tenant's stack is never typed at a prompt; run with --replace", rig.err.getvalue()
        )
        self.assertEqual([], rig.prompts)
        self.assertEqual(before, rig.dest.read_bytes())

    def test_set_of_another_key_keeps_the_stacks(self) -> None:
        rig = Rig(self, answers=["smtp.rotated.example.test"])
        rig.seed_app1()
        self.assertEqual(0, rig.run("--host", "app1"))
        self.assertEqual(0, rig.run("--host", "app1", "--set", "website_app1_smtp_host"))
        document = rig.document()
        self.assertEqual("smtp.rotated.example.test", document["website_app1_smtp_host"])
        self.assertEqual(stacks_document(), document[STACKS_KEY])

    def test_replace_reads_the_live_files_again(self) -> None:
        rig = Rig(self)
        rig.seed_app1()
        self.assertEqual(0, rig.run("--host", "app1"))
        rig.put("tenant-a.env", "GHOST_database__connection__password=SENT-rotated\n")
        self.assertEqual(0, rig.run("--host", "app1", "--replace"))
        first = mapping_of(list_of(rig.document()[STACKS_KEY])[0])
        self.assertEqual(
            "GHOST_database__connection__password=SENT-rotated\n", first["secrets_env_text"]
        )

    def test_an_existing_file_is_not_overwritten_without_replace_and_no_program_is_run(
        self,
    ) -> None:
        rig = Rig(self)
        rig.seed_app1()
        rig.put(tool.DEST_NAME, "{}")
        rig.claims_text = None
        self.assertEqual(1, rig.run("--host", "app1"))
        self.assertNotIn("volume claims", rig.stdout)
        self.assertEqual("{}", rig.dest.read_text(encoding="utf-8"))

    def test_the_program_is_run_by_its_fixed_path_with_one_argument_and_no_shell(self) -> None:
        listing = subprocess.CompletedProcess([], 0, stdout=b"tenant-a=30901\n", stderr=b"")
        regular = os.stat_result((stat.S_IFREG | 0o755, 0, 0, 1, tool.ROOT_UID, 0, 0, 0, 0, 0))
        with (
            mock.patch("os.lstat", return_value=regular),
            mock.patch("subprocess.run", return_value=listing) as run,
        ):
            self.assertEqual("tenant-a=30901\n", tool.run_volume_program())
        self.assertEqual([tool.VOLUME_PROGRAM, "--list-claims"], run.call_args.args[0])
        self.assertIsNot(True, run.call_args.kwargs.get("shell"))
        self.assertEqual(subprocess.DEVNULL, run.call_args.kwargs["stdin"])
        self.assertEqual({"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}, run.call_args.kwargs["env"])

    def test_a_program_that_fails_or_that_others_can_write_is_not_trusted(self) -> None:
        failed = subprocess.CompletedProcess([], 1, stdout=b"tenant-a=30901\n", stderr=b"SENT-X")
        regular = os.stat_result((stat.S_IFREG | 0o755, 0, 0, 1, tool.ROOT_UID, 0, 0, 0, 0, 0))
        writable = os.stat_result((stat.S_IFREG | 0o775, 0, 0, 1, tool.ROOT_UID, 0, 0, 0, 0, 0))
        stranger = os.stat_result((stat.S_IFREG | 0o755, 0, 0, 1, 1000, 0, 0, 0, 0, 0))
        link = os.stat_result((stat.S_IFLNK | 0o777, 0, 0, 1, tool.ROOT_UID, 0, 0, 0, 0, 0))
        with (
            mock.patch("os.lstat", return_value=regular),
            mock.patch("subprocess.run", return_value=failed),
        ):
            with self.assertRaises(tool.SeedError):
                tool.run_volume_program()
        for refused in (writable, stranger, link):
            with (
                mock.patch("os.lstat", return_value=refused),
                mock.patch("subprocess.run") as run,
                self.assertRaises(tool.SeedError),
            ):
                tool.run_volume_program()
            self.assertFalse(run.called)
        with (
            mock.patch("os.lstat", side_effect=FileNotFoundError),
            self.assertRaises(tool.SeedError),
        ):
            tool.run_volume_program()


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
        for host in ("db1", "demo1"):
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
        values = [value_for(key) for key in (*EDGE1_KEYS, *OPS1_LIVE, "website_app1_smtp_password")]
        stacks = [
            text
            for slug, _ in STACK_CLAIMS
            for text in ("SENT-secret-" + slug, "SENT-compose-" + slug, "registry.example/" + slug)
        ]
        return [
            *values,
            *stacks,
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
        rig = Rig(self)
        rig.seed_app1()
        self.assertEqual(0, rig.run("--host", "app1"))
        self.assert_clean(rig, "app1 fill")

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
        partial = Rig(self)
        partial.seed_app1()
        (partial.cfg / "tenant-a.env").unlink()
        cases.append(("partial stack", partial, ("--host", "app1")))
        no_program = Rig(self)
        no_program.seed_app1()
        no_program.claims_text = None
        cases.append(("no volume program", no_program, ("--host", "app1")))
        bad_claims = Rig(self)
        bad_claims.seed_app1()
        bad_claims.claims_text = "tenant-a=30901\ntenant-a=30902\n"
        cases.append(("bad claims", bad_claims, ("--host", "app1")))
        set_stack = Rig(self, answers=["SENT-TYPED"])
        set_stack.put(tool.DEST_NAME, json.dumps(app1_document()))
        cases.append(("set a stack", set_stack, ("--host", "app1", "--set", STACKS_KEY)))
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
        self.assertEqual(Path(tool.STACK_ROOT), ctx.stack_root)
        self.assertIs(tool.run_volume_program, ctx.list_claims)


if __name__ == "__main__":
    unittest.main()
