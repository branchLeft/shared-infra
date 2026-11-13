"""Read a CODEOWNERS file the way GitHub does, and say who owns a path.

This is the one home of the matcher that ansible/checks/test_codeowners.py and the command line
below share. The last line that matches a path wins, a line with no owner un-owns what it
matches, and there is no catch-all line. SAMPLES is a fixed table of paths, each in the class of
change it stands for, with the answer the repository's CODEOWNERS must give: every class the owner
keeps is owned, and every class that merges on the reviewer App's approval is not.

    codeowners_match.py                    check SAMPLES against .github/CODEOWNERS
    codeowners_match.py --file PATH        the same against any CODEOWNERS file
    codeowners_match.py --tuple            print the patterns, in file order, as a Python tuple
    codeowners_match.py --tree             count the tracked files the file owns
    codeowners_match.py --path PATH ...    print who owns each path

The samples run exits 1 when any sample's answer differs, and prints one line per sample.
"""

from __future__ import annotations

import argparse
import functools
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import NamedTuple

import pathspec

ROOT = Path(__file__).resolve().parents[2]
CODEOWNERS = ROOT / ".github" / "CODEOWNERS"
OWNER = "@branchLeft/branchleft-admin"

Rule = tuple[str, list[str]]


class Sample(NamedTuple):
    """One path, the class of change it stands for, and whether the owner must own it."""

    path: str
    klass: str
    owned: bool


def parse_rules(text: str) -> list[Rule]:
    """Return each line of a CODEOWNERS file as its pattern and its owners, in file order."""
    rules: list[Rule] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        pattern, *owners = line.split()
        rules.append((pattern, owners))
    return rules


@functools.cache
def _spec(pattern: str) -> pathspec.GitIgnoreSpec:
    return pathspec.GitIgnoreSpec.from_lines([pattern])


def owners_of(path: str, rules: list[Rule]) -> list[str]:
    """Return the owners of ``path``: those of the last rule that matches it, or none."""
    owners: list[str] = []
    for pattern, rule_owners in rules:
        if _spec(pattern).match_file(path):
            owners = rule_owners
    return owners


# What the owner keeps (owned) and what merges on the reviewer App's approval (released). Each
# kept class has a path here, and so has each released class, so that a matcher or a file that
# called everything owned, or nothing, is seen. Paths that name a file the repository does not
# hold yet are in PENDING.
SAMPLES: tuple[Sample, ...] = (
    # Rules, gates and exemption files.
    Sample(".github/CODEOWNERS", "rule: the review rule itself", True),
    Sample(".github/workflows/ci.yml", "rule: a workflow", True),
    Sample("CLAUDE.md", "rule: the repository's instructions", True),
    Sample(".pre-commit-config.yaml", "rule: the hook set", True),
    Sample(".ansible-lint", "rule: a lint floor", True),
    Sample(".image-scan-exemptions.json", "rule: an exemption file", True),
    Sample(".docs-lint.mode", "rule: the docs-lint setting", True),
    Sample("ansible/checks/check_delivery.py", "gate: a CI gate check", True),
    Sample("ansible/checks/check_enrolment.py", "gate: the host-role check", True),
    Sample("ansible/checks/host_roles.yml", "gate: the host-role list", True),
    Sample("ansible/checks/test_check_delivery.py", "gate: a kept gate's test", True),
    Sample("scripts/assert-no-hetzner-deletes.py", "gate: a script a secret job runs", True),
    Sample("hetzner/provision/branchleft_deploy.py", "gate: the deploy account command", True),
    Sample("hetzner/provision/test_suite_size.py", "gate: the suite-size floor", True),
    Sample(
        "hetzner/scripts/check-crowdsec-hub-pin.py",
        "gate: a script whose exit code gates a write-token step",
        True,
    ),
    Sample(
        "hetzner/scripts/test_check_crowdsec_hub_pin.py",
        "gate: that script's test",
        True,
    ),
    Sample(
        "ansible/checks/test_deploy_verifier_coverage.py", "gate: what the verifier trusts", True
    ),
    Sample("hetzner/estate.guard.test.ts", "gate: a Pulumi guard test", True),
    Sample("hetzner/projectGuard.test.ts", "gate: the project guard test", True),
    # Trust, keys and access.
    Sample("ansible/trust/mx1.yml", "trust: a signer list", True),
    Sample("ansible/owner_vars/edge1.yml", "trust: the owner's values for a host", True),
    Sample("ansible/roles/ci_jump/tasks/main.yml", "access: ssh key options", True),
    Sample("ansible/roles/ci_login/tasks/_sudoers.yml", "access: sudoers", True),
    Sample("ansible/roles/db1_grants/tasks/main.yml", "access: database grants", True),
    Sample("ansible/roles/host_baseline/tasks/_ssh.yml", "access: sshd", True),
    Sample("ansible/roles/broker_deploy/tasks/_admin_keys_dir.yml", "access: verifier keys", True),
    Sample("ansible/roles/deploy_slot_keys/tasks/main.yml", "access: deploy account keys", True),
    Sample("ansible/roles/deploy_verifier/vars/main.yml", "access: the verifier's pinned gh", True),
    Sample("ansible/roles/broker_deploy/tasks/main.yml", "access: the broker account", True),
    Sample("ansible/roles/demo1_build/tasks/_accounts.yml", "access: demo1 accounts", True),
    Sample("ansible/roles/node_exporter/tasks/_node_exporter.yml", "access: its account", True),
    Sample("ansible/roles/backup_worker/tasks/main.yml", "access: the backup account", True),
    Sample("hetzner-host/cloudInit.test.ts", "access: a test of key injection", True),
    Sample("ansible/roles/db1_grants/tests/unit/test_db1_grants.py", "access: a grants test", True),
    Sample(
        "ansible/roles/breakglass_mint_host/molecule/default/verify.yml",
        "access: a break-glass test",
        True,
    ),
    Sample(
        "ansible/roles/tunnel_account/molecule/default/verify.yml", "access: a tunnel test", True
    ),
    Sample("ansible/roles/r/library/x.py", "loader: a role's library", True),
    Sample("ansible/library/x.py", "loader: the top-level library", True),
    Sample("hetzner/control-plane/stack/postgres/pg_hba.conf", "access: database access", True),
    # Mail.
    Sample("mail/provision/provision_mailboxes.py", "mail: a program run on mx1", True),
    Sample("ansible/playbooks/mx1.yml", "mail: the mx1 playbook", True),
    Sample("ansible/inventories/production/hosts.yml", "mail: the host inventory", True),
    # Billed resources, install-time controls, DNS zone data.
    Sample("hetzner/estate.ts", "billed: a Pulumi program", True),
    Sample("hetzner-host/host.ts", "billed: the published host package", True),
    Sample("hetzner/Pulumi.production.yaml", "billed: a stack file", True),
    Sample("hetzner/package.json", "billed: install-time scripts", True),
    Sample("hetzner/pnpm-workspace.yaml", "billed: install-time allowBuilds", True),
    Sample("ovh/copy2/stack.ts", "billed: object storage with object lock", True),
    Sample("hetzner/dns/zone.json", "dns: live zone data", True),
    # The launch page, the owner's words.
    Sample("hetzner/edge/publicpress/index.html", "public: the launch page", True),
    Sample("LICENSE", "public: the licence", True),
    Sample("sites.ts", "public: the hostname registry", True),
    Sample("hetzner/edge/render.ts", "public: the edge renderer", True),
    Sample("hetzner/edge/render.test.ts", "public: the test that holds the Caddyfile", True),
    Sample("hetzner/edge/stack/caddy/Caddyfile", "public: the committed Caddyfile", True),
    Sample("hetzner/edge/validation/Caddyfile.enforcing", "public: the enforcing Caddyfile", True),
    # Backups: the timers, the retention window and the schedule.
    Sample("ansible/roles/db1_backup_timers/tasks/main.yml", "backup: dump and prune timers", True),
    Sample(
        "ansible/roles/db1_backup_timers/tests/unit/test_db1_backup_timers.py",
        "backup: a timer test",
        True,
    ),
    Sample("ansible/roles/db1_stack/templates/branchleft.cnf.j2", "backup: binlog expiry", True),
    Sample("ansible/roles/db_t1/templates/branchleft.cnf.j2", "backup: binlog expiry", True),
    Sample(
        "ansible/roles/backup_worker/defaults/main.yml", "backup: the nightly timer switch", True
    ),
    Sample("ansible/roles/backup_restore/defaults/main.yml", "backup: the state-copy timer", True),
    # Released: documents, lockfiles and pins, host configuration, tests, checkers, probes.
    Sample("README.md", "released: a document", False),
    Sample("mail/RUNBOOK-mx1-provision.md", "released: a mail document", False),
    Sample("ansible/trust/README.md", "released: a trust document", False),
    Sample("ansible/roles/ci_jump/README.md", "released: a kept role's document", False),
    Sample("pnpm-lock.yaml", "released: a lockfile", False),
    Sample("hetzner/pnpm-lock.yaml", "released: a lockfile", False),
    Sample("ansible/requirements.txt", "released: a hash-locked pin", False),
    Sample("ansible/roles/edge_stack/tasks/main.yml", "released: host configuration", False),
    Sample("ansible/roles/egress_nat/tasks/main.yml", "released: host configuration", False),
    Sample("ansible/roles/mx1_stack/tasks/main.yml", "released: host configuration", False),
    Sample("ansible/roles/deploy_tooling/tasks/main.yml", "released: deploy wiring", False),
    Sample("ansible/roles/broker_deploy/templates/broker.env.j2", "released: broker wiring", False),
    Sample("ansible/roles/node_exporter/tasks/main.yml", "released: host configuration", False),
    Sample("ansible/roles/backup_worker/README.md", "released: a backup role's document", False),
    Sample("hetzner/estate.test.ts", "released: a Pulumi program test", False),
    Sample("ansible/checks/test_edge_single_home.py", "released: an agreement test", False),
    Sample("ansible/checks/test_ci_jump_hosts.py", "released: an agreement test", False),
    Sample("hetzner/dns/zonecheck.py", "released: a checker", False),
    Sample("hetzner/scripts/probe-object-storage.py", "released: a probe", False),
    Sample("hetzner/scripts/check-address-plan-drift.py", "released: a read-only checker", False),
    Sample("ansible/playbooks/edge1.yml", "released: a host playbook", False),
)

# Samples that stand for a file the repository does not hold, so they are not looked up on disk:
# the launch page is listed before a file is in it, and a loader file is any file in the directory.
PENDING: frozenset[str] = frozenset(
    {
        "hetzner/edge/publicpress/index.html",
        "ansible/roles/r/library/x.py",
        "ansible/library/x.py",
    }
)


def mismatches(rules: list[Rule], samples: Sequence[Sample] = SAMPLES) -> list[Sample]:
    """Return the samples for which ``rules`` give a different answer than the table."""
    return [s for s in samples if (owners_of(s.path, rules) == [OWNER]) != s.owned]


def patterns(rules: list[Rule]) -> tuple[str, ...]:
    """Return the patterns of ``rules`` in file order."""
    return tuple(pattern for pattern, _ in rules)


def tracked_files() -> list[str]:
    """Return every file git tracks in this repository."""
    out = subprocess.run(  # noqa: S603
        ["git", "-C", str(ROOT), "ls-files"],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [line for line in out.splitlines() if line]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0] if __doc__ else None)
    parser.add_argument("--file", type=Path, default=CODEOWNERS, help="the CODEOWNERS file to read")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--tuple", action="store_true", help="print the patterns as a Python tuple")
    mode.add_argument("--tree", action="store_true", help="count the tracked files that are owned")
    mode.add_argument("--path", nargs="+", metavar="PATH", help="print who owns each path")
    args = parser.parse_args(argv)
    rules = parse_rules(args.file.read_text(encoding="utf-8"))
    if args.path:
        for path in args.path:
            sys.stdout.write(f"{' '.join(owners_of(path, rules)) or '(no owner)':32} {path}\n")
        return 0
    if args.tuple:
        sys.stdout.write("(\n")
        for pattern in patterns(rules):
            sys.stdout.write(f'    "{pattern}",\n')
        sys.stdout.write(")\n")
        return 0
    if args.tree:
        files = tracked_files()
        owned = sum(1 for path in files if owners_of(path, rules))
        sys.stdout.write(f"files {len(files)} owned {owned}\n")
        return 0
    wrong = set(mismatches(rules))
    for sample in SAMPLES:
        want = "owned" if sample.owned else "released"
        flag = "MISMATCH" if sample in wrong else "ok"
        sys.stdout.write(f"{flag:8} want {want:8} {sample.path}  [{sample.klass}]\n")
    sys.stdout.write(f"{len(SAMPLES) - len(wrong)} of {len(SAMPLES)} samples as required\n")
    return 1 if wrong else 0


if __name__ == "__main__":
    raise SystemExit(main())
