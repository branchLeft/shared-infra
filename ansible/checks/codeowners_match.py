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
    codeowners_match.py --against OLD      list tracked files that lost or gained an owner
                                           against the CODEOWNERS file OLD (exit 1 on a loss)

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
    # Guardrails: the review rule, instructions, hooks, workflows and the gates they run.
    Sample(".github/CODEOWNERS", "rule: the review rule itself", True),
    Sample("ansible/checks/test_codeowners.py", "rule: the review rule's proof", True),
    Sample("ansible/checks/codeowners_match.py", "rule: the review rule's matcher", True),
    Sample(".github/workflows/ci.yml", "rule: a workflow", True),
    Sample(".github/actions/ci-skip/action.yml", "rule: an action", True),
    Sample("CLAUDE.md", "rule: the repository's instructions", True),
    Sample(".claude/.gitignore", "rule: the agent hook directory", True),
    Sample(".pre-commit-config.yaml", "rule: the hook set", True),
    Sample(".ansible-lint", "rule: a lint floor", True),
    Sample(".image-scan-exemptions.json", "rule: an exemption file", True),
    Sample(".docs-lint.mode", "rule: the docs-lint setting", True),
    Sample("tools/floors.tsv", "rule: the floors file", True),
    Sample("ansible/checks/check_delivery.py", "gate: a CI gate check", True),
    Sample("ansible/checks/check_enrolment.py", "gate: the host-role check", True),
    Sample("ansible/checks/host_roles/edge1.yml", "gate: a host's role allowlist", True),
    Sample("ansible/checks/test_check_delivery.py", "gate: a kept gate's test", True),
    Sample("ansible/harness/run_harness.py", "gate: the Ansible harness", True),
    Sample("scripts/assert-no-hetzner-deletes.py", "gate: the delete guard a secret job runs", True),
    Sample("scripts/choose-apply-environment.py", "gate: the apply approval routing", True),
    Sample("hetzner/scripts/check-crowdsec-hub-pin.py", "gate: a script gating a write step", True),
    Sample("hetzner/scripts/test_check_crowdsec_hub_pin.py", "gate: that script's test", True),
    Sample("hetzner/provision/test_suite_size.py", "gate: the suite-size floor", True),
    Sample("hetzner/provision/test_counts/test_suite_size.txt", "gate: a suite-size floor", True),
    Sample("ansible/trust/mx1.yml", "gate: a pull signer allowlist", True),
    Sample("ansible/playbooks/includes/require_signers.yml", "gate: the signer requirement", True),
    Sample("ansible/roles/deploy_verifier/files/trusted_root.jsonl", "gate: verifier trust", True),
    Sample("ansible/roles/deploy_verifier/files/branchleft-verify-image.py", "gate: verifier", True),
    Sample("hetzner/estate.guard.test.ts", "guard: a Pulumi guard test", True),
    Sample("hetzner/projectGuard.ts", "guard: the project guard", True),
    Sample("hetzner/projectGuard.test.ts", "guard: the project guard test", True),
    Sample("ovh/copy2/configGuard.test.ts", "guard: a config guard test", True),
    Sample("ansible/roles/status_page/tests/unit/test_status_page_drop_guard.py", "guard", True),
    # Human-facing documents and the owner's words.
    Sample("README.md", "doc: the readme", True),
    Sample("LICENSE", "doc: the licence", True),
    Sample("hetzner-host/LICENSE", "doc: a licence", True),
    Sample("hetzner/edge/publicpress/index.html", "doc: the launch page", True),
    # Released: trust extended to agents on sensitive code, merged on reviewer approval.
    Sample("sites.ts", "released: the hostname registry", False),
    Sample("hetzner/edge/render.ts", "released: the edge renderer", False),
    Sample("hetzner/edge/render.test.ts", "released: the test that holds the Caddyfile", False),
    Sample("hetzner/edge/stack/caddy/Caddyfile", "released: the committed Caddyfile", False),
    Sample("hetzner/edge/validation/Caddyfile.enforcing", "released: enforcing Caddyfile", False),
    Sample("hetzner/estate.ts", "released: a Pulumi program", False),
    Sample("hetzner-host/firewalls.ts", "released: the firewall", False),
    Sample("hetzner/Pulumi.production.yaml", "released: a stack file", False),
    Sample("hetzner/package.json", "released: a package manifest", False),
    Sample("hetzner/pnpm-workspace.yaml", "released: install-time allowBuilds", False),
    Sample("ovh/copy2/stack.ts", "released: object storage", False),
    Sample("hetzner/dns/zone.json", "released: zone data", False),
    Sample("mail/provision/provision_mailboxes.py", "released: a program run on mx1", False),
    Sample("ansible/playbooks/mx1.yml", "released: the mx1 playbook", False),
    Sample("ansible/inventories/production/hosts.yml", "released: the host inventory", False),
    Sample("ansible/owner_vars/edge1.yml", "released: host values", False),
    Sample("ansible/roles/ci_jump/tasks/main.yml", "released: ssh key options", False),
    Sample("ansible/roles/ci_login/tasks/_sudoers.yml", "released: sudoers", False),
    Sample("ansible/roles/host_baseline/tasks/_ssh.yml", "released: sshd", False),
    Sample("ansible/roles/pull_trigger/tasks/main.yml", "released: a pull role", False),
    Sample("ansible/roles/backup_worker/defaults/main.yml", "released: a backup role", False),
    Sample("hetzner/provision/branchleft_deploy.py", "released: the deploy account command", False),
    Sample("hetzner/control-plane/stack/postgres/pg_hba.conf", "released: database access", False),
    Sample("ansible/roles/edge_stack/tasks/main.yml", "released: host configuration", False),
    Sample("ansible/playbooks/edge1.yml", "released: a host playbook", False),
    Sample("ansible/library/x.py", "released: a loader directory", False),
    Sample("ansible/roles/ci_jump/README.md", "released: an engineering document", False),
    Sample("ansible/checks/README.md", "released: a document in a gate directory", False),
    Sample("pnpm-lock.yaml", "released: a lockfile", False),
    Sample("hetzner/pnpm-lock.yaml", "released: a lockfile", False),
    Sample("ansible/requirements.txt", "released: a hash-locked pin", False),
    Sample("hetzner/estate.test.ts", "released: a Pulumi program test", False),
    Sample("ansible/checks/test_edge_single_home.py", "released: an agreement test", False),
    Sample("hetzner/dns/zonecheck.py", "released: a checker", False),
    Sample("hetzner/scripts/probe-object-storage.py", "released: a probe", False),
    Sample("hetzner/scripts/check-address-plan-drift.py", "released: a read-only checker", False),
)

# Samples that stand for a file the repository does not hold, so they are not looked up on disk.
PENDING: frozenset[str] = frozenset({"ansible/library/x.py", "hetzner/edge/publicpress/index.html"})


def mismatches(rules: list[Rule], samples: Sequence[Sample] = SAMPLES) -> list[Sample]:
    """Return the samples for which ``rules`` give a different answer than the table."""
    return [s for s in samples if (owners_of(s.path, rules) == [OWNER]) != s.owned]


def patterns(rules: list[Rule]) -> tuple[str, ...]:
    """Return the patterns of ``rules`` in file order."""
    return tuple(pattern for pattern, _ in rules)


def owner_changes(
    old: list[Rule], new: list[Rule], files: Sequence[str]
) -> tuple[list[str], list[str]]:
    """Return the files that lose their owner and the files that gain one going from old to new.

    A file whose owners change from one owner list to another is in neither: only a file that
    had an owner and has none, and a file that had none and has one, are reported.
    """
    lost = [f for f in files if owners_of(f, old) and not owners_of(f, new)]
    gained = [f for f in files if not owners_of(f, old) and owners_of(f, new)]
    return lost, gained


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
    mode.add_argument(
        "--against",
        type=Path,
        metavar="OLD",
        help="compare every tracked file's owner with the CODEOWNERS file OLD; exit 1 on a loss",
    )
    args = parser.parse_args(argv)
    rules = parse_rules(args.file.read_text(encoding="utf-8"))
    if args.against:
        old = parse_rules(args.against.read_text(encoding="utf-8"))
        files = tracked_files()
        lost, gained = owner_changes(old, rules, files)
        for path in lost:
            sys.stdout.write(f"LOST   {path}\n")
        for path in gained:
            sys.stdout.write(f"GAINED {path}\n")
        sys.stdout.write(f"files {len(files)} lost {len(lost)} gained {len(gained)}\n")
        return 1 if lost else 0
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
