#!/usr/bin/python3
"""Make the throwaway remote, keys and signed history the Molecule verify play reads.

Test setup only. Every key is made for the run. The result is ``fixtures.json``.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path("/var/tmp/ptt")  # noqa: S108 - short on purpose: gpg's agent socket lives beneath it
PLAYBOOK = "ansible/playbooks/host.yml"
MARKER_FILE = ROOT / "applied-marker"
STEP_MARKER_PREFIX = f"{ROOT}/step-"
ENVIRONMENT = {
    **os.environ,
    "GIT_AUTHOR_NAME": "TEST_AUTHOR",
    "GIT_AUTHOR_EMAIL": "author@example.invalid",
    "GIT_COMMITTER_NAME": "TEST_AUTHOR",
    "GIT_COMMITTER_EMAIL": "author@example.invalid",
    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
    "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
}


def run(argv: list[str], cwd: Path | None = None, extra: dict[str, str] | None = None) -> str:
    """Run a command with the fixed commit identity and dates and return its stripped output."""
    done = subprocess.run(  # noqa: S603 - argument lists, no shell, fixed programs
        argv,
        cwd=cwd,
        env={**ENVIRONMENT, **(extra or {})},
        capture_output=True,
        text=True,
        check=True,
    )
    return done.stdout.strip()


def step_tasks() -> str:
    """Return one placeholder task per step, each behind the never tag and its own tag.

    A plain apply or check must never run them. A step request runs only the one whose tag it
    names, and the task writes the extra variable the program set, so the test sees both.
    """
    text = ""
    for step in ("migrate", "identity", "provision"):
        text += (
            f"    - name: Record that the {step} step ran\n"
            "      ansible.builtin.copy:\n"
            '        content: "{{ control_plane_db_step }} step ran\\n"\n'
            f"        dest: {STEP_MARKER_PREFIX}{step}\n"
            "        owner: root\n        group: root\n        mode: '0644'\n"
            f"      tags: [never, control_plane_db_{step}]\n"
        )
    return text


def playbook(marker: str, fail: bool = False) -> str:
    """Return a placeholder playbook that records a marker, or fails, and holds the steps."""
    task = (
        "    - name: Fail on purpose\n"
        "      ansible.builtin.fail:\n"
        "        msg: PLACEHOLDER_FAILURE\n"
        if fail
        else "    - name: Record the marker of the applied commit\n"
        "      ansible.builtin.copy:\n"
        f'        content: "{marker}\\n"\n'
        f"        dest: {MARKER_FILE}\n"
        "        owner: root\n        group: root\n        mode: '0644'\n"
    )
    header = "- name: Placeholder play\n  hosts: all\n  gather_facts: false\n  tasks:\n"
    return f"{header}{task}{step_tasks()}"


class Signer:
    """How one commit is signed: an SSH key file, an OpenPGP key, or not at all."""

    def __init__(
        self, ssh_key: Path | None = None, gpg_home: Path | None = None, gpg_id: str = ""
    ) -> None:
        """Remember the key to sign with."""
        self.ssh_key = ssh_key
        self.gpg_home = gpg_home
        self.gpg_id = gpg_id

    def arguments(self) -> tuple[list[str], dict[str, str]]:
        """Return the git settings and environment that sign with this key."""
        if self.ssh_key is not None:
            return ["-c", "gpg.format=ssh", "-c", f"user.signingkey={self.ssh_key}", "-S"], {}
        if self.gpg_home is not None:
            return (
                ["-c", "gpg.format=openpgp", "-c", f"user.signingkey={self.gpg_id}", "-S"],
                {"GNUPGHOME": str(self.gpg_home)},
            )
        return [], {}


def commit(
    work: Path, files: dict[str, str | None], parent: str | None, message: str, signer: Signer
) -> str:
    """Make a commit from the work tree after applying ``files`` (None removes, '->x' links)."""
    for name, content in files.items():
        path = work / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.unlink(missing_ok=True)
        if content is None:
            continue
        if content.startswith("->"):
            path.symlink_to(content[2:])
        else:
            path.write_text(content, encoding="utf-8")
    run(["git", "add", "-A"], cwd=work)
    tree = run(["git", "write-tree"], cwd=work)
    settings, extra = signer.arguments()
    argv = [
        "git",
        *settings[:-1],
        "commit-tree",
        *settings[-1:],
        *(["-p", parent] if parent else []),
    ]
    return run([*argv, "-m", message, tree], cwd=work, extra=extra)


def commit_playbooks_link(
    work: Path, target: str, files: dict[str, str | None], parent: str, signer: Signer
) -> str:
    """Commit with ansible/playbooks a link to ``target``, then put the directory back."""
    directory = work / "ansible" / "playbooks"
    shutil.rmtree(directory)
    directory.symlink_to(target)
    sha = commit(work, files, parent, "playbooks is a link", signer)
    directory.unlink()
    directory.mkdir()
    return sha


def make_ssh_key(name: str) -> Path:
    """Make an unencrypted SSH key pair and return the private key's path."""
    path = ROOT / "keys" / name
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(path)])
    return path


def make_gpg_key(name: str) -> tuple[Path, str, str]:
    """Make an OpenPGP key in its own short-path keyring; return the keyring, id and public key."""
    home = ROOT / f"gnupg-{name}"
    home.mkdir(mode=0o700)
    base = ["gpg", "--batch", "--homedir", str(home)]
    run(
        [
            *base,
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-gen-key",
            name,
            "ed25519",
            "sign",
            "never",
        ]
    )
    fingerprint = next(
        line.split(":")[9]
        for line in run([*base, "--list-keys", "--with-colons"]).split("\n")
        if line.startswith("fpr")
    )
    return home, fingerprint, run([*base, "--armor", "--export", fingerprint]) + "\n"


def main(push: bool = False) -> int:
    """Build the fixtures and write ``fixtures.json``.

    With ``push`` the history is the one a host that takes bundles is tested with, and the
    bundles of its commits are written beside it (see ``push_fixtures``).
    """
    if push:
        return push_fixtures()
    shutil.rmtree(ROOT, ignore_errors=True)
    (ROOT / "keys").mkdir(parents=True, mode=0o755)
    work, remote = ROOT / "work", ROOT / "remote.git"
    run(["git", "init", "-q", "-b", "main", str(work)])
    run(["git", "init", "-q", "--bare", "-b", "main", str(remote)])
    ssh_a, ssh_b = make_ssh_key("signer-a"), make_ssh_key("signer-b")
    pgp_g, pgp_h = make_gpg_key("signer-g"), make_gpg_key("signer-h")
    a, b = Signer(ssh_key=ssh_a), Signer(ssh_key=ssh_b)
    g, h = Signer(gpg_home=pgp_g[0], gpg_id=pgp_g[1]), Signer(gpg_home=pgp_h[0], gpg_id=pgp_h[1])
    nobody = Signer()
    markers = {name: f"MARKER_{name.upper()}" for name in ("old", "good", "pgp_good", "tip")}
    ids: dict[str, str] = {}
    ids["old"] = commit(work, {PLAYBOOK: playbook(markers["old"])}, None, "old", a)
    ids["good"] = commit(work, {PLAYBOOK: playbook(markers["good"])}, ids["old"], "good", a)
    ids["pgp_good"] = commit(
        work, {PLAYBOOK: playbook(markers["pgp_good"])}, ids["good"], "by g", g
    )
    ids["other_ssh"] = commit(work, {PLAYBOOK: playbook("OTHER_SSH")}, ids["pgp_good"], "by b", b)
    ids["other_pgp"] = commit(work, {PLAYBOOK: playbook("OTHER_PGP")}, ids["other_ssh"], "by h", h)
    ids["unsigned"] = commit(
        work, {PLAYBOOK: playbook("UNSIGNED")}, ids["other_pgp"], "unsigned", nobody
    )
    signed = commit(work, {PLAYBOOK: playbook("TAMPERED")}, ids["unsigned"], "to be tampered", a)
    text = run(["git", "cat-file", "commit", signed], cwd=work)
    forged = subprocess.run(  # noqa: S603 - fixed program, no shell
        ["git", "hash-object", "-t", "commit", "-w", "--stdin"],  # noqa: S607 - on PATH
        cwd=work,
        env=ENVIRONMENT,
        input=text.replace("\n\nto be tampered", "\n\ntampered after signing") + "\n",
        capture_output=True,
        text=True,
        check=True,
    )
    ids["tampered"] = forged.stdout.strip()
    ids["no_playbook"] = commit(work, {PLAYBOOK: None}, ids["tampered"], "no playbook", a)
    ids["symlink"] = commit(
        work, {PLAYBOOK: "->../../../etc/hostname"}, ids["no_playbook"], "link", a
    )
    outside = ROOT / "outside"
    outside.mkdir()
    (outside / "host.yml").write_text(playbook("OUTSIDE"), encoding="utf-8")
    ids["dir_link_inside"] = commit_playbooks_link(
        work, "../real", {"real/host.yml": playbook("INSIDE")}, ids["symlink"], a
    )
    ids["dir_link_outside"] = commit_playbooks_link(
        work, str(outside), {}, ids["dir_link_inside"], a
    )
    ids["broken"] = commit(
        work, {PLAYBOOK: playbook("BROKEN", fail=True)}, ids["dir_link_outside"], "broken", a
    )
    ids["tip"] = commit(work, {PLAYBOOK: playbook(markers["tip"])}, ids["broken"], "tip", a)
    ids["side"] = commit(work, {PLAYBOOK: playbook("SIDE")}, ids["good"], "side", a)
    for branch, sha in (("main", ids["tip"]), ("side", ids["side"])):
        run(["git", "push", "-q", "--force", str(remote), f"{sha}:refs/heads/{branch}"], cwd=work)
    for home, _, _ in (pgp_g, pgp_h):
        run(["gpgconf", "--homedir", str(home), "--kill", "all"])
    fixtures = {
        "remote_url": f"file://{remote}",
        "ssh_key": " ".join(ssh_a.with_suffix(".pub").read_text(encoding="utf-8").split()[:2]),
        "pgp_key": pgp_g[2],
        "commits": ids,
        "markers": markers,
    }
    (ROOT / "fixtures.json").write_text(json.dumps(fixtures, indent=2) + "\n", encoding="utf-8")
    return 0


BUNDLES = ROOT / "bundles"


def run_bytes(argv: list[str], cwd: Path, data: bytes) -> str:
    """Run a command that takes binary standard input and return its stripped output."""
    done = subprocess.run(  # noqa: S603 - argument lists, no shell, fixed programs
        argv, cwd=cwd, env=ENVIRONMENT, input=data, capture_output=True, check=True
    )
    return done.stdout.decode().strip()


def malformed_commit(work: Path, parent: str, signer: Signer) -> str:
    """Return a signed commit whose tree holds an object git's own object check refuses.

    The tree is made with ``hash-object --literally``, so its hash is right and a bundle that
    carries it passes ``git bundle verify``. One entry has a zero-padded mode.
    """
    empty = run(["git", "hash-object", "-t", "tree", "-w", "--stdin"], cwd=work)
    subtree = run(["git", "rev-parse", f"{parent}:ansible"], cwd=work)
    raw = b"40000 ansible\0" + bytes.fromhex(subtree) + b"040000 junk\0" + bytes.fromhex(empty)
    tree = run_bytes(
        ["git", "hash-object", "-t", "tree", "--literally", "-w", "--stdin"], work, raw
    )
    settings, extra = signer.arguments()
    argv = ["git", *settings[:-1], "commit-tree", *settings[-1:], "-p", parent, "-m", "malformed"]
    return run([*argv, tree], cwd=work, extra=extra)


def make_bundle(work: Path, sha: str, name: str) -> Path:
    """Write a bundle of the commit the way the pushing workflow does: of a detached HEAD."""
    run(["git", "update-ref", "--no-deref", "HEAD", sha], cwd=work)
    path = BUNDLES / f"{name}.bundle"
    run(["git", "bundle", "create", str(path), "HEAD"], cwd=work)
    return path


def push_fixtures() -> int:
    """Build the history a host that takes bundles is tested with, and a bundle of each commit.

    One OpenPGP key stands in for GitHub's own signing key, and it is the only key the host
    trusts. The history is a straight line c0, c1, c2 (the floor starts at c0), with branches
    off it: signed by keys the host does not trust, unsigned, altered after signing, a sibling
    that does not descend from c1, an unrelated history, a commit with no playbook, one whose
    playbook is a link, and one holding an object git's own check refuses. ``fork`` and
    ``main_next`` are two commits on c2, standing for a web-editor commit on a fork and the real
    next commit of main. The bundles that are not of a commit (a truncated one, text, one that
    needs a commit it does not carry) are written too.
    """
    shutil.rmtree(ROOT, ignore_errors=True)
    (ROOT / "keys").mkdir(parents=True, mode=0o755)
    BUNDLES.mkdir(mode=0o755)
    work = ROOT / "work"
    run(["git", "init", "-q", "-b", "main", str(work)])
    web = make_gpg_key("web-flow-stand-in")
    other_pgp = make_gpg_key("other")
    other_ssh = make_ssh_key("other-ssh")
    w = Signer(gpg_home=web[0], gpg_id=web[1])
    ids: dict[str, str] = {}

    def add(name: str, parent: str | None, signer: Signer = w) -> None:
        ids[name] = commit(work, {PLAYBOOK: playbook(name.upper())}, parent, name, signer)

    add("c0", None)
    add("c1", ids["c0"])
    add("c2", ids["c1"])
    add("unsigned", ids["c1"], Signer())
    add("by_ssh", ids["c1"], Signer(ssh_key=other_ssh))
    add("by_other_pgp", ids["c1"], Signer(gpg_home=other_pgp[0], gpg_id=other_pgp[1]))
    signed = commit(work, {PLAYBOOK: playbook("TAMPERED")}, ids["c1"], "to be tampered", w)
    text = run(["git", "cat-file", "commit", signed], cwd=work)
    ids["tampered"] = run_bytes(
        ["git", "hash-object", "-t", "commit", "-w", "--stdin"],
        work,
        (text.replace("\n\nto be tampered", "\n\ntampered after signing") + "\n").encode(),
    )
    add("side", ids["c0"])
    add("orphan", None)
    add("fork", ids["c2"])
    add("main_next", ids["c2"])
    ids["no_playbook"] = commit(work, {PLAYBOOK: None}, ids["c2"], "no playbook", w)
    ids["symlink"] = commit(work, {PLAYBOOK: "->../../../etc/hostname"}, ids["c2"], "link", w)
    ids["malformed"] = malformed_commit(work, ids["c2"], w)
    for name, sha in ids.items():
        make_bundle(work, sha, name)
    whole = (BUNDLES / "c1.bundle").read_bytes()
    (BUNDLES / "truncated.bundle").write_bytes(whole[: len(whole) * 2 // 3])
    (BUNDLES / "junk.bundle").write_text("this is not a bundle\n" * 50, encoding="utf-8")
    run(["git", "update-ref", "--no-deref", "HEAD", ids["c2"]], cwd=work)
    run(
        ["git", "bundle", "create", str(BUNDLES / "partial.bundle"), "HEAD", f"^{ids['c1']}"],
        cwd=work,
    )
    for home, _, _ in (web, other_pgp):
        run(["gpgconf", "--homedir", str(home), "--kill", "all"])
    fixtures = {
        "pgp_key": web[2],
        "commits": ids,
        "bundles": str(BUNDLES),
        "seed": ids["c0"],
    }
    (ROOT / "fixtures.json").write_text(json.dumps(fixtures, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(push="--push" in sys.argv[1:]))
