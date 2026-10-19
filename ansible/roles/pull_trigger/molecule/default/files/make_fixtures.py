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
ENVIRONMENT = {
    **os.environ,
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "TEST_AUTHOR",
    "GIT_AUTHOR_EMAIL": "author@example.invalid",
    "GIT_COMMITTER_NAME": "TEST_AUTHOR",
    "GIT_COMMITTER_EMAIL": "author@example.invalid",
    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
    "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
}


def run(argv: list[str], cwd: Path | None = None, extra: dict[str, str] | None = None) -> str:
    """Run a command with the isolated environment and return its stripped output."""
    done = subprocess.run(  # noqa: S603 - argument lists, no shell, fixed programs
        argv,
        cwd=cwd,
        env={**ENVIRONMENT, **(extra or {})},
        capture_output=True,
        text=True,
        check=True,
    )
    return done.stdout.strip()


def playbook(marker: str, fail: bool = False) -> str:
    """Return a placeholder playbook that records a marker, or fails."""
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
    return f"- name: Placeholder play\n  hosts: all\n  gather_facts: false\n  tasks:\n{task}"


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


def main() -> int:
    """Build the fixtures and write ``fixtures.json``."""
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
    ids["broken"] = commit(
        work, {PLAYBOOK: playbook("BROKEN", fail=True)}, ids["symlink"], "broken", a
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


if __name__ == "__main__":
    sys.exit(main())
