#!/usr/bin/env python3
"""Prove that an escrowed passphrase still opens a Pulumi stack export archive.

The six post-wrap archives in offsite object storage are the only surviving
copies of those stacks' state once the GCP KMS key version is destroyed, and
every one of them is passphrase-wrapped. That moves the whole risk from the
key to the escrow: a passphrase that was mis-transcribed, truncated on paste,
or filed under the wrong entry looks identical in a password manager to one
that works, and the difference only shows up after the key is gone, when
there is nothing left to fall back to.

"It is in the password manager" and "it opens the archive" are different
claims. This script turns the second one into an exit code.

It does not re-implement Pulumi's decryption. It drives the real `pulumi`
binary against a throwaway local file backend in a temporary directory, and
lets Pulumi's own answer be the answer. Two stages, both of which must pass:

1. **Salt stage.** The archive's `secrets_providers.state.salt` is written
   into a scratch `Pulumi.<stack>.yaml` and `pulumi stack init` is run over
   it. A passphrase salt carries a known plaintext encrypted under the key it
   derives, so Pulumi validates the passphrase against the salt alone and
   fails with `incorrect passphrase`. This stage holds even for an archive
   with no encrypted values in it.
2. **Ciphertext stage.** `pulumi stack import` reads the archive into that
   stack. Deserialising a deployment decrypts every encrypted value it
   contains, so a wrong passphrase fails here with `failed to decrypt`. This
   is the stage that proves the archive's actual secrets open, not merely
   that the passphrase matches the salt.

`pulumi stack export --show-secrets` is deliberately *not* used. It is the
decryption proof the migration runbook uses against a live stack, but its
output is every secret the stack holds in plaintext, and an import already
forces the same decryption while emitting nothing.

Nothing decrypted is ever printed. Pulumi's own stderr is captured and
matched against known markers, never echoed: with the *correct* passphrase, a
corrupt archive makes Pulumi report a JSON parse error over the decrypted
plaintext, quoting a character of it. Classifying the stream instead of
relaying it is what keeps that out of a terminal scrollback.

Nothing touches a real backend or a real stack. `pulumi login` is never run --
it rewrites `~/.pulumi/credentials.json` for every project on the machine --
and the backend is passed per invocation through `PULUMI_BACKEND_URL`, pinned
to a `file://` path inside a temporary directory that is removed on every
exit path. `PULUMI_HOME` and `PULUMI_ACCESS_TOKEN` are redirected and dropped
so no invocation can reach the Pulumi service.

Usage:

    verify-archive-passphrase.py ARCHIVE [ARCHIVE ...]
                                 [--passphrase-file PATH] [--json]

The passphrase is never an argument: it is prompted for without echo, or read
from a file. Several archives may be given at once because the passphrases
are one per repository rather than one per stack -- `shared-infra` covers two
archives and `ghost-platform` covers two -- and re-typing one passphrase per
archive is itself a transcription risk.

Exit codes, deliberately distinct so that "the passphrase does not work" can
never be confused with "the check did not run":

    0  PASS          every archive opened with the supplied passphrase
    1  FAIL          Pulumi reported an incorrect passphrase for an archive.
                     This blocks the KMS key destruction.
    2  USAGE         the invocation or the environment is wrong -- no
                     passphrase, an empty one, a missing `pulumi` binary.
                     Nothing was verified.
    3  ARCHIVE       an archive is unusable as evidence: unreadable, not a
                     stack export, not passphrase-wrapped, or carrying
                     plaintext secrets. Says nothing about the passphrase.
    4  INCONCLUSIVE  the check could not reach a verdict -- an archive with
                     no encrypted values in it, or a Pulumi failure that is
                     neither a passphrase nor an archive problem.

With several archives the worst outcome wins, in the order
FAIL > ARCHIVE > INCONCLUSIVE > PASS. A usage error aborts before any
archive is read.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_USAGE = 2
EXIT_ARCHIVE = 3
EXIT_INCONCLUSIVE = 4

# Worst-first. `verdict_exit_code` folds a run's outcomes through this, so a
# single FAIL among six passes still blocks the wind-down.
SEVERITY = [EXIT_FAIL, EXIT_ARCHIVE, EXIT_INCONCLUSIVE, EXIT_PASS]

OUTCOME_LABEL = {
    EXIT_PASS: "PASS",
    EXIT_FAIL: "FAIL",
    EXIT_ARCHIVE: "ARCHIVE",
    EXIT_INCONCLUSIVE: "INCONCLUSIVE",
}

# Pulumi's wording for the failures this script is built to tell apart, most
# specific first. All three are matched against a captured stream that is
# never printed, so a change in Pulumi's phrasing degrades to INCONCLUSIVE --
# loud and unverified -- rather than to a false PASS.
#
# `cipher: message authentication failed` is its own case rather than a
# variant of "incorrect passphrase": it is what a ciphertext that does not
# authenticate under the derived key produces, which happens either because
# the passphrase is wrong or because the archive has been corrupted. Both
# readings mean the archive does not open, so it fails closed -- but the
# reported detail names both rather than asserting the passphrase is at fault.
FAILURE_MARKERS = (
    ("passphrase", re.compile(r"incorrect passphrase|failed to decrypt", re.IGNORECASE)),
    ("authentication", re.compile(r"message authentication failed", re.IGNORECASE)),
    ("deployment", re.compile(r"could not deserialize deployment", re.IGNORECASE)),
)

# `urn:pulumi:<stack>::<project>::<type>::<name>`. Only the first two fields
# are wanted: naming the scratch project and stack after the archive's own
# keeps `stack import` from reporting a URN mismatch that would have to be
# distinguished from a real failure.
URN_PREFIX = "urn:pulumi:"

# Pulumi's own constraint on a project or stack name. A name from an archive
# that does not satisfy it falls back to a fixed one; `--force` on the import
# means the resulting URN mismatch is not an error.
PULUMI_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$")

FALLBACK_PROJECT = "archive-verify"
FALLBACK_STACK = "verify"


class ArchiveError(Exception):
    """The archive cannot serve as evidence, whatever the passphrase is."""


class PreflightError(Exception):
    """A precondition of running the check at all is not met."""


def plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def count_key(obj: object, name: str) -> int:
    """How many times `name` appears as a key anywhere in `obj`.

    Same shape as the structural check recorded against the archive set, so
    the two agree on what they are counting. It counts keys, never values --
    a value is exactly what must not be read here.
    """
    if isinstance(obj, dict):
        return sum(k == name for k in obj) + sum(count_key(v, name) for v in obj.values())
    if isinstance(obj, list):
        return sum(count_key(v, name) for v in obj)
    return 0


def names_from_urn(urn: object) -> tuple[str, str]:
    """`(project, stack)` from a resource URN, or the fallbacks."""
    if not isinstance(urn, str) or not urn.startswith(URN_PREFIX):
        return FALLBACK_PROJECT, FALLBACK_STACK
    parts = urn.split("::")
    if len(parts) < 2:
        return FALLBACK_PROJECT, FALLBACK_STACK
    stack = parts[0][len(URN_PREFIX):]
    project = parts[1]
    if not PULUMI_NAME.match(stack) or not PULUMI_NAME.match(project):
        return FALLBACK_PROJECT, FALLBACK_STACK
    return project, stack


def inspect_archive(path: str | os.PathLike[str]) -> dict:
    """Read an archive's structure, without decrypting anything.

    Raises `ArchiveError` for every shape that cannot be evidence for the
    wind-down precondition, so those never reach the Pulumi stages and never
    get reported as a passphrase verdict.
    """
    p = pathlib.Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise ArchiveError(f"cannot read: {exc.strerror or exc}") from exc

    try:
        archive = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ArchiveError(f"not valid JSON: {exc}") from exc

    if not isinstance(archive, dict) or not isinstance(archive.get("deployment"), dict):
        raise ArchiveError("not a `pulumi stack export` document (no `deployment` object)")

    deployment = archive["deployment"]
    providers = deployment.get("secrets_providers")
    if not isinstance(providers, dict):
        raise ArchiveError("deployment has no `secrets_providers` block")

    kind = providers.get("type")
    if kind != "passphrase":
        # The four pre-wrap archives sitting in the same bucket and prefix are
        # this shape. They are KMS-wrapped and stop being readable at the
        # moment the key version is destroyed, so no passphrase opens them and
        # a passphrase verdict over one would be meaningless.
        raise ArchiveError(
            f"secrets provider is `{kind}`, not `passphrase` -- "
            "this is not a post-wrap archive and no passphrase opens it"
        )

    salt = (providers.get("state") or {}).get("salt")
    if not isinstance(salt, str) or not salt:
        raise ArchiveError("passphrase provider carries no salt")

    plaintext = count_key(deployment, "plaintext")
    if plaintext:
        # An export taken with --show-secrets. It is not wrapped at all, so it
        # proves nothing about an escrowed passphrase and should not be sitting
        # in a bucket.
        raise ArchiveError(
            f"contains {plaintext} `plaintext` key(s) -- this export is unwrapped, "
            "not passphrase-wrapped"
        )

    resources = deployment.get("resources")
    return {
        "salt": salt,
        "resources": len(resources) if isinstance(resources, list) else 0,
        "ciphertext": count_key(deployment, "ciphertext"),
        "names": names_from_urn(
            resources[0].get("urn") if isinstance(resources, list) and resources
            and isinstance(resources[0], dict) else None
        ),
    }


def run_pulumi(
    args: list[str], *, cwd: str, env: dict[str, str], capture_stdout: bool = False
) -> tuple[int, str, str]:
    """Run `pulumi`, returning `(returncode, stdout, stderr)`.

    stdout goes to `/dev/null` unless a caller explicitly asks for it. Only
    `whoami` does, and its output is a username and a backend URL. Everything
    that handles a deployment runs with stdout discarded, so no future edit to
    a subcommand's flags can start a decrypted value on its way to a terminal.

    stderr is always captured and is returned for *classification* only --
    every caller matches it against known markers and none of them prints it.
    With the correct passphrase, a corrupt archive makes Pulumi quote a
    character of the decrypted plaintext in its error.

    Seam for the unit tests, which stub this rather than invoking a real
    binary.
    """
    proc = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE if capture_stdout else subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return proc.returncode, (proc.stdout or "") if capture_stdout else "", proc.stderr or ""


def child_env(*, home: str, backend_url: str, passphrase_file: str) -> dict[str, str]:
    """The environment every Pulumi invocation gets.

    `PULUMI_CONFIG_PASSPHRASE` outranks `PULUMI_CONFIG_PASSPHRASE_FILE`, so an
    operator who happens to have the plain variable exported would have the
    whole verification silently run against that value instead of the escrowed
    one -- and pass. It is removed and its absence asserted rather than
    assumed.
    """
    if not backend_url.startswith("file://"):
        raise PreflightError(f"refusing a non-file backend: {backend_url}")

    env = dict(os.environ)
    env.pop("PULUMI_CONFIG_PASSPHRASE", None)
    env.pop("PULUMI_ACCESS_TOKEN", None)
    env["PULUMI_HOME"] = home
    env["PULUMI_BACKEND_URL"] = backend_url
    env["PULUMI_CONFIG_PASSPHRASE_FILE"] = passphrase_file
    # No update check, no telemetry prompt: this must run offline and must not
    # emit a network call from a procedure whose point is that it touches
    # nothing live.
    env["PULUMI_SKIP_UPDATE_CHECK"] = "true"
    env["PULUMI_SKIP_CONFIRMATIONS"] = "true"

    if "PULUMI_CONFIG_PASSPHRASE" in env:
        raise PreflightError("PULUMI_CONFIG_PASSPHRASE survived removal from the child environment")
    return env


def classify_failure(stderr: str) -> str:
    """Name the kind of Pulumi failure a captured stderr describes.

    Returns `passphrase`, `authentication`, `deployment` or `unknown`. The
    caller decides what each means for the stage it is in, because the same
    marker carries a different verdict at `stack init` (where only the salt is
    in play) than at `stack import` (where the archive's own ciphertext is).
    """
    for kind, marker in FAILURE_MARKERS:
        if marker.search(stderr):
            return kind
    return "unknown"


def assert_scratch_backend(*, cwd: str, env: dict[str, str], backend_url: str, pulumi: str) -> None:
    """Prove, from Pulumi rather than from this file, which backend it resolved.

    `child_env` sets the backend, but an ambient `~/.pulumi/credentials.json`
    login or a `backend.url` pinned in a project file are both ways for the
    effective backend to differ from the one intended, and the failure mode is
    a command addressing live state. `whoami --verbose` reports what Pulumi
    actually resolved, and this refuses to continue unless it is the scratch
    directory created moments ago.
    """
    rc, stdout, _stderr = run_pulumi(
        [pulumi, "whoami", "--verbose"], cwd=cwd, env=env, capture_stdout=True
    )
    if rc != 0:
        raise PreflightError("`pulumi whoami` failed against the scratch backend")
    resolved = ""
    for line in stdout.splitlines():
        if line.startswith("Backend URL:"):
            resolved = line.split(":", 1)[1].strip()
            break
    if resolved != backend_url:
        raise PreflightError(
            f"pulumi resolved a backend that is not the scratch one: {resolved or 'none reported'}"
        )


def verify_archive(archive: str, info: dict, passphrase_file: str, *, pulumi: str) -> tuple[int, str]:
    """`(outcome, detail)` for one archive. Never returns a decrypted value."""
    if not info["ciphertext"]:
        return (
            EXIT_INCONCLUSIVE,
            "archive holds no encrypted values, so opening it proves nothing about the passphrase",
        )

    # Absolute before anything runs. Every Pulumi invocation below runs with
    # its cwd inside the scratch project, so a relative archive path or a
    # relative passphrase file resolves against the wrong directory -- which
    # fails safe as INCONCLUSIVE rather than as a pass, but fails.
    archive = os.path.abspath(archive)
    passphrase_file = os.path.abspath(passphrase_file)

    project, stack = info["names"]
    workdir = tempfile.mkdtemp(prefix="pulumi-archive-verify-")
    try:
        proj_dir = os.path.join(workdir, "project")
        state_dir = os.path.join(workdir, "state")
        home_dir = os.path.join(workdir, "home")
        for d in (proj_dir, state_dir, home_dir):
            os.makedirs(d, mode=0o700)

        with open(os.path.join(proj_dir, "Pulumi.yaml"), "w", encoding="utf-8") as fh:
            # `runtime: nodejs` never runs: nothing here previews or applies,
            # so no language plugin is fetched and the check works offline.
            fh.write(f"name: {project}\nruntime: nodejs\ndescription: throwaway archive verification\n")

        # The archive's own salt, so `stack init` validates the passphrase
        # against it. A scratch stack left to mint its own salt would accept
        # any passphrase at this stage.
        with open(os.path.join(proj_dir, f"Pulumi.{stack}.yaml"), "w", encoding="utf-8") as fh:
            fh.write(f"encryptionsalt: {info['salt']}\n")

        backend_url = "file://" + state_dir
        env = child_env(home=home_dir, backend_url=backend_url, passphrase_file=passphrase_file)
        assert_scratch_backend(cwd=proj_dir, env=env, backend_url=backend_url, pulumi=pulumi)

        rc, _stdout, stderr = run_pulumi([pulumi, "stack", "init", stack], cwd=proj_dir, env=env)
        if rc != 0:
            kind = classify_failure(stderr)
            if kind in ("passphrase", "authentication"):
                return EXIT_FAIL, "passphrase does not match the archive's salt"
            return EXIT_INCONCLUSIVE, "`pulumi stack init` failed for a reason that is not the passphrase"

        rc, _stdout, stderr = run_pulumi(
            [
                pulumi, "stack", "import",
                "--stack", stack,
                "--file", archive,
                # The URN identity check is meaningless in a throwaway backend,
                # and letting it fire would produce a non-zero exit that has to
                # be told apart from a decryption failure. Decryption happens
                # while the deployment is deserialised, which is before any URN
                # is compared, so forcing past that check cannot mask it.
                "--force",
            ],
            cwd=proj_dir,
            env=env,
        )
        if rc != 0:
            kind = classify_failure(stderr)
            verdicts = {
                "passphrase": (
                    EXIT_FAIL,
                    "passphrase does not decrypt this archive's encrypted values",
                ),
                "authentication": (
                    EXIT_FAIL,
                    "encrypted values do not authenticate under this passphrase -- "
                    "a wrong passphrase or a corrupted archive; either way it does not open",
                ),
                "deployment": (
                    EXIT_ARCHIVE,
                    "archive could not be deserialised even though the passphrase matched the salt",
                ),
            }
            return verdicts.get(
                kind,
                (
                    EXIT_INCONCLUSIVE,
                    "`pulumi stack import` failed for a reason that is neither passphrase nor archive",
                ),
            )

        return (
            EXIT_PASS,
            f"passphrase opens this archive ({plural(info['resources'], 'resource')}, "
            f"{plural(info['ciphertext'], 'encrypted value')})",
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def check_passphrase_file(path: str) -> None:
    """Reject an empty passphrase before anything is invoked.

    An empty passphrase is a usage error, not a verdict. Reporting it as FAIL
    would tell the operator their escrowed passphrase is wrong when what
    actually happened is that nothing was supplied -- the same shape as the
    zsh `read -rs -p` trap, where the prompt never appears and the variable is
    left empty. The file itself is not modified; Pulumi reads it directly.
    """
    try:
        content = pathlib.Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise PreflightError(f"cannot read the passphrase file: {exc.strerror or exc}") from exc
    except UnicodeDecodeError as exc:
        raise PreflightError(f"the passphrase file is not UTF-8 text: {exc}") from exc
    # Whitespace-only, not just zero-length: Pulumi strips a trailing newline
    # from this file, so a file written with `echo` and nothing else -- which
    # is what the zsh trap leaves behind -- is an *empty* passphrase to Pulumi.
    # It reports that as an incorrect passphrase, which would arrive here as
    # "your escrowed passphrase does not work" when nothing was supplied at
    # all.
    if not content.strip():
        raise PreflightError("the passphrase file is empty -- nothing was supplied")


def prompt_passphrase(workdir: str) -> str:
    """Prompt without echo and write the passphrase to a 0600 file.

    A file rather than an environment value, matching the migration runbook,
    and never an argument -- an argument is visible in the process table and
    in shell history.

    Entered once, not twice. A confirmation loop is right when a passphrase is
    being *created* and a typo becomes permanent; here a typo must be allowed
    to fail the check, which is the whole point.
    """
    passphrase = getpass.getpass("Escrowed passphrase (input hidden): ")
    if not passphrase.strip():
        raise PreflightError("no passphrase entered")
    path = os.path.join(workdir, "passphrase")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(passphrase)
    return path


def verdict_exit_code(outcomes: list[int]) -> int:
    for code in SEVERITY:
        if code in outcomes:
            return code
    return EXIT_PASS


def render(results: list[dict]) -> str:
    width = max(len(r["archive"]) for r in results)
    label_width = max(len(OUTCOME_LABEL[r["outcome"]]) for r in results)
    lines = [
        f"{r['archive']:<{width}}  {OUTCOME_LABEL[r['outcome']]:<{label_width}}  {r['detail']}"
        for r in results
    ]
    lines.append("")
    failed = [r for r in results if r["outcome"] == EXIT_FAIL]
    unverified = [r for r in results if r["outcome"] in (EXIT_ARCHIVE, EXIT_INCONCLUSIVE)]
    if failed:
        lines.append(
            f"{plural(len(failed), 'archive')} did not open with this passphrase -- "
            "the GCP KMS key version must not be destroyed"
        )
    elif unverified:
        lines.append(f"{plural(len(unverified), 'archive')} unverified -- no evidence either way")
    else:
        lines.append(f"all {plural(len(results), 'archive')} open with this passphrase")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    # `allow_abbrev=False` on purpose: with it on, `--passphrase VALUE` is
    # accepted as an abbreviation of `--passphrase-file`, so a passphrase typed
    # onto the command line -- into the process table and the shell history --
    # is silently treated as a path. Off, it is a usage error.
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0], allow_abbrev=False)
    parser.add_argument("archive", nargs="+", help="path to a `pulumi stack export` archive")
    parser.add_argument(
        "--passphrase-file",
        help="file holding the passphrase; without it, the passphrase is prompted for without echo",
    )
    parser.add_argument(
        "--pulumi",
        default="pulumi",
        help="the pulumi binary to drive (default: the one on PATH)",
    )
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)

    if shutil.which(args.pulumi) is None and not os.path.isfile(args.pulumi):
        print(f"error: no `{args.pulumi}` binary found; nothing was verified", file=sys.stderr)
        return EXIT_USAGE

    workdir = tempfile.mkdtemp(prefix="pulumi-archive-passphrase-")
    try:
        try:
            if args.passphrase_file:
                check_passphrase_file(args.passphrase_file)
                passphrase_file = args.passphrase_file
            else:
                passphrase_file = prompt_passphrase(workdir)
        except PreflightError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_USAGE

        results = []
        for archive in args.archive:
            name = os.path.basename(archive)
            try:
                info = inspect_archive(archive)
            except ArchiveError as exc:
                results.append({"archive": name, "outcome": EXIT_ARCHIVE, "detail": str(exc)})
                continue
            try:
                outcome, detail = verify_archive(archive, info, passphrase_file, pulumi=args.pulumi)
            except PreflightError as exc:
                outcome, detail = EXIT_INCONCLUSIVE, str(exc)
            results.append({"archive": name, "outcome": outcome, "detail": detail})

        if args.as_json:
            print(
                json.dumps(
                    [
                        {
                            "archive": r["archive"],
                            "outcome": OUTCOME_LABEL[r["outcome"]],
                            "exit_code": r["outcome"],
                            "detail": r["detail"],
                        }
                        for r in results
                    ],
                    indent=2,
                )
            )
        else:
            print(render(results))

        return verdict_exit_code([r["outcome"] for r in results])
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
