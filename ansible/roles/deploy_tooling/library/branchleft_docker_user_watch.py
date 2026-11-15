#!/usr/bin/python3 -I
"""Watch the app host's firewall isolation policy and fail when it has been reopened.

Run by a timer on a host of class app. It lists the same firewall chains the role reads
back and applies the same checks (the checks are deploy_tooling_chain's, installed beside
this file, so there is one definition of "the policy is in place"). It writes nothing and
repairs nothing: a reopened chain is reported, and the policy unit's own restart is what
puts it right.

Exit status, which is the unit's result:
  0  the chains carry the policy.
  1  the policy has been reopened: a chain is absent, a rule is missing, out of order or
     one the host's variant must not carry, or a rule above the policy's last drop could
     let a packet past it.
  2  the check could not be made (the program, a listing or an argument is unusable). It
     is never read as "intact": an unchecked host is reported the same way a reopened one is.

Nothing printed holds the text of a rule the policy did not put there.
"""

import argparse
import importlib.util
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, TextIO

CHECKS_NAME = "deploy_tooling_chain"


def load_checks() -> ModuleType:
    """Return the checks module: the one already imported, else the file beside this one.

    Isolated mode puts no directory on the path, so the file is loaded by its own path and
    nothing else on the host can stand in for it.

    Raises:
        ImportError: when the file beside this one cannot be loaded.
    """
    loaded = sys.modules.get(CHECKS_NAME)
    if loaded is not None:
        return loaded
    path = Path(__file__).resolve().with_name(f"{CHECKS_NAME}.py")
    spec = importlib.util.spec_from_file_location(CHECKS_NAME, path)
    if spec is None or spec.loader is None:
        message = f"cannot load the checks at {path}"
        raise ImportError(message)
    module = importlib.util.module_from_spec(spec)
    sys.modules[CHECKS_NAME] = module
    spec.loader.exec_module(module)
    return module


if TYPE_CHECKING:
    import deploy_tooling_chain as chain
else:
    chain = load_checks()

EXIT_INTACT = 0
EXIT_REOPENED = 1
EXIT_UNCHECKED = 2

DEFAULT_RECONCILER = "/usr/local/sbin/branchleft-docker-user-policy"
TOOL_DIRECTORIES = ("/usr/sbin", "/sbin", "/usr/bin", "/bin")
LIST_TIMEOUT_SECONDS = 30

# The failures that mean the policy is not in force. Any other PolicyError means the check
# itself could not be made.
REOPENED = (
    chain.ChainAbsentError,
    chain.RuleMissingError,
    chain.RuleMisplacedError,
    chain.RuleForbiddenError,
    chain.RuleBypassError,
    chain.ForwardBypassError,
)


def find_tool(family: chain.Family) -> str | None:
    """Return the path of the firewall tool in the system directories, or None."""
    for directory in TOOL_DIRECTORIES:
        candidate = Path(directory) / family
        if candidate.is_file():
            return str(candidate)
    return None


def list_table(family: chain.Family) -> chain.Listing:
    """List one family's filter table with the real tool. A tool that cannot run is a failure."""
    tool = find_tool(family)
    if tool is None:
        return chain.Listing(127, "", f"{family} is not installed")
    try:
        done = subprocess.run(  # noqa: S603 - fixed argument list, no shell, a system path
            [tool, "-w", "-t", "filter", "-S"],
            capture_output=True,
            text=True,
            timeout=LIST_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return chain.Listing(124, "", f"{family} did not answer in {LIST_TIMEOUT_SECONDS}s")
    except OSError as error:
        return chain.Listing(126, "", error.strerror or "cannot run")
    return chain.Listing(done.returncode, done.stdout, done.stderr)


def watch(
    reconciler: Path,
    variant: str,
    allowlist: Sequence[str],
    runner: chain.Runner,
    out: TextIO,
    err: TextIO,
) -> int:
    """Check the chains once, say what was found, and return the exit status."""
    try:
        params = chain.params_from_mapping(
            {
                "reconciler_path": str(reconciler),
                "variant": variant,
                "foreign_chain_allowlist": list(allowlist),
            }
        )
        found = chain.check_all(params, runner)
    except REOPENED as error:
        print(f"branchleft-docker-user-watch: REOPENED: {error}", file=err)
        return EXIT_REOPENED
    except chain.PolicyError as error:
        print(f"branchleft-docker-user-watch: CANNOT CHECK: {error}", file=err)
        return EXIT_UNCHECKED
    print(
        f"branchleft-docker-user-watch: intact, {found.owned_rules} policy rules in place",
        file=out,
    )
    return EXIT_INTACT


def main(argv: Sequence[str] | None = None) -> int:
    """Parse the arguments, check once and return the exit status."""
    parser = argparse.ArgumentParser(description="Fail when the DOCKER-USER policy is reopened.")
    parser.add_argument("--variant", required=True, choices=["standard", "protected_no_db"])
    parser.add_argument("--reconciler", default=DEFAULT_RECONCILER)
    parser.add_argument("--allow", action="append", default=[], metavar="CHAIN")
    arguments = parser.parse_args(argv)
    try:
        return watch(
            Path(arguments.reconciler),
            arguments.variant,
            arguments.allow,
            list_table,
            sys.stdout,
            sys.stderr,
        )
    except Exception as error:  # noqa: BLE001 - an unexpected failure is "cannot check", never "reopened"
        print(
            f"branchleft-docker-user-watch: CANNOT CHECK: {type(error).__name__}", file=sys.stderr
        )
        return EXIT_UNCHECKED


if __name__ == "__main__":
    sys.exit(main())
