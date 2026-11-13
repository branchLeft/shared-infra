#!/usr/bin/python3 -I
"""TEST STAND-IN, not docker. The test has no container engine (ANS-15 forbids
reaching one), so prepare.yml installs this as `docker` in the instance. It
records each call and answers the few the role and the compose module make,
in the shapes the module's source parses. It runs no containers.
Three files in the state directory switch its behaviour: config_fails makes
the compose file validator refuse, up_fails makes a real `up` fail, and
compose_version sets the version `compose version` reports.
"""

import sys
from pathlib import Path

STATE = Path("/var/lib/compose_stack_standin")


def main(argv: list[str]) -> int:
    padded = f" {' '.join(argv)} "
    log = "dryrun.log" if " --dry-run " in padded else "argv.log"
    with (STATE / log).open("a", encoding="utf-8") as handle:
        handle.write(" ".join(argv) + "\n")

    if " compose version " in padded:
        version_file = STATE / "compose_version"
        version = "v2.40.3"
        if version_file.exists():
            version = version_file.read_text(encoding="utf-8").rstrip("\n")
        print(f'{{"version":"{version}"}}')
    elif " version " in padded:
        print('{"Client":{"Version":"28.0.0"}}')
    elif " config " in padded:
        if (STATE / "config_fails").exists():
            sys.stderr.write("invalid compose file\n")
            return 1
    elif " up " in padded:
        if log == "argv.log" and (STATE / "up_fails").exists():
            sys.stderr.write("stand-in: the image could not be pulled\n")
            return 1
        sys.stderr.write('{"id":"Container stand-in-app-1","status":"Working","text":"Recreate"}\n')
        sys.stderr.write('{"id":"Container stand-in-app-1","status":"Done","text":"Recreated"}\n')
    elif " ps " in padded:
        try:
            sys.stdout.write((STATE / "ps.json").read_text(encoding="utf-8"))
        except OSError as error:
            sys.stderr.write(f"cat: {error.filename}: No such file or directory\n")
            return 1
    elif " images " in padded:
        print("[]")
    else:
        sys.stderr.write("stand-in: call not expected\n")
        return 64
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
