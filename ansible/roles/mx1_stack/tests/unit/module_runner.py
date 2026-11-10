"""Run one of the role's modules the way Ansible does, and read what it printed.

A helper for the unit tests, not a test: discovery looks for ``test_*.py`` only.
"""

import contextlib
import io
import json
import os
from collections.abc import Callable, Iterator, Mapping


def run_module(
    main: Callable[[], None], params: Mapping[str, object], *, check_mode: bool = False
) -> tuple[bool, dict[str, object], str]:
    """Run ``main`` with the parameters; return (failed, the JSON it printed, the raw text).

    Raises:
        AssertionError: The module neither exited nor printed JSON.
    """
    from ansible.module_utils.testing import patch_module_args

    args = {**params, "_ansible_check_mode": check_mode}
    buffer = io.StringIO()
    with patch_module_args(args), contextlib.redirect_stdout(buffer):
        try:
            main()
        except SystemExit:
            pass
    raw = buffer.getvalue()
    if not raw.strip():
        message = "the module printed nothing"
        raise AssertionError(message)
    document = json.loads(raw)
    return bool(document.get("failed")), document, raw


def listing(directory: str) -> dict[str, bytes]:
    """Return every file under a directory, by relative path, with its bytes."""
    found: dict[str, bytes] = {}
    for root, _directories, names in os.walk(directory):
        for name in names:
            path = os.path.join(root, name)
            with open(path, "rb") as handle:
                found[os.path.relpath(path, directory)] = handle.read()
    return found


@contextlib.contextmanager
def environment(**changes: str) -> Iterator[None]:
    """Set environment variables for a block and put them back."""
    saved = {name: os.environ.get(name) for name in changes}
    os.environ.update(changes)
    try:
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
