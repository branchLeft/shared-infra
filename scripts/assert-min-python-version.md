# assert-min-python-version.py

The module docstring of `assert-min-python-version.py` kept its summary paragraph; the rest of the narrative, usage notes and rationale is below, unchanged.

`hetzner/provision`'s suite uses PEP 604 `X | None` annotations with no
`from __future__ import annotations` guard -- unlike every other Python suite
in this repo, which already carries that import and so tolerates old
interpreters even though the same syntax appears in their source. Under
Python 3.9 (this workstation's `/usr/bin/python3`), `unittest discover`
does not refuse to run: it imports every module matching `test_*.py`, catches
the `TypeError` the one broken module raises, replaces it with a single
synthetic failing test named after that module, and keeps collecting
everything else. The summary line then reads `FAILED (errors=1)` with a
smaller test count instead of naming the real cause -- indistinguishable, at
a glance, from any other lone pre-existing failure, and the tests inside that
module are gone from the count with nothing to compare it against.

This script makes that failure loud and specific instead: run it before
`unittest discover` and it names the actual interpreter, the actual
executable and the version floor, rather than leaving the diagnosis to
whatever `TypeError` the first unparseable line happens to raise.

Usage:

    assert-min-python-version.py 3.10                        # bare floor check
    assert-min-python-version.py 3.10 --suite hetzner/provision
    assert-min-python-version.py --self-test
