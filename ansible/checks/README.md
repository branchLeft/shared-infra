# ansible/checks

This folder holds the checks that prove the lock and the workflow. Their narrative lives here
because the CMT-3 gate requires comment blocks in the code to stay below 11 lines.

## test_lock_reader_parity.py: parity with pip

The install program (`ansible/roles/ansible_runtime/files/install_runtime.py`) refuses a lock that
pip would run with an option such as `--index-url`. To do that it has to read the lock as pip
reads it, and two review cycles each found a difference by hand. So this file is the oracle: for a
table of lock shapes it asks pip's own code how it reads each one (`_decode_req_file`, `preprocess`
and `break_args_options` in `pip/_internal/req/req_file.py`) and holds the program to it. The table
is a list of shapes, each saying what the program must do and what pip must see, and pip is asked
as well, so a wrong entry in the table fails too.

The pip it asks is pinned. The pin is `ansible/checks/pip-requirements.txt`, a hashed requirement
for one version (26.1.2), which both CI tool environments in `.github/workflows/ansible.yml` install
with `--require-hashes --only-binary=:all:` before the lock. The lock does not pin pip, so without
this file the oracle would run whatever ensurepip bundles with the runner's Python. Before it calls
any pip internal, this file reads the interpreter's `pip.__version__` and fails, naming both
versions, when it is not the pin. It never skips and never falls back to `auto_decode`.

The version the test compares is read from `pip-requirements.txt` on every run, by `check_pins.py`
(`read_pip_pin`), so the file the workflow installs is the only home of the version. The comparison
runs before the test imports or probes any pip internal, so a wrong pip is reported by its version
and not by a missing function. Tests in the same file patch the version they see and hold that
down, so no second pip is needed to prove it.

pip's `req_file` module is not a public interface. A pip upgrade is therefore two steps, done
together: change the pin in `pip-requirements.txt` to the new version with the hash of its wheel
(the `bdist_wheel` entry of PyPI's JSON API; the install is wheels-only, so the source archive's
hash is never used), and re-check the table above against the new pip's `req_file` (the parity).
Until both are done the test fails, which is the intended result.

Dependabot watches the pin: its `pip` entry for `/ansible/checks` opens the bump, and
`check_pins.py` fails if that entry goes or if the pin file is anything but one `pip==X.Y.Z` line
with one sha256. `test_ci_python_steps.py` requires both CI tool environments, and the install
recipe in `ansible/README.md`, to install the pin before the lock, with hashes required and wheels
only.
