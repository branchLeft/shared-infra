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

pip's `req_file` module is not a public interface. A pip upgrade is therefore two steps, done
together: change the pin in `pip-requirements.txt` to the new version with its hash from PyPI's JSON
API, and re-check the table above against the new pip's `req_file` (the parity). Until both are done
the test fails, which is the intended result. Dependabot does not watch the pin: `check_pins.py`
watches only `requirements.in`, and the pin is not an input it lists.
