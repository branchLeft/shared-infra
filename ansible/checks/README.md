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

The pip it asks is the one in the interpreter that runs this file: in CI the ensurepip-bundled pip
of the virtual environment that holds the pinned toolchain (the lock does not pin pip). The version
is in every failure message. pip's `req_file` module is not a public interface; if a pip release
moves it, this file fails with a message that says so, and it is not skipped, because a skipped
oracle would read as a pass. Re-checking the parity against the new pip is the repair.
