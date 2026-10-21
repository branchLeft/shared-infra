# TEST PLACEHOLDER for the state-copy installer. The role runs it with --check when the timer is asked for.
# Like the real one it exits 2 when an input is missing; the test makes one "missing" with a flag file.
import os
import sys

if os.path.exists("/run/test-state-copy-not-ready"):
    print("install_state_copy: missing: TEST PLACEHOLDER input", file=sys.stderr)
    sys.exit(2)
print("install_state_copy: ready")
