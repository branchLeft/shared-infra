"""Make a Unix socket file at a path, then exit, for the grant role's test.

The role asks that the Docker socket exists and is a socket. The test container
has no Docker daemon, so this makes the file the role looks at. A bound socket
file stays on disk after the process that bound it exits.
"""

from __future__ import annotations

import socket
import sys


def main(path: str) -> None:
    """Bind a Unix stream socket at ``path`` and close it."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.bind(path)


if __name__ == "__main__":
    main(sys.argv[1])
