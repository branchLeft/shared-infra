#!/usr/bin/env python3
"""Make a Unix socket file at the path given, for the db1_grants test only.

The role looks at the database socket (is it a socket, who owns it) before it sends
the admin password to it. No Ansible module makes a socket, so the test makes one
here: bind creates the file, and the socket object is closed without listening, as
nothing in the test connects to it (the fake client does not).
"""

import os
import socket
import sys

path = sys.argv[1]
owner = int(sys.argv[2])
if os.path.exists(path):
    os.unlink(path)
probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
probe.bind(path)
probe.close()
os.chown(path, owner, owner)
os.chmod(path, 0o777)
