#!/usr/bin/env python3
"""Test scaffolding, not part of the role: listening sockets for the flows the scenario opens.

Each argument is HOST:PORT. The program listens on every one and closes each connection
it accepts at once, so a client that connects has proved the packet reached a listener.
It runs as a systemd unit (edge-firewall-listeners.service) written by prepare.yml.
"""

import selectors
import socket
import sys


def main() -> None:
    selector = selectors.DefaultSelector()
    for spec in sys.argv[1:]:
        host, port = spec.rsplit(":", 1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, int(port)))
        sock.listen(16)
        sock.setblocking(False)
        selector.register(sock, selectors.EVENT_READ)
    while True:
        for key, _ in selector.select():
            connection, _ = key.fileobj.accept()
            connection.close()


if __name__ == "__main__":
    main()
