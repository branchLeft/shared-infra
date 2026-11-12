#!/usr/bin/env python3
"""A minimal SMTP responder that records which address each message arrived from.

It accepts every message and writes one JSON line per message to stdout: the TCP peer
address (the fact the spike measures), the EHLO name, MAIL FROM and RCPT TO. It speaks no
STARTTLS and checks nothing. It is a measuring instrument, not a mail server.

Run it as `python3 sink.py --host 0.0.0.0 --port 2525`.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Any

ADDRESS_START = "<"
ADDRESS_END = ">"


def parse_path(argument: str) -> str:
    """Return the address inside `FROM:<a@b>` or `TO:<a@b>`, without parameters.

    An unparseable argument returns the text unchanged, so the log still shows what the
    client sent.
    """
    start = argument.find(ADDRESS_START)
    end = argument.find(ADDRESS_END, start + 1)
    if start == -1 or end == -1:
        return argument.strip()
    return argument[start + 1 : end]


class Session:
    """The state of one SMTP connection, advanced one command line at a time."""

    def __init__(self, peer: str) -> None:
        self.peer = peer
        self.ehlo = ""
        self.mail_from = ""
        self.rcpt_to: list[str] = []
        self.in_data = False

    def reset_transaction(self) -> None:
        self.mail_from = ""
        self.rcpt_to = []
        self.in_data = False

    def record(self) -> dict[str, Any]:
        return {
            "peer": self.peer,
            "ehlo": self.ehlo,
            "mail_from": self.mail_from,
            "rcpt_to": list(self.rcpt_to),
        }

    def handle(self, line: str) -> tuple[list[str], dict[str, Any] | None, bool]:
        """Return the reply lines, a finished-message record if any, and whether to close."""
        if self.in_data:
            if line == ".":
                finished = self.record()
                self.reset_transaction()
                return ["250 2.0.0 accepted"], finished, False
            return [], None, False
        verb, _, argument = line.partition(" ")
        verb = verb.upper()
        if verb in ("EHLO", "HELO"):
            self.ehlo = argument.strip()
            return ["250 spike-sink"], None, False
        if verb == "MAIL":
            self.reset_transaction()
            self.mail_from = parse_path(argument)
            return ["250 2.1.0 ok"], None, False
        if verb == "RCPT":
            self.rcpt_to.append(parse_path(argument))
            return ["250 2.1.5 ok"], None, False
        if verb == "DATA":
            self.in_data = True
            return ["354 end with ."], None, False
        if verb == "RSET":
            self.reset_transaction()
            return ["250 2.0.0 ok"], None, False
        if verb == "NOOP":
            return ["250 2.0.0 ok"], None, False
        if verb == "QUIT":
            return ["221 2.0.0 bye"], None, True
        return ["502 5.5.2 command not recognised"], None, False


async def serve_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peername = writer.get_extra_info("peername")
    session = Session(str(peername[0]))
    writer.write(b"220 spike-sink ready\r\n")
    await writer.drain()
    try:
        while True:
            raw = await reader.readline()
            if not raw:
                break
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            replies, finished, close = session.handle(line)
            if finished is not None:
                print(json.dumps(finished, sort_keys=True), flush=True)
            for reply in replies:
                writer.write(reply.encode("utf-8") + b"\r\n")
            await writer.drain()
            if close:
                break
    finally:
        writer.close()


async def run(host: str, port: int) -> None:
    server = await asyncio.start_server(serve_connection, host, port)
    print(json.dumps({"listening": [host, port]}), flush=True)
    async with server:
        await server.serve_forever()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Record the peer address of each SMTP message.")
    parser.add_argument("--host", default="0.0.0.0")  # noqa: S104 - the sink listens on the lab network
    parser.add_argument("--port", type=int, default=2525)
    args = parser.parse_args(argv)
    try:
        asyncio.run(run(args.host, args.port))
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
