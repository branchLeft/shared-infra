#!/usr/bin/env python3
"""Prove that each Hetzner project's token reaches its own project and no other.

Usage (tokens are read from the environment and never printed):

    read -rs HCLOUD_PROBE_TOKEN_MAIL; export HCLOUD_PROBE_TOKEN_MAIL
    ... one per project: MAIL, ORG, TENANTS, DEMOS, DNS, BACKUP, DEMO_DNS
    probe-project-isolation.py                           # the 7x7 proof
    probe-project-isolation.py --control-swap tenants=demos

**Why a denial alone proves nothing.** The Cloud API is implicitly scoped to
the token's project, so "token A cannot see project B" and "token A is broken,
expired, or pointed at an empty project" produce the same empty answer. Every
negative cell here is therefore paired with a positive one taken by the same
instrument:

* **Listing.** Each token must list its own project's marker firewall (the
  positive), and must not list any other project's marker or known server.
* **Real hosts.** The mail token must also list and fetch by id `mx1`, and
  the org token `edge1`, so the positive is tied to the production project
  and not only to a firewall someone created by hand.
* **By id.** Each marker is fetched by id with its own token, which must
  return 200 and the marker's name. Every other token fetching that same id
  must return 404 `not_found`. The 200 is what makes the 404 mean "a different
  project", rather than "this path never works".

**The control case.** `--control-swap tenants=demos` evaluates the tenants
row with the demos token. A working probe must report FAIL for it, and
specifically must mark the tenants row REACHES ACROSS in the demos column: the
demos marker is listed and fetched by that token. A FAIL for any other reason
-- the tenants marker missing, say -- does not count, because a probe whose
cross-reach check is broken would still produce that one. The control exits
0 only when it saw the reach.

Exit codes: 0 PASS (or a control that failed as required), 1 FAIL (or a control
that passed), 2 the probe could not run -- a transport error, a refused token,
or a malformed response. 2 is never read as isolation.

Only GET requests are issued, so a "Read" token is enough. The project table
below is a copy of `hetzner/projects.ts`; `test_probe_project_isolation.py`
fails if the two differ.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

API = "https://api.hetzner.cloud/v1"
MARKER_PREFIX = "project-marker-"
PER_PAGE = 50
# A generous bound on pagination: an estate this size is a page or two. A
# response that never stops offering a next page is a malformed instrument.
MAX_PAGES = 100

PROJECTS: dict[str, tuple[str, ...]] = {
    "mail": ("mx1",),
    "org": ("edge1", "nextcloud1", "ops1", "app1", "db1"),
    "tenants": ("edge-t", "app-t1", "db-t1"),
    "demos": ("demo1",),
    "dns": (),
    "backup": (),
    "demo-dns": (),
}


# Servers that exist today and must be seen, by name and by id, from their
# own project's token. A hand-made marker alone could be created in the wrong
# project by the same mistake that mints a token there; a production host
# cannot.
REQUIRED_SERVERS: dict[str, tuple[str, ...]] = {"mail": ("mx1",), "org": ("edge1",)}


def marker(project: str) -> str:
    return f"{MARKER_PREFIX}{project}"


def token_env(project: str) -> str:
    # A shell variable name can't carry a hyphen, and `demo-dns` does --
    # replaced with `_` here and nowhere else, so the project's own name
    # (the dict key, the marker suffix, the CLI's --control-swap value) never
    # changes.
    return f"HCLOUD_PROBE_TOKEN_{project.upper().replace('-', '_')}"


class ProbeError(Exception):
    """The probe could not observe something. Never evidence of isolation."""


@dataclass
class Response:
    status: int
    body: dict


class Api:
    """GETs against the Cloud API. `opener` is swappable for tests."""

    def __init__(self, base: str = API, opener=urllib.request.urlopen, timeout: float = 20.0):
        self.base = base.rstrip("/")
        self.opener = opener
        self.timeout = timeout

    def get(self, token: str, path: str, query: dict | None = None) -> Response:
        url = f"{self.base}{path}"
        if query:
            url = f"{url}?{urllib.parse.urlencode(query)}"
        request = urllib.request.Request(
            url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"}
        )
        try:
            with self.opener(request, timeout=self.timeout) as reply:
                return Response(reply.status, _json(reply.read(), path))
        except urllib.error.HTTPError as error:
            with error:
                return Response(error.code, _json(error.read(), path))
        except (urllib.error.URLError, OSError) as error:
            raise ProbeError(f"GET {path}: transport error ({error.__class__.__name__})") from None

    def list_names(self, token: str, collection: str) -> dict[str, int]:
        """`{name: id}` for every item in `collection`, across all pages."""
        found: dict[str, int] = {}
        page = 1
        for _ in range(MAX_PAGES):
            reply = self.get(token, f"/{collection}", {"page": page, "per_page": PER_PAGE})
            if reply.status != 200:
                raise ProbeError(f"GET /{collection}: HTTP {reply.status} {_code(reply.body)}")
            items = reply.body.get(collection)
            if not isinstance(items, list):
                raise ProbeError(f"GET /{collection}: response has no '{collection}' list")
            for item in items:
                found[str(item["name"])] = int(item["id"])
            next_page = reply.body.get("meta", {}).get("pagination", {}).get("next_page")
            if next_page is None:
                return found
            page = int(next_page)
        raise ProbeError(f"GET /{collection}: more than {MAX_PAGES} pages")


def _json(raw: bytes, path: str) -> dict:
    try:
        body = json.loads(raw or b"{}")
    except ValueError:
        raise ProbeError(f"GET {path}: response is not JSON") from None
    if not isinstance(body, dict):
        raise ProbeError(f"GET {path}: response is not a JSON object")
    return body


def _code(body: dict) -> str:
    error = body.get("error")
    return str(error.get("code")) if isinstance(error, dict) else ""


@dataclass
class View:
    servers: dict[str, int]
    firewalls: dict[str, int]


@dataclass
class Cell:
    """What token `row` observed about project `column`."""

    row: str
    column: str
    listed: bool
    by_id_status: int | None
    ok: bool
    note: str = ""


@dataclass
class Result:
    cells: list[Cell] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.problems and all(cell.ok for cell in self.cells)


def observe(api: Api, tokens: dict[str, str]) -> dict[str, View]:
    return {
        project: View(api.list_names(token, "servers"), api.list_names(token, "firewalls"))
        for project, token in tokens.items()
    }


def missing_required_servers(api: Api, token: str, project: str, view: View) -> list[str]:
    """Required servers that the project's own token cannot list and fetch."""
    missing = []
    for server in REQUIRED_SERVERS.get(project, ()):
        server_id = view.servers.get(server)
        if server_id is None:
            missing.append(server)
            continue
        reply = api.get(token, f"/servers/{server_id}")
        fetched = reply.body.get("server")
        if reply.status != 200 or not isinstance(fetched, dict) or fetched.get("name") != server:
            missing.append(server)
    return missing


def evaluate(api: Api, tokens: dict[str, str], views: dict[str, View]) -> Result:
    """Every (token, project) pair: own project positive, every other refused."""
    result = Result()
    marker_ids: dict[str, int] = {}
    for project in PROJECTS:
        own = views[project]
        if marker(project) not in own.firewalls:
            result.problems.append(
                f"{project}: its token does not list {marker(project)} -- either the token "
                f"belongs to another project or the marker was never created"
            )
        else:
            marker_ids[project] = own.firewalls[marker(project)]

    for row in PROJECTS:
        view = views[row]
        for column in PROJECTS:
            listed = marker(column) in view.firewalls or any(
                server in view.servers for server in PROJECTS[column]
            )
            status = None
            fetched_name = None
            if column in marker_ids:
                reply = api.get(tokens[row], f"/firewalls/{marker_ids[column]}")
                status = reply.status
                if status not in (200, 404):
                    raise ProbeError(
                        f"GET marker of {column} with the {row} token: HTTP {status} "
                        f"{_code(reply.body)}"
                    )
                if status == 404 and _code(reply.body) != "not_found":
                    raise ProbeError(f"404 without error code not_found for {row}->{column}")
                firewall = reply.body.get("firewall")
                if isinstance(firewall, dict):
                    fetched_name = firewall.get("name")
            if row == column:
                ok = listed and status == 200 and fetched_name == marker(column)
                note = "own project, listed and fetched by id" if ok else "OWN PROJECT NOT SEEN"
                missing = missing_required_servers(api, tokens[row], row, view)
                if missing:
                    ok = False
                    note = f"OWN PROJECT NOT SEEN: {', '.join(missing)} not listed and fetched by id"
            elif status is None:
                ok = False
                note = f"no {column} marker id to test against"
            else:
                ok = not listed and status == 404
                note = "refused" if ok else "REACHES ACROSS"
            result.cells.append(Cell(row, column, listed, status, ok, note))
    return result


def render(result: Result, label: str) -> str:
    names = list(PROJECTS)
    width = max(len(name) for name in names) + 2
    lines = [f"{label}: rows are tokens, columns are projects", ""]
    lines.append("token".ljust(width) + "".join(name.ljust(width + 6) for name in names))
    index = {(cell.row, cell.column): cell for cell in result.cells}
    for row in names:
        line = row.ljust(width)
        for column in names:
            cell = index.get((row, column))
            if cell is None:
                text = "-"
            else:
                shown = "listed" if cell.listed else "absent"
                text = f"{'ok' if cell.ok else 'XX'} {shown}/{cell.by_id_status}"
            line += text.ljust(width + 6)
        lines.append(line)
    lines.append("")
    for cell in result.cells:
        if not cell.ok:
            lines.append(f"  {cell.row} token vs {cell.column} project: {cell.note}")
    lines.extend(f"  {problem}" for problem in result.problems)
    lines.append("PASS" if result.passed else "FAIL")
    return "\n".join(lines)


def detected_reach(result: Result, row: str, source: str) -> bool:
    """Whether the swapped row was caught reaching into the source's project.

    Any FAIL is not enough: a probe whose cross-reach check is broken still
    fails the swapped row on its missing own marker, and would pass as a
    control while being unable to see the one thing it exists to see.
    """
    return any(
        cell.row == row
        and cell.column == source
        and not cell.ok
        and (cell.listed or cell.by_id_status == 200)
        for cell in result.cells
    )


def read_tokens(environ: dict[str, str]) -> dict[str, str]:
    tokens: dict[str, str] = {}
    missing = []
    for project in PROJECTS:
        value = environ.get(token_env(project), "").strip()
        if not value:
            missing.append(token_env(project))
        tokens[project] = value
    if missing:
        raise ProbeError(f"unset or empty: {', '.join(missing)}")
    return tokens


def distinct(tokens: dict[str, str]) -> list[str]:
    """Projects sharing a token value, compared by digest so nothing is printed."""
    seen: dict[str, str] = {}
    clashes = []
    for project, token in tokens.items():
        digest = hashlib.sha256(token.encode()).hexdigest()
        if digest in seen:
            clashes.append(f"{seen[digest]} and {project} were given the same token")
        seen[digest] = project
    return clashes


def parse_swap(value: str) -> tuple[str, str]:
    row, sep, source = value.partition("=")
    if not sep or row not in PROJECTS or source not in PROJECTS or row == source:
        raise argparse.ArgumentTypeError(
            f"expected <project>=<other project> from {', '.join(PROJECTS)}"
        )
    return row, source


def run(argv: list[str], environ: dict[str, str], api: Api, out=sys.stdout) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--control-swap",
        type=parse_swap,
        metavar="PROJECT=OTHER",
        help="evaluate PROJECT's row with OTHER's token; must report FAIL",
    )
    args = parser.parse_args(argv)
    try:
        tokens = read_tokens(environ)
        if args.control_swap:
            row, source = args.control_swap
            tokens[row] = tokens[source]
            result = evaluate(api, tokens, observe(api, tokens))
            print(render(result, f"CONTROL: {row} row evaluated with the {source} token"), file=out)
            if not detected_reach(result, row, source):
                print(
                    f"CONTROL BROKEN: the {row} row, evaluated with the {source} token, does not "
                    f"show REACHES ACROSS in the {source} column, so this probe cannot detect a "
                    "token reaching the wrong project. Its PASS on a real run proves nothing.",
                    file=out,
                )
                return 1
            print(
                f"CONTROL OK: the probe reported the {row} row reaching across into {source}, "
                "as it must.",
                file=out,
            )
            return 0
        clashes = distinct(tokens)
        if clashes:
            raise ProbeError("; ".join(clashes))
        result = evaluate(api, tokens, observe(api, tokens))
    except ProbeError as error:
        print(f"ERROR (not evidence of isolation): {error}", file=out)
        return 2
    print(render(result, "Hetzner project isolation"), file=out)
    return 0 if result.passed else 1


def main() -> int:
    # The endpoint is deliberately not configurable from the environment: a
    # stray variable pointing at anything else would receive every token and
    # could answer PASS.
    return run(sys.argv[1:], dict(os.environ), Api())


if __name__ == "__main__":
    raise SystemExit(main())
