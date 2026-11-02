"""A stand-in for Stalwart's admin API on 127.0.0.1:8080, for the role's container test only.

It keeps objects by kind and id in one JSON file, answers the JMAP get and set calls and the
readiness poll, and logs every request, so a test can count calls and see any write. While the
file `fail` exists it answers every request with a 500 whose body is that file's text.
"""

import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

HOME = "/var/tmp/stand-in"
STATE = f"{HOME}/state.json"
CALLS = f"{HOME}/calls.jsonl"
FAIL = f"{HOME}/fail"
SECRET = f"{HOME}/secret"


def read(path: str) -> str:
    with open(path, encoding="utf-8") as handle:
        return handle.read().strip()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args: object) -> None:
        return

    def send(self, code: int, body: object) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def record(self, entry: dict[str, str]) -> bool:
        """Log the request; answer 500 with the fail text and return True while it is set."""
        with open(CALLS, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")
        if os.path.exists(FAIL):
            self.send(500, {"error": read(FAIL)})
            return True
        return False

    def do_GET(self) -> None:
        if not self.record({"method": "GET", "path": self.path, "jmap": ""}):
            self.send(200, {"permissions": []})

    def do_POST(self) -> None:
        call = json.loads(self.rfile.read(int(self.headers["Content-Length"])))["methodCalls"][0]
        name, args = call[0], call[1]
        if self.record({"method": "POST", "path": self.path, "jmap": name}):
            return
        kind, operation = name[2:].split("/")
        state = json.load(open(STATE, encoding="utf-8")) if os.path.exists(STATE) else {}
        objects = state.setdefault(kind, {})
        result: dict[str, object] = {}
        if operation == "get":
            if args.get("ids") == ["singleton"]:
                objects.setdefault("singleton", {"id": "singleton"})
            found = [objects[i] for i in args["ids"]] if "ids" in args else list(objects.values())
            account = args.get("accountId")
            result = {"list": [o for o in found if account is None or o.get("accountId") == account]}
        else:
            created, updated = {}, {}
            for key, new in args.get("create", {}).items():
                identifier = f"{kind}{len(objects) + 1}"
                objects[identifier] = {**new, "id": identifier, "accountId": args.get("accountId")}
                created[key] = {"id": identifier}
                if kind == "AppPassword":
                    created[key]["secret"] = read(SECRET)
            for identifier, patch in args.get("update", {}).items():
                objects.setdefault(identifier, {"id": identifier}).update(patch)
                updated[identifier] = {}
            result = {"created": created, "updated": updated}
        with open(STATE, "w", encoding="utf-8") as handle:
            json.dump(state, handle)
        self.send(200, {"methodResponses": [[name, result, "0"]]})


HTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
