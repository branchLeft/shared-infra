"""Judge the configuration Caddy itself would run for the demo edge's candidate.

The role never reads a Caddyfile for its sites or its certificate modes. It has Caddy
adapt the candidate (`caddy adapt --adapter caddyfile`), and this program judges the
JSON that comes back, so whitespace, a brace on a line of its own, or any other
spelling of the same Caddyfile cannot change the verdict.

The config is read from the environment variable named by --env, because the command
that runs this program is a script task and a script task has no standard input. The
program prints one line and nothing else: OK, or REFUSED and a code. No line carries a
hostname or any part of the config, as the config holds the slots' hostnames.

Usage: judge_caddy_config.py --env NAME --base BASE --token-file PATH
Exit status: 0 accepted, 1 refused.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

REFUSALS = {
    "not-json": "Caddy did not print a JSON config.",
    "internal-issuer": "The config holds an internal issuer, Caddy's own authority.",
    "top-level": "The config holds a top-level key other than the admin switch and apps.",
    "admin": "The config does not switch the admin endpoint off.",
    "apps": "The config holds an app other than http and tls.",
    "tls-shape": "The tls app holds anything but one automation policy list.",
    "policies": "The tls app does not hold exactly one automation policy.",
    "policy-subjects": "The one automation policy does not manage exactly the wildcard name.",
    "policy-keys": "The automation policy holds a key beyond its subjects and issuers.",
    "issuers": "The automation policy does not hold exactly one issuer.",
    "issuer-module": "The one issuer is not ACME.",
    "issuer-challenges": "The ACME issuer is not the DNS-01 challenge of the pinned provider.",
    "http-shape": "The http app holds anything but its servers.",
    "servers": "The config does not hold exactly one server.",
    "server-listen": "The one server does not listen on port 443 alone (plain HTTP).",
    "server-keys": "The one server holds a key beyond its listen and routes.",
    "routes": "The one server does not hold exactly one route, the wildcard site.",
    "route-keys": "The route holds a key beyond its match, handle and terminal.",
    "route-match": "The route does not match exactly the wildcard host.",
}


def internal_issuer_anywhere(node: object) -> bool:
    if isinstance(node, dict):
        if node.get("module") == "internal":
            return True
        return any(internal_issuer_anywhere(v) for v in node.values())
    if isinstance(node, list):
        return any(internal_issuer_anywhere(v) for v in node)
    return False


def judge(config: object, base: str, token_file: str) -> str | None:
    """Return the code of the first refusal, or None when the config is acceptable."""
    if not isinstance(config, dict):
        return "not-json"
    # The internal issuer is named first, whatever else is wrong, as the most useful answer.
    if internal_issuer_anywhere(config):
        return "internal-issuer"
    if set(config) != {"admin", "apps"}:
        return "top-level"
    if config["admin"] != {"disabled": True}:
        return "admin"
    apps = config["apps"]
    if not isinstance(apps, dict) or set(apps) != {"http", "tls"}:
        return "apps"

    wildcard = "*." + base
    tls = apps["tls"]
    if not isinstance(tls, dict) or set(tls) != {"automation"}:
        return "tls-shape"
    automation = tls["automation"]
    if not isinstance(automation, dict) or set(automation) != {"policies"}:
        return "tls-shape"
    policies = automation["policies"]
    if not isinstance(policies, list) or len(policies) != 1:
        return "policies"
    policy = policies[0]
    if not isinstance(policy, dict) or policy.get("subjects") != [wildcard]:
        return "policy-subjects"
    if set(policy) != {"subjects", "issuers"}:
        return "policy-keys"
    issuers = policy["issuers"]
    if not isinstance(issuers, list) or len(issuers) != 1:
        return "issuers"
    issuer = issuers[0]
    if not isinstance(issuer, dict) or issuer.get("module") != "acme":
        return "issuer-module"
    expected = {
        "module": "acme",
        "challenges": {
            "dns": {"provider": {"name": "hetzner", "api_token": "{file." + token_file + "}"}},
        },
    }
    if issuer != expected:
        return "issuer-challenges"

    http = apps["http"]
    if not isinstance(http, dict) or set(http) != {"servers"}:
        return "http-shape"
    servers = http["servers"]
    if not isinstance(servers, dict) or len(servers) != 1:
        return "servers"
    server = next(iter(servers.values()))
    if not isinstance(server, dict) or server.get("listen") != [":443"]:
        return "server-listen"
    if set(server) != {"listen", "routes"}:
        return "server-keys"
    routes = server["routes"]
    if not isinstance(routes, list) or len(routes) != 1:
        return "routes"
    route = routes[0]
    if not isinstance(route, dict) or set(route) != {"match", "handle", "terminal"}:
        return "route-keys"
    if route["match"] != [{"host": [wildcard]}] or route["terminal"] is not True:
        return "route-match"
    return None


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--token-file", required=True)
    args = parser.parse_args(argv)
    try:
        config = json.loads(os.environ.get(args.env, ""))
    except ValueError:
        config = None
    code = judge(config, args.base, args.token_file)
    if code is None:
        print("OK")
        return 0
    print(f"REFUSED {code}: {REFUSALS[code]}")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
