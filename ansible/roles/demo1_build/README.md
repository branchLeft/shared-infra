# demo1_build

This role builds the demo host's slots on demo1: it stages the demo-host
provisioning programs from `branchLeft/ghost-platform` at a pinned commit,
installs the three that something else runs, and declares everything the runbook's
Phase A (`demo1-host-build-and-broker-runbook.md` in ghost-platform-docs, steps
A-1 to A-12) used to do by hand, as far as it can be done without the owner. It
reads what the `broker_deploy` role leaves behind and never writes it.

This README is self-contained and is written for a maintainer new to the
repository. It follows the order the standard sets for a role README (ANS-14).

## What the role does, and what it does not

The role is a host build for seven slots, each a pair of colours (`a`, `b`).
Every slot has its own uid (30001 and up), a socket directory the health router
serves from, two colour units and two drain flags. One account, `demo-router`
(uid and gid 30008), runs the health routers.

What the role does, in the order of `tasks/main.yml`:

1. **Checks its inputs** (`_inputs.yml`): the pinned commit is a full sha, every
   program has a 64-digit sha256, the slot table is digits and not repeated, and
   the wrapper path is an absolute path with no dot segment, doubled slash or
   trailing slash.
   **Holds each vendored program to its pin** (`_vendored.yml`), right after,
   and before anything is read from the host or written to it: each of the ten
   programs under `files/ghost-platform` is hashed on the machine that runs the
   role and must be a plain file with its pinned sha256, or the run stops and
   names the file.
2. **Checks what `broker_deploy` left** (`_preconditions.yml`), read-only: the
   `broker` account exists; `/etc/branchleft`, `/var/lib/branchleft`, `/usr/local`,
   `/usr/local/sbin`, `/usr/local/lib` and `/opt` are root-owned directories that
   are not links and not writable by group or others (root runs programs from
   them); the broker's slots directory is `broker:broker` `0755`; and, when
   `broker.env` exists, it holds exactly one drain-flag line,
   `BROKER_DRAIN_FLAG_DIR=/var/lib/branchleft-broker/drain-flags`.
3. **Stages the programs** (`_release.yml`): the ten programs, each copied with
   `copy` from the role's own `files/ghost-platform` (which step 1 has held to the
   pins), into `/opt/branchleft/demo-host/releases/<commit>/demo-host/provision/`
   (root, `0755` directories, `0644` files). `current` links to the release. The
   role then reads each file back, compares it with its pin again, and decides
   whether the release is whole. Nothing is fetched from the network.
4. **Compares the sudoers grant with the pinned generator** (`_sudoers_check.yml`),
   read-only, and before any program is installed, so a grant it refuses leaves
   the wrapper uninstalled by that run: the file is a regular file, `root:root`,
   `0440`, and passes `visudo -csf`; the **body** of the file equals the body of the
   output of the pinned `render_slot_sudoers.py`, line for line and in order; the
   slots in the generator's rules are the slots in the role's table; and every rule
   runs exactly `demo1_build_wrapper_path`, the path step 5 installs the wrapper
   at, so a path the grant does not name is refused before anything is written
   there. It needs only the staged release, so it follows step 3.

   The body is everything from the first line that is not part of the header. The
   header is the leading run of blank lines and comment lines, a comment being `#`
   alone or `#` and a space (`^#( .*)?$` in `vars/main.yml`), and a comment
   ending in a backslash is not header, because sudoers joins it to the next line.
   The header is the one part not compared, because `broker_deploy`'s template and
   the generator word it differently. From the first rule on nothing is exempt: a
   comment, a `#1000` uid rule and a `#includedir` line all differ from the
   generator's body and are refused, wherever they sit. Nothing is sorted.
   Trailing blank lines are dropped, as they are inert.

   In a plan on a host with no staged release there is no generator to compare
   with. The comparison is then **skipped, with a stated reason**, and the plan says
   so in a visible line, "Sudoers grant NOT verified", so a skip does not read as a
   pass (ANS-10). The checks that need no generator still run. An apply cannot
   reach that branch: `_release.yml` refuses to go on without the whole release.

5. **Installs three programs where something else runs them** (`_programs.yml`):
   the slot wrapper at the path of the sudoers grant, and the drain sidecar and the
   health router in `/usr/local/lib/branchleft/` (root, `0755`), the paths the
   rendered units name. Before installing the sidecar it reads it and refuses a
   file that reads another drain-flag directory or names flags another way.
6. **Records the uid claims and makes the router's account** (`_accounts.yml`):
   see the next section.
7. **Declares the directories** (`_dirs.yml`): the router's socket tree, the
   broker's state directory, the drain-flag directory and, once, the fourteen
   flags a build starts drained. It first refuses, in a plan as well as an apply
   and before it creates anything, any of those paths that is a link or is not a
   directory: the broker owns a parent of two of them and the router a parent of
   the others, so either could point one at a directory root relies on, and a file
   task that followed the link would give that directory to the broker or the
   router. Every file task there also sets `follow: false`, so the module refuses
   a link that appears after the check. The flags are written in a staging
   directory under the state root, which only root can write, and the directory is
   moved to the flag directory's name in one rename (see "Drain flags"), so root
   never writes through a name in the broker's own tree.
8. **Writes the units** (`_units.yml`): the shared compose template unit, copied
   from `hetzner/provision/` of the checkout (A-7); the fourteen colour drop-ins and
   the health router's template unit, from the pinned renderers' output; one systemd
   reload when any changed. Then it asks systemd whether each colour instance
   loads (`_units_loaded.yml`, read-only). An instance that does not load stops the
   run, and the message names the cause: the shared compose template unit is not
   installed, or does not load with the drop-ins (see Phase A-7).
9. **Stages the candidates** (`_candidate.yml`, `_site_candidates.yml`,
   `_dns_token.yml`, `_candidate_refusal.yml`): two files in a root-only candidate
   directory, for the owner to diff against the live edge before going live.
   `edge-upstreams.caddy` is the edge's upstream snippets, rendered by the pinned edge
   renderer. `Caddyfile` is the one combined candidate: the pinned site renderer is
   called once, with every slot that has an owner-placed edge input, and prints the
   upstream snippets once and one `*.<base>` site, with a host matcher for each slot
   and a final `handle { abort }`. The site's one certificate is the wildcard that
   Caddy obtains by DNS-01, through a `tls { dns hetzner {file.<token path>} }` block
   that the role passes to the renderer; there is no interim certificate mode. The
   role checks each input's shape first (a regular file, not a link, `root:root`, mode
   0600 or narrower), looks at the token file (below), and reports the renderer's own
   refusal by slot number, without its message. Before it stages the text it has the
   demo edge's Caddy image adapt it and judges the config Caddy would run (see
   "How the candidate is judged"): anything but one wildcard site on port 443 with one
   ACME issuer, the DNS-01 provider and the token file is refused. The role also
   removes any `site-<n>.caddy` an earlier version staged. A slot with no input is
   named "Site candidate for slot <n> NOT rendered", and a candidate that is not
   staged at all says "Production candidate NOT staged" and why. Both are stated
   skips, not a pass. The renderer lives in ghost-platform: this role carries its
   sha256-pinned copy and holds the text it prints to the check above, and never
   edits or rewrites that text.
10. **Reads back what root will run** (`_integrity.yml`): each installed program is
    the pinned file, `root:root`, mode `0755`, not a link, and every directory
    above it is root-owned and not writable by anyone else.

### What each Phase A step becomes

| Runbook step                                              | Becomes                                                                                                                                                                  | Where                                 |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------- |
| A-1 stage the scripts in a root-only directory            | RUN as a pinned release, kept (not removed)                                                                                                                              | `_release.yml`                        |
| A-2 install sudo and xz-utils                             | NOT ROLE: the role requires `visudo` and refuses without it; xz belongs to the Node step                                                                                 | `_sudoers_check.yml`                  |
| A-3 claim the uids                                        | RUN the pinned `demo_uid_claims.py`, only when a claim is missing                                                                                                        | `_accounts.yml`                       |
| A-4 the two accounts                                      | `demo-router` created here (create or assert, never `usermod`); `broker` is `broker_deploy`'s and asserted                                                               | `_accounts.yml`, `_preconditions.yml` |
| A-5 wrapper, then the sudoers boundary                    | wrapper INSTALL; the boundary is `broker_deploy`'s and is compared, never written                                                                                        | `_programs.yml`, `_sudoers_check.yml` |
| A-6 read the boundary back                                | the assertions of the sudoers check                                                                                                                                      | `_sudoers_check.yml`                  |
| A-7 compose template and drop-ins                         | the template unit is copied from `hetzner/provision/` (read, not copied into the role); the fourteen drop-ins are written and the fourteen instances are checked to load | `_units.yml`, `_units_loaded.yml`     |
| A-8 health routers                                        | the template unit is written and systemd reloaded; no router is enabled or started                                                                                       | `_units.yml`                          |
| A-9, A-9b drain-flag directory                            | declared with modules, links refused; flags pre-seeded once, under a root-owned marker                                                                                   | `_dirs.yml`                           |
| A-10 the seven slot directories, by the wrapper's `reset` | NOT ROLE: `reset` wipes and recreates a tenancy and is the owner's to run                                                                                                | none                                  |
| A-11 remove the staging directory                         | retired: the release is the staging and is kept                                                                                                                          | none                                  |
| A-12 evidence                                             | the Molecule `verify.yml` and the harness                                                                                                                                | `molecule/default`                    |

### What each pinned program becomes

| Program                                         | Role                     | Notes                                                                                                              |
| ----------------------------------------------- | ------------------------ | ------------------------------------------------------------------------------------------------------------------ |
| `branchleft_slot.py`                            | INSTALL                  | The wrapper. Installed, never run.                                                                                 |
| `demo_sidecar.py`                               | INSTALL                  | Run by the colour drop-ins, never by the role.                                                                     |
| `health_router.py`                              | INSTALL                  | Run by the router unit, never by the role.                                                                         |
| `render_slot_sudoers.py`                        | RUN, stdout only         | Printed, not written: the comparison.                                                                              |
| `render_colour_units.py`                        | RUN, stdout only         | The drop-ins' text.                                                                                                |
| `render_router_unit.py`                         | RUN, stdout only         | The router unit's text.                                                                                            |
| `render_demo_edge.py`                           | RUN, stdout only         | The candidate fragment.                                                                                            |
| `demo_uid_claims.py`                            | RUN, writes the register | Only when a claim is missing; never in check mode.                                                                 |
| `render_demo_site.py`                           | RUN, stdout only         | One call for every slot with an input, staged as the one Caddyfile. Never run with `--gate-env-out`, which writes. |
| `demo_go_live.py`                               | STAGED, NOT ROLE         | The owner's go-live. The role never runs it.                                                                       |
| `provision_socket_dirs.py`, `drain_flag_dir.py` | NOT FETCHED              | Their jobs are declared with `file` tasks, so a plan shows each one.                                               |
| `branchleft_demo_egress.sh`                     | NOT ROLE                 | The egress ruleset; see the gaps.                                                                                  |

"RUN, stdout only" means the renderer is run with no output flag: it prints to
standard output and writes nothing, so running it is a read and is the one
task allowed to run in check mode (ANS-10). Each such task runs with
`/usr/bin/python3 -E -s -B`, so no environment variable, user site or bytecode
file reaches the release.

### What the role does not do

- It does not write `/etc/sudoers.d/branchleft-slot` or create the `broker`
  account. `broker_deploy` owns both. A second writer of the grant is what the
  comparison and the Molecule control exist to catch.
- It does not apply `broker_deploy`, and it has no `dependencies` entry in
  `meta/main.yml` (ANS-12). `broker_deploy` is applied first, from the owner's
  inputs, and `demo1_build` refuses a host where it has not been.
- It does not write the live Caddyfile, run `demo_go_live.py`, or run
  `branchleft-slot reset`. Opening the demo is the owner's decision.
- It does not enable or start a health router or a colour unit.
- It does not fetch secrets. Anything secret on the host is a root-only file the
  owner puts there.
- It does not read the DNS token. The token is the owner's, placed once as a root-only
  file in `/etc/branchleft/secrets/`; the role only looks at the file's type, owner,
  mode and size, never opens it, takes no checksum of it and never copies it, and
  gives Caddy the path. Caddy reads the file when it runs.
- It does not make the owner's edge input for a slot, and does not decide what it
  holds. The renderer reads the file, the role checks its shape and stages the
  output, and no task of the role prints the output (ANS-16).
- It does not hold or change renderer logic. The renderer lives in ghost-platform and
  the role carries sha256-pinned copies of it; it never edits a vendored file and
  never rewrites the text the renderer prints.
- It does not keep a copy of the shared compose template unit. It installs the file
  `hetzner/provision/branchleft-compose@.service` of the checkout (A-7, Phase A-7
  below). A byte copy or a link of that file in this role is refused by
  `test_deploy_tooling_single_owner.py`.

## Interface

[`meta/argument_specs.yml`](meta/argument_specs.yml) declares every variable and
[`defaults/main.yml`](defaults/main.yml) holds them. There is no required input and
no secret: the one file that holds a secret is named by a path input and never read.

- `demo1_build_source_sha`: the ghost-platform commit the vendored programs were
  taken from. It names the release directory.
- `demo1_build_release_files`: each program's path under the commit and its sha256.
- `demo1_build_slot_names`: the slot table, taken from `broker_deploy_slot_names`
  when that is set; the role checks it against the slots in the generator's grant.
- `demo1_build_wrapper_path`: taken from `broker_deploy_wrapper_path` when that is
  set. The pinned generator hard-codes `/usr/local/sbin/branchleft-slot`, so on an
  apply this input has exactly one value that can pass: any other path makes the
  installed grant differ from the generator's, and every rule must name this path
  anyway. The input exists so the role states the path it installs at; it is not a
  place to choose another one.
- `demo1_build_wildcard_base`: the base domain of the demo's one wildcard site
  (`*.<base>`), empty by default. Every demo hostname is exactly one label below it.
  The role refuses anything that is not a lower-case domain of at least two labels
  (letters, digits and inner hyphens, no wildcard character, no leading or trailing
  dot). Empty, the production candidate is not staged and the plan and apply say so.
- `demo1_build_dns_token_file`: the path of the root-only file that holds the DNS-01
  token of the demo's own DNS project, by default
  `/etc/branchleft/secrets/demo-dns-caddy-demo1-wildcard`. It must be a file directly
  in `/etc/branchleft/secrets`, named with letters, digits, dot, underscore and
  hyphen. The role passes the path to the renderer as `dns hetzner {file.<path>}`.
- `demo1_build_caddy_image`: the Caddy image that judges the candidate, empty by
  default. Pinned by its digest: `<name>@sha256:` and 64 hex digits, with no tag and no
  image ID (the role refuses anything else). It is the demo edge's image (Caddy with the
  Hetzner DNS module), carried onto the host by the owner ("How the Caddy image gets onto
  the host"); the role never pulls. The role finds it with `docker image inspect` and
  wants exactly one image whose `RepoDigests` hold the pinned digest. Empty, or an
  image that docker does not find, the production candidate is not staged and the plan
  and apply say so. An image that docker finds and that lists anything else (no digests,
  another digest, two images, output that is not JSON) is refused.

`vars/main.yml` holds the constants (paths, accounts, uids, patterns). A caller
cannot override them.

### The wildcard candidate and the DNS token

The owner places the DNS token once, as `root:root` mode `0600`, in a root-only
`/etc/branchleft/secrets/` (the role neither creates nor checks the directory: a
token the owner has not placed reads as missing). The role looks at it with `stat`
and nothing else: `get_checksum`, `get_mime` and `get_attributes` are off because
each opens the file, and `follow` is off so a link is seen as a link. Nothing in the
candidate, the plan or the log holds the token's value, only its path, and only
inside the `dns hetzner {file.<path>}` reference.

A run stages `Caddyfile` only when the base is set, the token file is placed, the
Caddy image is set and loaded, the renderer is staged and at least one slot has an
edge input. When one of those is missing the run completes with a stated skip, never a
failure, and prints the first that applies, in this order, each starting "Production
candidate NOT staged:":

| Reason                                           | Words that follow                                                                     |
| ------------------------------------------------ | ------------------------------------------------------------------------------------- |
| The wildcard base is empty                       | the wildcard base (demo1_build_wildcard_base) is not set                              |
| No token file at the token path                  | no DNS token file is placed at the path                                               |
| No Caddy image is set                            | no Caddy image (demo1_build_caddy_image) is set to judge the candidate with           |
| The Caddy image is not on the host, by digest    | the Caddy image (demo1_build_caddy_image) is not loaded on this host under its digest |
| No renderer staged (a check run on a fresh host) | the pinned site renderer is not staged on this host                                   |
| No slot has an owner-placed edge input           | no slot has an owner-placed edge JSON                                                 |

A Caddy image that docker finds and that is not the pinned one is a refusal, not a skip: it
names the pinned digest and what docker listed, before the renderer runs. A host that has
the image on the classic image store lands here or in the skip above, never in a pass
("How the Caddy image gets onto the host").

A token file that is there and is not right is refused, each in its own check, and
the message names the path and never a value: it is a link, it is not a regular file,
it is not `root:root`, it has a group or other bit or an execute bit (it must be
`0600` or narrower), or it is empty. A renderer that refuses the base or an input is
reported as "The pinned site renderer refused the wildcard base or the edge input of
the occupied slot(s) <numbers>", with its own message withheld because it can echo a
hostname.

### How the candidate is judged

The role never reads the Caddyfile for its sites or its certificate modes. Caddy ignores
indentation and line breaks, so a test of the text's lines tests one spelling of the
file: an indented second site, a site opened on the closing brace of the wildcard
site, or an `internal` issuer in the global block all get past it, and Caddy serves
each. So the role asks Caddy. `_candidate_refusal.yml` runs, as root and before the
text is staged:

1. `files/judge_caddy_config.py --what candidate` on the text, before Caddy sees it. Caddy
   adapts with the environment and the filesystem of the judging container, which hold
   nothing, and the edge runs with its own, so the JSON cannot show two things: a
   `{$NAME}`, which Caddy replaces with the environment's value as it reads the text and
   which can bring in a whole extra site, and an `import` of a path, which brings in
   whatever files match it (none, in the judging container). Both are fixed syntax of
   Caddy's lexer, so a test of the text is sound here and not a test of one spelling. The
   text is refused if it holds `{$`, an `{env.` placeholder, a `{file.` placeholder other
   than the DNS token reference, which may occur once (a handler with a second one serves
   the token), or an
   `import` that is not `import <name>` of a snippet the text defines (Caddy reads any
   other name as a file). It is also refused if it names `file_server`, `templates` or
   `root` as a whole word (not one run into a host name such as `root.example`, so
   neither side may be a letter, digit, underscore, dot or hyphen): a file handler, or the
   directory it reads from, can serve the DNS token wherever it sits. It is also refused if
   it names `expression` as a whole word or holds a `ph(` call (a space may follow `ph`): a
   CEL expression matcher reads a placeholder by a name it builds at run time
   (`ph(req, "fi" + "le.<path>")`), which no `{file.` count in the text or the JSON sees,
   and its yes or no answer leaks the file a byte at a time. The renderer emits none of
   these.
2. `docker run --rm -i --pull never --network none --read-only --cap-drop ALL
--cap-add NET_BIND_SERVICE ... <demo1_build_caddy_image> caddy adapt --adapter
caddyfile --config -`, the candidate on standard input. Nothing is pulled, started
   as a server or written. Caddy refusing the text is a refusal.
3. `files/judge_caddy_config.py` on the JSON Caddy printed, which is what Caddy would
   run. It accepts only: the admin endpoint off; the `http` and `tls` apps and no
   other (`pki` is where `skip_install_trust` shows); one server, listening on `:443`
   alone (a plain-HTTP site is a server on `:80`), with one route whose host matcher
   is `*.<base>` and no other key (`auto_https` options show as keys); one TLS
   automation policy, for the subject `*.<base>` alone, with one issuer that is ACME
   with exactly the DNS-01 provider `hetzner` and the token file reference
   `{file.<token path>}`; no `internal` issuer anywhere in the JSON; and no other
   `{file.` or `{env.` placeholder anywhere in it, in a key or a value (the reference
   in the issuer is the only one); and no `file_server` or `templates` handler and no
   `root` key anywhere in it, at any depth (a `root` directive and `vars root` adapt to
   one). These are refused outright, not by path: a root of `/` or `/etc` above the token,
   a relative root, a placeholder root and a link all reach it, and the demo edge serves no
   file; and no `expression` key anywhere in it, at any depth, for the same reason as the
   text's `expression` and `ph(`. Adapting does not resolve a placeholder, so a
   handler that answers with the token file keeps its placeholder in the JSON. It prints
   one line, `OK` or `REFUSED <code>: <reason>`, that holds no hostname.

The judge takes the JSON in its environment, because a script task has no standard
input. Both steps are hidden (`no_log`, ANS-16), and the registered results are emptied.

The Caddy image is a role input because demo1 runs no Caddy of its own and the owner
loads the demo edge's image onto it (an image that must not be pulled from a registry).
Until it is set and found on the host the candidate is not staged. This is the point of the
check: a judge that cannot ask Caddy would have to read the text.

`tests/unit/test_caddy_judge.py` is the proof. It builds the demo edge's Caddy (2.11.4
with the Hetzner DNS module, the pins of ghost-platform's `services/demo-edge`), renders
the candidate with the real vendored renderer, applies each bypass to it (the three
indentation spellings, the closing-brace spelling, a plain-HTTP site, `tls internal` in
the site, `cert_issuer internal`, `local_certs`, `skip_install_trust`, `auto_https`
options, a custom ACME CA, certificate files, a token from the environment, a handler that
answers with the token file or an environment value, and a `file_server`, `templates` or
`root` handler with a root at the token's directory, above it or relative, and an
expression matcher that reads the token or an environment value by a built name), adapts each with the role's own
argument list and judges it. Each result must equal the JSON recorded in
`tests/unit/fixtures/`. For the refusals of the raw text it adapts each with real Caddy and
shows the hole: with the environment value or the files the edge would have, the same
text adds a second server, while adapted alone it gives one server the judge accepts. For
the file handlers it serves each one from real Caddy beside a fake token (a random string,
never a secret) in a throwaway container with no network, and fetches the token back with
the container's own `wget`; a handler that serves no file gets nothing back. It serves the
expression matcher the same way and shows a right guess of the token's start answering
`match` and a wrong one `nomatch`. The
Molecule scenarios replay those recorded files through a stand-in for docker, so the
refusals' messages and the nothing-staged check are tested in the container and the
recorded files are tied to real Caddy by that unit test.

The same test file proves the image check against a real Docker on both image stores. It
starts two throwaway Docker-in-Docker daemons with no network (pinned by digest), one on
the classic image store and one on the containerd image store, makes an image in the
second, carries it with `docker save` and `docker load` as the owner does, and runs the
role's own `docker image inspect` argument list and its own RepoDigests test (both rendered
from `vars/main.yml`) in each. It also runs the Molecule stand-in for docker
(`molecule/default/files/standin-docker.sh`) beside the real one and requires the same
answers to the calls the role makes, so the stand-in can no longer pass where a host would
not. A runner with no Docker fails these tests.
`DEMO1_BUILD_RECORD=1` rewrites the fixtures after a Caddy or renderer change (run
Prettier on them afterwards; the test compares the JSON, not the text).

### How the Caddy image gets onto the host

**The route: a one-off carry by the owner, then a check by digest.** The host has no route
to a registry and its egress allowlist holds the package mirrors only, so it never pulls
the image. The owner pulls the pinned image on a workstation, anonymously (the package is
public, so there is no login), checks the digest there, tags it with the name of the pin,
and streams `docker save` into `docker load` on demo1 over the edge1 jump that every other
bootstrap step uses. The host opens no connection and its allowlist is not touched. This is
the route the spool role's image takes (`demo1_egress_spool`), and the commands are in the
demo1 bootstrap runbook as owner steps, and only there: this README does not copy them, so
there is one home for them. The owner steps are:

1. Pull the pinned image by its digest on the workstation, for `linux/amd64` (a workstation
   may be arm64; demo1 is amd64).
2. Read the digest of what arrived and compare it with the digest in
   `demo1_build_caddy_image`. They must be equal, or the carry stops.
3. Tag the image with the name part of the pin.
4. `docker save` the tag, with no platform flag, into `docker load` on demo1.
5. On demo1, `docker image inspect <name>@sha256:<digest>` must list one image whose
   `RepoDigests` hold the digest. This is the check the role makes before it uses the image.

**What the trust rests on.** The digest in `demo1_build_caddy_image`, which is in the signed
commit. The workstation is only a carrier. The check on demo1 is made again from what is on
demo1, and the role makes it a last time before it judges anything: it asks docker for the
image by the pinned reference, wants exactly one image back, and wants the pinned digest in
its `RepoDigests`.

**Observed with a real Docker (29.8.2 on the workstation, 27.5 in the throwaway daemons),
each store.** They fix the steps, so they are named here:

- On the containerd image store, a save by tag then a load keeps the digest. The loaded image
  is found by `name@sha256:<digest>` and lists that reference in `RepoDigests`.
- On the classic image store, the same carry gives an image with a different ID, found by its
  tag with an empty `RepoDigests`, and `docker image inspect name@sha256:<digest>` exits 1,
  "No such image". The role sees an image that is not there and states a skip. The owner reads
  the store on both ends first (`docker info`, "Storage Driver" or "driver-type"), and the
  carry is for the containerd image store.
- `docker images --quiet <reference>` prints nothing for a digest reference on either store,
  whether the image is loaded or not, because its argument is a repository filter. The role
  does not use it, and a test holds that it would have found nothing.
- A wrong digest under the right name is not found: `docker image inspect` exits 1.

The traps of the spool image's carry apply unchanged, because the steps are the same: a
save by a digest reference carries no name, `docker save --platform` changes the digest, and
a tar with a changed layer loads with exit 0 and fails only when a container is created from
it. The image is not run by the role beyond `caddy adapt`, which fails on such an image.

**Limits, named:**

- **The demo edge's image is not published yet.** Nothing pushes it to a registry, so
  there is no digest to pin and nothing for the owner to pull. Until the image exists at a
  digest, `demo1_build_caddy_image` stays empty and the candidate is a stated skip. Where
  and how it is built, and for `linux/amd64` from an arm64 workstation, are decided with
  that publication, not here.
- **The carry is a bootstrap route.** A new digest needs the same steps again.
- **It fails closed on a classic image store**, as above: the role finds no image and stages
  nothing.
- **The role proves identity, not completeness.** A half-loaded image is found by
  `docker image inspect`; `caddy adapt` is what fails on it, and the role then refuses the
  candidate as one Caddy could not adapt.

### The pin

The commit is `595bcce0ee2bb1c7f8de565cf008060ea43122cf`, which is at or after
`0a23634b652a37260d77e656ded3c37ff24d62ec`, the ghost-platform commit that moved the
drain flags out of the slot directory to
`/var/lib/branchleft-broker/drain-flags`. A pin older than that commit puts flags
where the broker does not look; the role refuses a sidecar that does so.

Two things must agree: the files under `files/ghost-platform` and the checksums.
The role never fetches a file; it holds the copy it carries to the pins, on the
machine that runs it, before it writes anything (step 1). A changed file with the
old checksum fails there, and so does a changed checksum. CI runs the same
comparison without a container (`ansible/checks/test_demo1_no_github_fetch.py`),
and the Molecule scenarios run the role itself.

### Vendored files

The ten programs are carried in `files/ghost-platform/demo-host/provision/`, at
the paths they have in ghost-platform. They arrive on the demo host in the signed
commit it checks out, so the host needs no route to GitHub, and its egress
allowlist holds the package mirrors only. To bump them, in one change:

1. In ghost-platform, at the new commit, compute each checksum with
   `git show <commit>:<path> | shasum -a 256`.
2. Write each file into `files/ghost-platform` with
   `git show <commit>:<path> > ansible/roles/demo1_build/files/ghost-platform/<path>`,
   so the bytes are the commit's and nothing re-wraps them.
3. Change `demo1_build_source_sha` and every checksum in `defaults/main.yml`, and
   the same values in `meta/argument_specs.yml`.

Named limit: CI no longer compares the carried bytes with ghost-platform. It holds
them to the pin in this repository, so a change to a file and its pin together
passes. The review of such a change is a review of file content, not of a commit
sha; a CI step that checks out ghost-platform at the pinned commit and diffs is
filed as follow-up. The vendored files are also not scanned by the no-fetch check,
which reads the role's own tasks and variables: they are upstream's text, and root
runs them.

## Requirements

- ansible-core at the version pinned in `ansible/requirements.txt`; the role's
  `min_ansible_version` is that version and the harness checks it.
- No collections beyond `ansible.builtin`.
- Target: Debian 13 with Python 3 (`/usr/bin/python3`), systemd, and `sudo` (for
  `visudo`). The role runs as root.
- `broker_deploy` applied on the host first.
- No network from the host: the role fetches nothing (the programs are vendored).

## What it changes on a host

- `/opt/branchleft`, `/opt/branchleft/demo-host`, `releases/`, the release directory
  and its two subdirectories: `root:root` `0755`. The ten programs in
  `.../demo-host/provision/`: `root:root` `0644`. The link `current` to the release.
- `/usr/local/lib/branchleft/` (`root:root` `0755`) holding the sidecar and the
  health router (`root:root` `0755`), and the wrapper at `demo1_build_wrapper_path`
  (`root:root` `0755`).
- The uid register `/etc/branchleft/tenant-uids/`: one claim file per slot,
  `demo-<n>` with `slug=demo-<n>` and `uid=3000<n+1>`, and `demo-router` with uid 30008. Each `root` `0600`. The directory is `root` `0700`; the role refuses any
  other mode and never changes it.
- The `demo-router` group and account at 30008 (`/usr/sbin/nologin`, no home),
  only when the account does not exist. An existing account is checked against
  the same uid, gid, shell and group and is never modified.
- `/var/lib/branchleft/demo-router/` (`root:root` `0755`) and, under it, one
  directory per slot and one per colour (uid and gid 30008, `0700`).
- `/var/lib/branchleft-broker` (`broker:broker` `0750`) and its `drain-flags`
  directory (`broker:broker` `0755`). Once, on the run that creates the flag
  directory and only where there is no marker, fourteen empty flags (`root`
  `0644`), one per slot and colour.
- `/etc/branchleft/demo1-drain-flags-preseeded` (`root:root` `0644`, empty): the
  marker that says the flags were preseeded.
- `/var/lib/branchleft/demo-drain-flags-staging` (`root:root` `0700`): where the flags
  are written before the directory is moved into place. It exists only during the run
  that makes the flag directory, and a run that died in the middle leaves it.
- `/etc/systemd/system/branchleft-compose@.service` (`root:root` `0644`): the shared
  compose template unit, the bytes of `hetzner/provision/branchleft-compose@.service`
  of the checkout. Written before the reload; not enabled or started.
- `/etc/systemd/system/branchleft-compose@demo-<n>-<colour>.service.d/colour.conf`
  (`root:root` `0644`) for each slot and colour, and
  `branchleft-health-router@.service`; one systemd reload when any changed.
- `/var/lib/branchleft/demo-candidates/` (`root` `0700`) holding
  `edge-upstreams.caddy` (`root` `0600`), and, when the wildcard base is set and the
  DNS token file is placed, one `Caddyfile` (`root` `0600`): the pinned renderer's
  output for every slot whose owner-placed input `/etc/branchleft/demo-<n>.edge.json`
  it read, one `*.<base>` site. There is no per-slot file. The role never writes or
  reads back those inputs' values, never reads the DNS token, and never writes the
  live edge.

### Drain flags

A flag's presence means the colour is drained, and the broker clears a flag by
deleting it when a colour goes live. So the role writes the flags once, and never
recreates a flag after the broker removed it: putting one back would drain a colour
that is serving traffic. "Once" is a marker, `/etc/branchleft/demo1-drain-flags-preseeded`,
written after the flags. The broker owns the flag directory and can delete anything
in it, but cannot write `/etc/branchleft`, which the preconditions require to be
root's and closed to group and others. So the marker outlives the flags: a host
where every colour has gone live holds no flag at all, and a later run does not
seed them again. The flags are written only by the run that creates the flag
directory, and only where there is no marker. A directory that was already there is
never seeded, whatever it holds: one that holds a flag but has no marker (a host
built before the marker existed) gets the marker and no flags.

The order of the run that makes the directory, and why. The broker owns
`/var/lib/branchleft-broker`, so it can rename a directory in it and put a link of
the same name in its place, and a root task that writes a path through that name
follows the link. The link check cannot close that, and nor can making the flag
directory root's first, because the name is still resolved in the broker's directory
at every write. So the order is: (1) the declared directories are read and refused
if a link or not a directory, and the staging directory's parent (the state root) and
the broker's state directory (or its parent, where it does not exist yet) are read and
refused unless they are on one filesystem (see the premise below); (2) the staging directory
`/var/lib/branchleft/demo-drain-flags-staging` is made, root's `0700`, under the
state root, which only root can write; (3) the fourteen flags are written into it;
(4) the staging directory is moved to the flag directory's name with
`mv -T` (a single rename of the directory itself); (5) the flag directory is declared
as the broker's `0755` with `follow: false`; (6) the marker is written. Nothing the
broker owns is resolved while root writes a flag. Step 4 names a path in the broker's
tree, but as the destination of a rename: rename does not follow a link at the name
it replaces, and refuses a directory over a link or over a directory that holds
anything, so a link or a full directory the broker put there in the meantime stops
the run with nothing written through it. A directory the broker made there empty is
replaced.

The premise of step 4: it is one rename only where the staging directory and the
broker's state directory are on the same filesystem. A rename cannot cross
filesystems, and GNU `mv` does not then fail: it copies the tree and removes the
source. The copy makes the directory in the broker's tree first and writes each flag
through that name, which is the write through a name the broker owns that the staged
move is there to prevent; the order and staging checks below would not see it (the
copy keeps the flags' times and `mv` removes the source). So step 1 compares the device
number of the state root with that of the broker's state directory (and of a staging
directory a dead run left) and refuses the run, before anything is created, naming both
devices, in a plan as well as an apply. The two are one filesystem on the demo host
(`/var/lib` is not split, and no mount in this repository splits it), which is why this
is a guard and not a live fault. The device number does not see a bind mount of the same
filesystem (see the named limits).

The declaration in step 5 runs on every run and is the only task that touches the
flag directory on a host that already has one. It never sets the directory to root's
and back: on a host with a live flag directory a later run changes nothing in it, so
the broker, which may be running, never finds its directory changed under it. A run
that dies between steps 2 and 4 leaves the staging directory: the next run uses it
again (a flag already in it is kept). A run that dies after step 4 and before step 5
leaves a flag directory that is root's, which the next run hands to the broker.

A directory that exists, is empty and has no marker is refused, in a plan as well as
an apply and before anything is created. It cannot be told apart from two hosts that
need opposite things: one built by the pinned programs with every colour already live
(seeding it would drain every colour that is serving traffic), and one where an
earlier run died after creating the directory and before writing the first flag
(leaving it empty would start every colour live). The refusal names both remedies.
To keep the colours as they are, place the marker as root, empty, `root:root`
`0644`. To start every colour drained, remove the empty directory and run the role
again, which creates and seeds it. A run that dies while writing the flags leaves
some of them and no marker: the next run writes the marker without seeding, so the
flags that are missing are put in place by the owner.

### The uid register

The register is written only by the pinned `demo_uid_claims.py`, which locks the
directory and writes each claim crash-safely. The program has no dry-run flag, so it
is not run in check mode. The role decides first, by reading, whether any of the
eight claims is missing; it runs the program only then. Before running it, the role
reads `/etc/passwd` and refuses to claim a uid that an account already has, and it
refuses a claim file that holds another uid. The program is consumed as it is: it
takes no lock against a concurrent tenant allocation, which is a known gap in
ghost-platform and is not fixed here.

## Check mode

A plan makes no change on the host. Every program the role runs in check mode only
prints, and every program that writes is skipped there with its reason stated at
the task. In order:

| Task                                                     | In check mode                                                                                                                                                                                                    |
| -------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Reads (`stat`, `slurp`, `getent`, `find`, `visudo -csf`) | Run.                                                                                                                                                                                                             |
| Pinned renderers (stdout only)                           | Run with `check_mode: false`, only on a host that has the release; otherwise skipped, because there is no release to run.                                                                                        |
| Sudoers grant against the generator                      | Compared where the release is staged. On a host with none it is skipped and the plan prints "Sudoers grant NOT verified", with the reason; it never fails.                                                       |
| Directories, links, accounts, files, units               | Modules report what would change.                                                                                                                                                                                |
| Hash of each vendored program (`_vendored.yml`)          | Run: reads where the role runs and refuses a program that is not its pin.                                                                                                                                        |
| `copy` of the programs                                   | Run where the release directory exists (nothing to do); skipped where the directory does not exist, because `copy` cannot write into a missing directory.                                                        |
| Colour drop-ins and edge candidate                       | Skipped where their directories do not exist yet, for the same reason.                                                                                                                                           |
| Edge inputs, DNS token and site candidates               | Inputs and the token file are read as a stat, no checksum, and refused on their shape. Without a renderer, base or token the run says "Production candidate NOT staged"; a slot with no input is "NOT rendered". |
| Colour instances load (`_units_loaded.yml`)              | Where the drop-in directories are not on the host, skipped with the line "Colour units NOT verified". Elsewhere systemd is asked, changing nothing, and the check stops a run whose instance does not load.      |
| `demo_uid_claims.py`                                     | Never run.                                                                                                                                                                                                       |
| Drain-flag staging, pre-seed, move and marker            | Never run.                                                                                                                                                                                                       |
| Link check on the declared directories                   | Run: reads and refuses, so a plan on a host with a link in place stops there.                                                                                                                                    |
| Same-filesystem check of the staged move                 | Run where the move would run (no flag directory, no marker): reads and refuses, so a plan on a host whose state root and broker directory are split stops.                                                       |
| Refusal of an empty flag directory with no marker        | Run: reads and refuses, so a plan on such a host stops there with both remedies named.                                                                                                                           |
| Integrity read-back                                      | Not run: it reads the result of a real run.                                                                                                                                                                      |

The `plan` scenario's `converge.yml` runs the role in check mode and compares a list of
watched paths before and after: a path that did not exist must still not exist and
one that did must have the same modification time. That control holds on a fresh
host and on a configured one. The same play reads whether the release link
exists before the plan and asserts the other half of the rule: a plan on a host
with no staged release must print the NOT verified notice, and a plan on a
configured host must not, so a skipped comparison cannot pass silently.

## How to test it

From the repository root, with the tools installed as `ansible/README.md`
describes (Docker running locally, Python 3.12 or later):

```text
.venv/bin/python ansible/harness/run_harness.py ansible/roles/demo1_build
```

There are three scenarios, and CI runs each as its own job (a shard, below). Each
leaves out the harness steps that another scenario runs, listed in its
`skip-steps.txt` (`ansible/README.md`, "Sharing steps between scenarios"), and the
three together run every step:

- `molecule/default` applies the role and checks the result: `converge`,
  `idempotence` and `verify`. It holds every control that needs the role applied:
  the writers' boundaries, the drain flags, the install order, and `verify.yml`.
- `molecule/plan` is the three steps that plan: `check-fresh` before any apply,
  `check-configured` after one, and Molecule's own `molecule-check`. Its `converge.yml`
  applies the role once and makes the plan comparisons (a plan changes nothing, and
  says whether the sudoers grant was verified). It has no `verify.yml`, because it
  leaves out `idempotence` and `verify`.
- `molecule/refusals` does not apply the role. It stages the pinned release with the
  role's own `_release.yml` and runs the grant check alone against edited grants,
  one case at a time, and the directory step alone against links, files and flag
  directories. It leaves out the three plan steps: every play in it is skipped in
  check mode, so they would prove nothing there.

Both other scenarios' `molecule.yml` is a link to the default scenario's, so the
platform pin and settings have one home, and their `prepare.yml` imports the default
one's, so the grant is still rendered by `broker_deploy`'s own template.

To run one scenario, add `--scenario plan` or `--scenario refusals` (the default is
`default`):

```text
.venv/bin/python ansible/harness/run_harness.py --scenario refusals ansible/roles/demo1_build
```

Each runs on one systemd container (the same Debian 13 image and settings as
`broker_deploy`; the reason for each key is in `molecule.yml`, including the host
cgroup namespace, which is the stated exception).

Time is the reason there are three. A shard is one job with a 25-minute limit. The
first version of the refusal cases, which applied the role for each of eleven
cases, was cancelled at the limit; they moved to `refusals`. With the three plan
steps still in `default`, that shard then took 24 minutes 27 seconds of its 25 in
CI, and `refusals` took 11 minutes for a scenario that applies nothing. The plan
steps are where the time went: Molecule's own `check` recreates the container and
applies the role for real before it plans, and `check-fresh` and `check-configured`
each plan the whole role. So they moved to `plan`, and `refusals` left them out.

These are the steps of the shards before the split, from the CI run of the earlier
head (the record is the harness log at each head; the limit has not been raised):

| Step               | `default` | `refusals` |
| ------------------ | --------- | ---------- |
| `converge`         | 5 min 11  | 3 min 50   |
| `idempotence`      | 4 min 49  | 1 min 37   |
| `verify`           | 1 min     | 12 s       |
| `check-configured` | 2 min 8   | under 1 s  |
| `molecule-check`   | 7 min 55  | 4 min 16   |

The first application of the role in `default` takes about 140 s (measured when
the programs were still downloaded; the copies, the units and the integrity read-back), the second about 100 s, and the two refusal
plays that follow about 30 s and 3 s. What is in `refusals` is every case that needs
no install: the grant edits (ten), the wrong-pin case, the eighth-slot case, the
`/usr/bin/passwd` wrapper-path case, and the directory cases. What stays in
`default` is the case that proves a refusal comes before the install, which only a
whole-role run can show.

### The time bar, and what to do when it is missed

The record is CI, read from the harness step of each shard (the step named "Run the
harness over this role or pattern, for this scenario") at the head under review. The
bar for that step is:

| Shard      | The step must take at most | Why this number                                                             |
| ---------- | -------------------------- | --------------------------------------------------------------------------- |
| `default`  | 20 minutes                 | 80% of the 25-minute cap, so a slow runner does not cancel it               |
| `plan`     | 20 minutes                 | the same; it holds `molecule-check`, the longest step, and is the tight one |
| `refusals` | 10 minutes                 | 40% of the cap; the scenario applies nothing                                |

Read the step times with `gh run view <run id> --json jobs`, looking at the
`startedAt` and `completedAt` of that step. A shard over its bar is a failed
done-when even when it is green, and the 25-minute limit is not raised to make it
pass. The way to meet it is to move steps between scenarios, which is a
`skip-steps.txt` edit and, for a new scenario, a directory (a link for
`molecule.yml`, an import for `prepare.yml`); no workflow edit is needed, because the
shard list takes every directory under `molecule/` as a scenario. If `plan` is the
one over its bar, `molecule-check` is the step to move, to a scenario of its own.

### What runs for real

- `prepare.yml` renders `broker_deploy`'s own sudoers template and `broker.env`
  template with its own defaults and installs them. The role is therefore tested
  against the real component's output, and not against a fixture written to match.
  It also places what the owner places: the edge inputs of slots 0 and 1, with
  hostnames under the reserved `site-fixture.invalid` (one label below the wildcard
  base the converges set), and a DNS token file in `/etc/branchleft/secrets/`,
  `root:root` `0600`, holding a stand-in value that is not a credential. Both are
  placed with `no_log`.
- The pinned programs are the real ones, run: the renderers, the claim program and
  the checks of the sidecar's text. The scenario uses the role's own
  `files/ghost-platform/`, the same files a real apply copies, with no second copy;
  the role holds each to its pin, so a file that differs fails the scenario. Both
  scenarios run with `raw.githubusercontent.com` and `ghcr.io` mapped to the
  container's own loopback (`etc_hosts` in `molecule.yml`), and `verify.yml` asserts
  that both names resolve only there and that a request to either gets no answer
  (`molecule/default/tasks/blocked_outbound.yml`), so a role that reached for either
  would fail on a runner with internet too. A real apply makes no such request
  either.
- The real `visudo` checks the grant, and systemd reads the units.

### What does not run for real

- The wrapper is installed and never run (it needs Docker and a slot). The sidecar
  and the health router are installed and never started.
- No colour unit and no router is enabled or started.
- Docker, Caddy and the tenant images are absent.

### What `plan/converge.yml` proves

- A check run changes nothing on the host (above), and says whether the sudoers
  grant was verified. Both hold on a fresh host and on a configured one, because
  the scenario runs the converge in check mode before the apply and after it. The
  watched paths include the staged `Caddyfile` and the token file.
- A plan names the five slots with no edge input as "NOT rendered" on either host, and
  names all seven on a fresh host, where no renderer is staged. On a fresh host it also
  says "Production candidate NOT staged: the pinned site renderer is not staged"; on a
  configured one it says nothing, because the candidate is staged.

### What `default/converge.yml` proves

- The role leaves the sudoers grant and the broker's slots directory exactly as it
  found them: same checksum, same modification time, same entries.
- A drain flag the broker cleared is not put back by a later run, and neither are
  all fourteen: after every flag is cleared the directory step is run again, and
  no flag returns while the preseed marker stays.
- A refusal by the grant check stops the run before the install: the probe path
  `/usr/local/sbin/branchleft-slot-refused-probe` is not a file after the refusal.
  This is the one refusal that needs the whole role, so it stays here. A second
  case, a dotted spelling of a system binary, is refused by the input check before
  anything runs.
- `base_unset_is_a_stated_skip`, `token_missing_is_a_stated_skip`,
  `caddy_image_unset_is_a_stated_skip` and `caddy_image_not_loaded_is_a_stated_skip`
  run first, on a
  host where nothing is staged (`stated_skip.yml`, tagged so the idempotence step
  skips it): the role's site step completes, prints "Production candidate NOT staged:"
  with the reason, and the staged `Caddyfile` is exactly as it was, absent.
- After the apply, the five slots with no edge input are named "NOT rendered" and no
  "NOT staged" notice was printed. `secrets_never_logged` starts here: the stat result
  the role keeps of the token file holds no checksum, mime type, charset or content,
  so the role never opened it. Its other half is in `verify.yml`.

### What `refusals/converge.yml` proves

The first play stages the release, so the generator is on the host, and keeps the
grant as prepared. Each later play (`refused_grant.yml`) writes an edited grant with
`visudo -csf` as the validator, runs `_sudoers_check.yml` alone, and puts the
prepared grant back in every outcome. Each expects the refusal named in its case:

- the grant as prepared is **accepted** (the control: without it a role that
  refused every grant would pass every case);
- a `#1000` uid rule and a `#includedir` line, each before the first rule and after
  the last, and a comment after the last rule;
- a comment ending in a backslash before the first rule, which counts as body
  because sudoers joins it to the next line (a split that took it for header
  would drop it and accept the grant);
- the first rule with `, ALL` added, the last rule with `, /bin/sh` added, and the
  first rule replaced by a wildcard rule;
- the first rule removed (the comparison looks for a missing rule as well as an
  extra one), and the first two rules swapped (the comparison is ordered);
- a wrapper path the grant does not name (`/usr/bin/passwd`), refused by the
  last assertion of the grant check;
- the wrapper tie on its own, with no release staged (the generator comparison is
  skipped, as in a first plan): the grant as prepared is accepted and the role
  says it was NOT verified, and the last rule with `, /bin/sh` added is refused,
  because the tie matches each rule to its end;
- each path of the directory step as a link, one case each (the socket root, a
  slot's directory, a colour's directory, the broker's state directory and the
  drain-flag directory), refused before anything is created, with the link's
  target still `root:root` `0711` afterwards; and the same paths as real
  directories, accepted, which is the control (`refused_link.yml`; Molecule's
  idempotence step skips it, because the control creates the directories each time);
- the drain-flag directory as a regular file, which the file module would also
  refuse, with a message of its own, so only the role's message passes the case (the
  not-a-directory half of the check, which the link cases do not reach);
- a flag directory that was already there, is empty and has no marker, refused
  before anything is created with both remedies named, and nothing seeded, no marker
  written and the directory's owner unchanged (`refused_unmarked.yml`); and the same
  directory in the two states the role can read, accepted and not seeded: with the
  marker, and holding one flag with no marker (which gets the marker). In those two
  the directory is made the broker's first, as a running broker leaves it, and its
  owner, mode and change time are the same after the role's step: a task that set it
  to root's and back to write into it would leave the owner and change the time;
- in the accepted control of the directory step, the order of the run that makes the
  flag directory: the broker's state directory gained the flag directory after the
  newest flag was written (a directory's modification time is when an entry was made
  or moved into it), and the staging directory is gone. A directory made in the
  broker's tree first and filled after has an older time than its newest flag, and a
  copy leaves the staging directory behind;
- the staged move between two filesystems, refused before anything is created
  (`refused_device.yml`): the staging directory on `/run`, a tmpfs in the test
  container, and the broker's state directory on it (not yet made, so its parent is
  read), each refused with "cannot cross filesystems" naming the devices, and nothing
  left behind. The control that the check does not refuse everything is the accepted
  case of `refused_link.yml`, which runs the step on the real paths, on one filesystem;
- an eighth slot in the role's slot table, refused by the slot-table assertion;
- a pinned checksum with one digit changed, which stops the role at the vendored
  check, naming the program and before anything is written: the control is the
  same check with the real pins, and the whole-role case uses a source commit the
  host has no release directory for and asserts that none was made;
- the owner's edge input as a link, not root's and open to others, each refused with
  its own message, and a valid pair of inputs accepted and staged as `Caddyfile`
  (`refused_site_input.yml`); and a hostname the renderer refuses, whose message is
  withheld and whose hostname, a canary, must not reach the log;
- the DNS token file, with the valid one prepare placed put back after every case
  (`refused_token.yml`): `refused_token_link`, `refused_token_directory`,
  `refused_token_not_root`, `refused_token_mode_0644` and `refused_token_empty`, each
  expecting the role's own message, which names the path and no value, and each
  asserting that no `Caddyfile` was left. A link is refused for being a link; take
  that check away and the next one still refuses it, but with another message, so the
  case still goes red;
- the refusal of the staged text (`refused_candidate.yml`), run on a stand-in with
  the renderer's shape and one change, because the renderer cannot be made to print an
  interim certificate. The container has no Caddy, so docker is a stand-in that replays
  the JSON real Caddy printed for the same change (`tests/unit/fixtures`; "How the
  candidate is judged"). The cases are `refused_tls_internal`,
  `refused_tls_internal_indented`, `refused_global_cert_issuer_internal`,
  `refused_global_local_certs`, `refused_global_skip_install_trust`,
  `refused_global_auto_https_off`, `refused_indented_http_site`,
  `refused_indented_slot_site`, `refused_closing_brace_site`, `refused_http_only_site`
  and `refused_unadaptable_candidate`, each failing with its own code and no hostname,
  and the refusals of the raw text, `refused_env_substitution`,
  `refused_env_placeholder`, `refused_second_file_placeholder`, `refused_import_of_a_path`
  and `refused_import_of_an_undefined_name`, which are refused before Caddy is asked,
  with `refused_text_file_server`, `refused_text_templates`, `refused_text_root` and
  `refused_text_expression`,
  and `refused_handler_serves_the_token`, which is the JSON of a handler that answers
  with the token file, with `refused_handler_file_server`, `refused_handler_templates`
  `refused_handler_root` and `refused_handler_expression`, the JSON of a handler that reads
  a file or builds the name of one. The control is
  the text unchanged, accepted;
- the refusal of the Caddy image the host holds (`refused_image.yml`), with docker a
  stand-in that lists what the case says: `refused_image_no_digests` (what a loaded image
  lists on the classic store), `refused_image_other_digest`, `refused_image_two_images`
  and `refused_image_not_json`, each failing before the renderer runs and staging
  nothing. The control lists the pinned digest and stages the root-only candidate.

What `refusals` cannot see is an install, since it never applies the role. It
also cannot stage a stand-in for the generator: the real one is staged through
`_release.yml`, because a stand-in would be a second copy of the grant table, which
is the thing the check exists to compare with.

### What `verify.yml` checks

The expected owners, modes, numbers and paths are written out in the file, not
read from the role's variables, so a role that produced a wrong value fails
instead of agreeing with itself. The one value read from the role is each program's
pinned checksum, which is the pin. It checks the release (files, owners, modes, no
bytecode, `current`), the three installed programs, the register and its eight
claims, the router's account, the socket tree, the state and flag directories and
the thirteen flags that remain, the fourteen drop-ins and the router unit, systemd
loading the router unit without enabling it, the candidate directory and its
fragment, and the absences: no `Caddyfile` anywhere but the staged candidate, no slot
directory a `reset` would make, no wrapper lock directory.

`candidate_staged_root_0600_when_token_present` reads the staged candidate back: the
directory holds the `Caddyfile` and the fragment and no per-slot file (`prepare.yml`
leaves `site-0.caddy` and `site-3.caddy` there, carrying `tls internal`, as an earlier
version of the role staged them, so the role must have removed them); the
`Caddyfile` is `root:root` `0600`; its one top-level site is `*.site-fixture.invalid`;
both hostnames occur once each, in an `@slotN host` matcher and nowhere else; there
is no `https://`; exactly one `tls` line and no `internal` or `local_certs`; and the
token path occurs once, inside the `dns hetzner {file.<path>}` reference.
`secrets_never_logged` then scans the staged files and the run's Ansible log for the
stand-in token value and finds nothing. The scan counts only because its control is
found in the same log: the "Production candidate NOT staged" notice the stated skips
printed.

### What breaks which step

One row per mechanism. The first column is what to remove or change, the second is
the scenario and Molecule step that goes red, the third is the assertion that owns
the refusal and the words of its message, which the case matches, so a different
failure does not pass for the right one. The retrieval is the run itself: the
harness prints the step and the message, and the shard's log at the head of a pull
request shows the same.

The grant check (`_sudoers_check.yml`) runs its assertions in this order, and each
`refusals` case names the one that owns it, so a case goes red when an earlier
assertion fires in its place or a later one is the only one left:

1. the file is root's regular file, mode `0440`;
2. `visudo -csf` accepts it;
3. the installed body equals the generator's body (the grant bodies in `vars/main.yml`);
4. the slots in the generator's grant are the slots of the role;
5. every rule runs the wrapper path the role installs at.

| Mechanism removed or changed                                                                              | Scenario, step                          | Owning assertion and message                                                                                                  |
| --------------------------------------------------------------------------------------------------------- | --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| A task that writes a different valid sudoers file                                                         | default, `converge`                     | "The role wrote the sudoers grant."                                                                                           |
| The header split of the body reverted to a filter on any `#` line                                         | refusals, `converge`                    | 3: "is not what render_slot_sudoers.py renders" for the `#1000` and `#includedir` cases, in both positions                    |
| The body equality weakened to a prefix match on each rule                                                 | refusals, `converge`                    | 3: the same message, for the `, ALL` and `, /bin/sh` cases                                                                    |
| The comparison made one-directional (extra lines only)                                                    | refusals, `converge`                    | 3: the same message, for the case with a rule removed                                                                         |
| Both sides sorted before the comparison                                                                   | refusals, `converge`                    | 3: the same message, for the swapped-rules case                                                                               |
| The slot-table assertion removed                                                                          | refusals, `converge`                    | 4: "are not the slots in demo1_build_slot_names", for the eighth-slot case                                                    |
| The wrapper tie (assertion 5) removed                                                                     | refusals, `converge`                    | 5: "does not run /usr/bin/passwd in every rule"; and in default, the probe-path play                                          |
| The wrapper tie weakened to a prefix match (`[^ ]` at its end)                                            | refusals, `converge`                    | 5: "does not run /usr/local/sbin/branchleft-slot in every rule", for the `, /bin/sh` case with no release staged              |
| A backslash comment counted as header                                                                     | refusals, `converge`                    | 3: "is not what render_slot_sudoers.py renders", for the comment ending in a backslash                                        |
| The link check removed and `follow: false` set to true                                                    | refusals, `converge`                    | "is a link or is not a directory"; the case gets "The role accepted a link or a file in place of a directory it declares."    |
| The link check removed, `follow: false` kept                                                              | refusals, `converge`                    | the module refuses with its own message, "already exists as a link", which is not the case's phrase, so the case is red       |
| The not-a-directory half removed (the link test alone)                                                    | refusals, `converge`                    | "is a link or is not a directory", for the regular-file case: without it the flag-directory refusal answers in its place      |
| The refusal of an empty flag directory with no marker removed                                             | refusals, `converge`                    | "The role accepted a flag directory that is empty and has no marker."                                                         |
| One of the two seeding tests removed (the other still holds)                                              | none                                    | not detected: the directory test and the marker test each hold alone (a named limit below)                                    |
| The flags written in the broker's tree (staging removed, the directory made at its name and filled there) | refusals, `converge`                    | "gained the drain-flag directory before the newest flag was in it", in the accepted control of `refused_link.yml`             |
| The move replaced by a copy (the staging directory left behind)                                           | refusals, `converge`                    | "The drain-flag staging directory is still there. The directory was copied and not moved into place."                         |
| The same-filesystem assertion made vacuous (`- true`)                                                     | refusals, `converge`                    | "The role accepted a staging directory and a flag directory on different filesystems." (the copy fallback of `mv` ran)        |
| The broker directory's parent no longer read where the directory does not exist yet                       | refusals, `converge`                    | the same message, for the staging directory on a tmpfs                                                                        |
| A task that sets an existing flag directory to root's before it is handed back                            | refusals, `converge`                    | "The role changed a flag directory that was already the broker's", in the two accepted cases of `refused_unmarked.yml`        |
| `_programs.yml` run before `_sudoers_check.yml`                                                           | default, `converge`                     | "The role wrote /usr/local/sbin/branchleft-slot-refused-probe and then refused it." (the probe path exists after the run)     |
| The NOT verified notice removed, or printed on a configured host                                          | plan, `check-fresh`, `check-configured` | "A plan on a host with no staged release did not say the sudoers grant was NOT verified"                                      |
| The dot-segment condition of `_inputs.yml` removed                                                        | default, `converge`                     | the dotted-path play: "for a reason other than The wrapper path must be an absolute path"                                     |
| The checksum comparison of `_vendored.yml` removed                                                        | refusals, `converge`                    | "The role accepted a program whose pinned checksum was wrong", for the case with one digit of a pin changed                   |
| `_vendored.yml` moved after another step of `main.yml`                                                    | CI, `test_demo1_no_github_fetch.py`     | "main.yml includes ... first, not _inputs.yml then _vendored.yml"                                                             |
| `etc_hosts` removed from `molecule.yml`                                                                   | default and refusals, `verify`          | "resolves to an address outside the container, so the block on it is not in force"                                            |
| The old `get_url` task put back                                                                           | CI, `test_demo1_no_github_fetch.py`     | the file and line of the `get_url` and of the `raw.githubusercontent.com` URL                                                 |
| The socket directory mode changed                                                                         | default, `verify`                       | "The router's socket tree is not root's 0755 at the top and the router's 0700 below."                                         |
| The drain-flag directory's owner changed to root                                                          | default, `verify`                       | "The broker's state directory is not broker:broker 0750, or the drain-flag directory is not broker:broker 0755."              |
| A Caddyfile written anywhere but the staged candidate                                                     | default, `verify`                       | "A Caddyfile other than the staged candidate exists"                                                                          |
| The real wrapper's `reset` run by a task                                                                  | default, `verify`                       | the same assertion (the real wrapper leaves its lock directory)                                                               |
| The register directory made `0755` on the host                                                            | default, `converge`                     | "is not a directory owned by root with mode 0700."                                                                            |
| The wrapper installed group-writable                                                                      | default, `converge`                     | the integrity assertion on the installed programs                                                                             |
| The claim program run in check mode                                                                       | plan, `check-*`                         | "The check run changed"                                                                                                       |
| A file added to the broker's slots directory                                                              | default, `converge`                     | "The role changed the broker's slots directory"                                                                               |
| The site input link check removed (`_site_candidates.yml`)                                                | refusals, `converge`                    | "is a link or not a regular file", for the link case; the mode check then refuses the link instead                            |
| The site input owner check removed                                                                        | refusals, `converge`                    | "is not root:root", for the case of an input owned by broker                                                                  |
| The site input mode check removed                                                                         | refusals, `converge`                    | "must be 0600 or narrower", for the case of an input of mode 0644                                                             |
| The renderer's output not hidden (`no_log: false` on the render task)                                     | refusals, `verify`                      | "The scenario's log does not hold the scan control, or it holds the canary", for the leak case                                |
| The staged Caddyfile written with mode 0644                                                               | default, `verify`                       | "The staged Caddyfile is not a regular file of root:root mode 0600."                                                          |
| The NOT rendered notice made silent                                                                       | default, `converge`                     | "The site candidates are not the five slots with no edge input, a slot with no input was not named as NOT rendered"           |
| The token link check removed (`_dns_token.yml`)                                                           | refusals, `converge`                    | "is a link.", for `refused_token_link`; the next check then refuses it with another message                                   |
| The token regular-file check removed                                                                      | refusals, `converge`                    | "is not a regular file.", for `refused_token_directory`; the mode check then refuses it instead                               |
| The token owner check removed                                                                             | refusals, `converge`                    | "is not root:root.", for `refused_token_not_root`                                                                             |
| The token mode check removed                                                                              | refusals, `converge`                    | "is mode 0644.", for `refused_token_mode_0644`                                                                                |
| The token empty check removed                                                                             | refusals, `converge`                    | "is empty.", for `refused_token_empty`                                                                                        |
| The judge made to accept every config (`files/judge_caddy_config.py`, `judge` returns `None`)             | refusals, `converge`; `tests/unit`      | "The role accepted a candidate it must refuse.", for every `refused_*` case of the candidate; the unit test names each bypass |
| The notice of a skipped candidate changed or removed                                                      | default, `converge`                     | "The step did not say that the production candidate was not staged for the reason this case sets"                             |
| The token stat given `get_mime` or `get_checksum`                                                         | default, `converge`                     | "The role's stat of the DNS token file read it"                                                                               |
| The token value let into the log or a staged file                                                         | default, `verify`                       | "the stand-in token value is in the log or in a staged candidate (ANS-16)"                                                    |
| The colour instance check (`_units_loaded.yml`) assert removed                                            | refusals, `converge`                    | "The colour unit check accepted instances that load from no template."                                                        |
| Both seeding tests removed (the pre-seed guard)                                                           | default, `converge`                     | "The role put a cleared drain flag back."                                                                                     |

The row "The NOT rendered notice made silent" has not been run, so its red is not yet
recorded. It is a mechanism the default scenario would show, and it is not in the PR
body's sabotage record.

The harness's own controls (a failing second scenario fails its shard, a role with
no `molecule/` still gets a shard and fails at the scenario limits, a privileged
second scenario without a comment is refused, a second privileged platform needs a
comment of its own and is not covered by another platform's, and shard names are
unique) are in
`ansible/harness/test_run_harness.py` and `test_list_shards.py`, and run with the
other unit tests of `ansible/harness`.

### Named limits

- **The sidecar is not run.** It needs an image environment file that this role
  does not deliver; see the gaps. The test proves the text and the paths, not that
  a colour starts.
- **Each seeding test holds without the other.** The flags are seeded only where the
  run creates the directory and there is no marker. On a host with a directory the
  run did not create, the first test alone stops the seeding; on a host with the
  marker, the second does. Removing one of them leaves every case green, because the
  other covers every state the cases reach; removing both is caught. So the pair is
  checked as a pair.
- **`follow: false` on a file task is covered by the role's own check.** The check
  refuses a link before any file task runs, so a test cannot show the module's
  refusal by itself: the module guards the moment between the read and the write,
  which a test of this kind cannot hold open. The same holds for the move of the
  staging directory: that a link or a full directory put at the flag directory's name
  between the read and the move stops the `mv -T` is the kernel's rename, and no test
  can put the link in that gap. What the tests hold is the order around it: the flags
  exist before the directory appears in the broker's tree, and the move leaves
  nothing behind.
- **One filesystem is read as one device number.** The same-filesystem check compares
  `stat` device numbers, so it does not see a bind mount of the same filesystem (the
  device number is shared and a rename across the mount point still fails), nor a mount
  that appears between the read and the move. Only root can mount, and no mount in this
  repository splits `/var/lib`. The test container cannot mount (no capability is
  added), so it uses `/run`, a tmpfs, as the other filesystem, and cannot make a
  broker directory that exists and is itself a mount point, so no test reaches the
  branch that reads an existing broker directory's own device: it is the same
  comparison with the directory in place of its parent.
- **A silent skip passes, except one.** Tasks skipped in check mode on a host with
  no release are not caught by the harness; this table and the comments at each
  skip are the review of it (ANS-10). The grant comparison is the exception: its
  skip must print "Sudoers grant NOT verified" and `plan/converge.yml` asserts
  it.
- **The wrapper tie checks the shape of a rule, not its arguments.** It matches
  each rule from `broker ALL=(root) NOPASSWD:` and the wrapper path to the end of
  the line: one or more arguments of letters, digits, dot, underscore, slash and
  hyphen, one space before each. A rule with a comma, a wildcard, a colon or a
  trailing space does not match. Which arguments are legal is the body
  comparison's, and a plan on a host with no release does not make it.
- **A plan on a fresh host does not compare the grant.** There is no generator to
  compare with until a release is staged, so the first plan reports the grant as
  not verified. The apply compares it, and refuses any difference before anything
  is installed.
- **The mode at the instant of writing** of a file is a property of Ansible's
  temporary file and atomic move, not of anything the test observes.
- **A release directory is never removed.** Old releases stay.
- **A run killed after a unit file is written and before the systemd reload** leaves
  the new file unread by systemd. The next run finds nothing changed and does not
  reload, so the file is read at the next reload from any source (another role, a
  boot). Every file is written atomically, so none is ever half-written.
- The Python unit tests in `tests/unit` run in the Ansible workflow's lint job
  (`ansible/checks/run_role_unit_tests.sh`), and need Docker (real Caddy, and the
  throwaway daemons of the image check). The Molecule scenarios carry the controls that
  need the role applied.
- CI runs both scenarios: the Ansible workflow runs one job per scenario of every
  directory under `ansible/roles/` (`ansible/harness/list_shards.py` lists them),
  and this role's shards are `demo1_build` and `demo1_build (refusals)`.

## Gaps the role names and does not close

- **The sidecar's image environment file has no delivery path.**
  `/etc/branchleft/demo-sidecar.image.env` is not written by this role or by
  `broker_deploy`. The colour units and drop-ins are installed, but no colour starts
  until the owner places the file.
- **No router is enabled or started.** The template unit is installed and systemd is
  reloaded; starting is the owner's step.
- **The compose template unit is written from `hetzner/provision/` (A-7, the owner's
  ruling B of 4 Nov, ws#2364 comment 6630331961).** The drop-ins extend
  `branchleft-compose@`, and `deploy_tooling` owns that file on the other hosts. The
  single-owner test (`ansible/checks/test_deploy_tooling_single_owner.py`) refused a
  second role that names it, so it now exempts demo1 by program
  (`ALLOWED_SECOND_OWNER_PROGRAMS`): demo1 may read and name that one file, and a byte
  copy or a link of it stays refused. That exemption sits in an owner-merged file, so
  the PR that adds it waits for the owner's merge. The role-path check
  (`ansible/checks/check_role_paths.py`) does not object and needs no exemption:
  `deploy_tooling` writes the template through a loop item (`dest: '{{ item.path }}'`),
  which that check leaves templated and does not compare. demo1 never applies
  `deploy_tooling`, so the host has one writer of the file. What demo1 holds today is
  unknown without host access: the first plan shows any difference, and
  `_units_loaded.yml` stops a run whose colour instance does not load.
- **The candidate has no interim certificate and the role refuses one.** The role
  passes the renderer `--dns-directive` with a `dns hetzner {file.<token path>}`
  line and never `--tls`, so the one site's certificate is the wildcard Caddy obtains
  by DNS-01. A candidate that holds `tls internal`, `local_certs`, `skip_install_trust`,
  a second `tls` directive or a second site is refused before it is staged, whatever
  produced it. The role does not look at the other global options that can change
  certificate behaviour (an `auto_https` setting, an issuer in the global block), nor
  at a `tls` line inside an upstream transport, which would fail closed. The owner
  still diffs the candidate against the live edge, and places the token, before any
  go-live step. The role does not create or check `/etc/branchleft/secrets`: if the
  owner has not made it, the token reads as missing and the candidate is not staged.
- **The slot directories `/opt/branchleft/demo-<n>`** are made by the wrapper's
  `reset`, which this role never runs. They do not exist after the role.
- **The egress interaction is unverified.** The demo host's egress ruleset
  (`branchleft_demo_egress.sh`, ghost-platform) is not applied here, and the merged
  `egress_nat` role inserts NAT rules on the forward chain. Their interaction has
  not been checked, so the first converge of demo1 waits for that check.
- **The uid register has no lock** against a concurrent tenant allocation.
  The role consumes it as it is.
- **The first apply's expected difference** from the host as the runbook left it at
  its pinned commit (`fb2f064`): the sidecar and the health router are replaced by the
  pinned versions (the drain-flag path fix); everything else the role declares
  already matches. A running health router keeps the old code until the owner
  restarts it.
- **Ticket order.** The ticket for the demo-host work after this one lists this build
  as a dependency while `broker_deploy` (its real prerequisite) is merged: the
  recorded graph is inverted. The build order in this README is the correct one.

## How it is delivered

Delivery to a host is ANS-17: only the gated workflow, run against `main` after the
approval of its protected environment. The plan job shows the host's diff in check
mode first. Nothing is applied from a laptop. This role is not applied to any host
yet. `ansible/playbooks/demo1.yml` enrols demo1 on the signed push route and lists this role
after `pull_trigger`. The host has no inventory entry: the playbook and its trust file enrol it.
The commit reaches the host by push, which needs shared-infra#511 (not yet merged), so the role
is applied only after that lands. The first live run is check mode; the apply waits on the owner.

The playbook `ansible/playbooks/demo1.yml` refuses any host but demo1. It does not
apply `broker_deploy`, whose inputs are the owner's built bundle and public key.
The trap of a `dependencies` entry (a role applied before its own inputs exist) is
therefore not reachable from this role.

## How to change it safely

1. To change the release, change `demo1_build_source_sha`, the files under
   `files/ghost-platform` and every checksum in `demo1_build_release_files`
   together, in `defaults/main.yml` and in `meta/argument_specs.yml` (see "Vendored
   files"). A file that does not match its checksum stops the role before it writes.
2. Keep every task able to run under `--check --diff`. A task that writes a file a
   program owns is skipped in check mode with a stated reason; a task that only reads
   may use `check_mode: false`.
3. A task that writes anything `broker_deploy` owns is wrong: the sudoers grant, the
   `broker` account, the state root and the broker's slots directory are read only.
4. Never run `reset`, the go-live program or a renderer with an output flag from a
   task. A renderer prints to standard output; keep it that way.
5. If a task reports changed on a second run, fix the task with a module,
   `changed_when`, `creates` or `removes`. Never weaken the idempotence step.
6. Run the test command above before opening a pull request, then break the control
   you touched and see the step fail.

## Design notes for the task and scenario files

These notes hold the reasoning that was once in the comments of the task, variable
and scenario files. Each section names the file it belongs to. The code beneath each
comment is the source of truth.

### defaults/main.yml

- The copies under `files/ghost-platform` are of the ghost-platform commit in
  `demo1_build_source_sha`. The same commit names the release directory: the
  role stages the release under the releases directory, in a directory named by
  that commit (`demo1_build_release_dir` in `vars/main.yml`).
- The demo host takes the programs from the signed commit CI pushes to it. The host
  never fetches them from anywhere. Each file is held to its sha256 on the machine
  that runs the role, before the role writes anything to the host.
- A bump changes the files, the commit and every checksum in one change. See
  "Vendored files" and "The pin" above.
- The role also refuses an installed sidecar that does not name the drain-flag
  directory (`tasks/_programs.yml`).
- Nothing in this file is private. The role has no secret input and no required
  input: every value has a default, and the pinned programs are public.

### vars/main.yml

- The generator's output exists only once the release is staged
  (`demo1_build_release_ready`). Until then only the installed grant is cut.
- The header is the leading run of blank lines and comments. It is not compared,
  because broker_deploy's template and the generator word it differently.
- The body is everything from the first line that is not header. It is compared as
  an ordered list: no comment is exempt after the first rule, and nothing is sorted.
- A comment ending in a backslash is not header, because sudoers joins such a line
  to the next. Trailing newlines are dropped before the split, since blank lines at
  the end are inert.

### tasks/_candidate.yml

- The role never runs the go-live program and never runs a slot reset. Opening the
  demo to visitors is the owner's decision. The pinned go-live program makes it, and
  it refuses while a test stand-in is loaded.
- The candidate directory is under the root-owned state root and is root's alone, so
  a root writer cannot be led through a link that someone else planted.
- Nothing reads the candidates automatically. They are evidence the owner diffs
  against the live edge before running the go-live program.

### tasks/_site_candidates.yml

- Each edge input is checked in its own assert, in this order: not a link and a
  regular file, owned by root:root, and mode 0000, 0200, 0400 or 0600. Each failure
  names the input path and never a value.
- The renderer is run with no output flag, so it only reads and writes nothing.
  `failed_when` is off, and its output is hidden, so a refusal is handled by the
  role. A renderer refusal is reported by the occupied slot numbers, never with the
  renderer's message, which can echo a hostname.
- A printed notice says why the production candidate is not staged. The checks run
  in order: the wildcard base is unset, the DNS token is not placed, no release is
  staged, and no slot has an input. The first that applies is the one named.
- Each slot with no edge input gets a printed line. The list of slots that were not
  rendered is sorted, because `difference()` returns them in no fixed order.
- The role never passes the renderer `--gate-env-out`, because that flag writes. It
  never writes the live edge and never runs the go-live program.
- The candidate is staged root-owned, mode 0600, in the candidate directory, and only
  when that directory exists. In check mode it does not exist yet.
- The registered render holds the Caddyfile, so it is emptied at the end of the play.

### tasks/_candidate_refusal.yml

- There is no interim-certificate mode. The one certificate is the wildcard that Caddy
  obtains by DNS-01. A candidate with a `tls internal` directive, a `local_certs`
  option or a `skip_install_trust` option is refused.
- The candidate must hold exactly one `tls` directive, and that directive must be a
  block holding only the role's DNS directive line. It must hold exactly one site: the
  wildcard site of the base.
- The checks are separate asserts, so a scenario can name the one that fired. No
  message names a hostname, and none carries the candidate text.

### molecule/default/stated_skip.yml

- The play is imported twice by `converge.yml`: once with an empty wildcard base and
  once with the token file not placed.
- It runs the site step alone, with the two edge inputs that `prepare.yml` placed. So
  the only reason to stage nothing is the one the case sets.
- It asserts the notice starts with `Production candidate NOT staged: `, and that the
  staged Caddyfile is left as it was found: absent if it was absent, and with the same
  modification time. A silent skip would read as a configured host. A failure would
  stop a plan that has nothing to approve.
- It runs before the role is applied, where nothing is staged.

### molecule/default/converge.yml, the wrapper path control

- A role that only fails does not prove the order. It can fail after the install and
  leave the wrapper live under a refused grant. That is why the control runs the whole
  role, and the probe path is one that does not exist.
- The other refusal cases are in the refusals scenario, so the default scenario applies
  the role only a few times. Its shard is bound by the time limit.

### molecule/refusals/converge.yml

- The refusals scenario does not apply the role. The first play stages the pinned
  programs with the role's own release tasks (`_release.yml`), which holds the
  generator. Every other play runs one task file alone against an edited grant or a
  planted link.
- Links are checked by `refused_link.yml`, which runs `_dirs.yml`.
- This scenario cannot see an install, so whether a refusal comes before the install
  is proved in the default scenario.

### molecule/refusals/refused_candidate.yml

- The pinned renderer cannot be made to print a refused candidate. So the stand-in
  text has the shape the renderer prints for two slots, with one change.
- `converge_case.tls` replaces the wildcard site's tls block. `converge_case.append`
  is added after the text.
- The control case, `converge_case.accepted: true`, runs the unchanged text and must
  pass. That shows the other cases are refused for their change, and not because the
  step refuses everything.
- No failure may carry the stand-in hostname. The failure text is read whole.
- The step writes nothing.

### molecule/refusals/refused_token.yml

- `converge_case.plant` is one of: `link` (a link to a root file of mode 0600),
  `directory`, `owner` (a file owned by `converge_case.owner`, mode 0600), `mode` (a
  root file of `converge_case.mode`), or `empty` (an empty root file of mode 0600).
- `converge_case.expect` is the text the refusal must name. The play also asserts the
  token path is in the message, so no other check may be the one that fires.
- A refusal leaves no Caddyfile behind, and the stand-in token value must not appear
  in the failure.
- The `always` block removes the planted file and target, then puts back the token
  file that `prepare.yml` placed.

### molecule/refusals/refused_site_input.yml

- `converge_case.plant` is one of: `link`, `owner`, `mode`, `valid` or `leak`.
  `valid` is a root file of mode 0600 that the renderer accepts, and the step must stage
  a root-only, mode 0600 Caddyfile from it. `leak` is a root file whose hostname the
  renderer refuses. That hostname is the canary: it must not reach the log.
- The step runs with the wildcard base set, and with the token file and the slot 1
  input that `prepare.yml` placed left as they are. So the valid case renders two
  slots, and no other case is refused for a token or a second input.
- The "Scan control line" debug task is the positive control for the log scan in
  `verify.yml`. The scan reads this run's log, and this line proves that the scan can
  read it, so a scan that finds no canary means something.
- The play is tagged for the idempotence step to skip, because the valid case stages a
  candidate. It is a control, not a state.
