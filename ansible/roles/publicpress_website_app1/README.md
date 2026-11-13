# publicpress_website_app1

This role puts the publicpress.co.uk website Compose stack on `app1` the way
[`website_app1`](../website_app1/README.md) puts the branchleft.co.uk site there: it writes the
stack's SMTP environment file, copies the compose file, enables the stack's unit, and, when given
an image, has the host's deploy program pin that digest and restart the stack, then smoke tests
the app.

It is a copy of that role with the stack's own names, one port of its own and one container
instead of two. The differences are named under "What is different, and why".

## What the role does

1. Refuses, before anything is written, a project path, an environment path or an image that is
   not a plain absolute path or an image of `ghcr.io/branchleft/publicpress-website` pinned by
   digest, and an SMTP value that is empty or not printable ASCII.
2. Creates `/etc/branchleft` (root, `0755`), the directory the stack's unit reads its secrets from.
3. Writes `/etc/branchleft/publicpress-website.env` (root, `0600`, no backup) with four lines,
   `PUBLICPRESS_SMTP_HOST`, `PUBLICPRESS_SMTP_PORT`, `PUBLICPRESS_SMTP_USER` and
   `PUBLICPRESS_SMTP_PASSWORD`.
4. Creates `/opt/branchleft/publicpress-website` (root, `0755`) and copies `files/compose.yml`
   into it (root, `0644`).
5. Enables `branchleft-compose@publicpress-website.service`. It does not start it.
6. When `publicpress_website_app1_image` is set and the content differs from the content last
   deployed (a digest of the image and the compose file), runs
   `sudo -n /usr/local/sbin/branchleft-deploy publicpress-website <image>` with argv, not a shell,
   then requests each path of `publicpress_website_app1_smoke_paths` from
   `http://10.20.1.100:8081` until it returns 200.
7. Records a stamp file (root, `0600`) only after step 6 has passed, so a run that fails part-way
   deploys again on the next run.

It never writes an image reference of its own, never writes
`/etc/branchleft/publicpress-website.image.env` (the deploy program does), and never removes a
volume.

## The port

The app listens on `10.20.1.100:8081`, the private address of `app1`. 8081 is the next port after
the branchleft.co.uk site's 8080 that nothing on app1 uses. What was checked: the compose files of
every role (the branchleft.co.uk site binds 8080 and 9092), the `app1` entries of `sites.ts`
(8080, and the tenant's 8101), the monitoring targets on `10.20.1.100` (9092, 9100) and the
tenant range, which starts at 8100. `tests/unit/test_publicpress_website_app1_contract.py` fails
when another stack, edge site or monitoring target takes 8081, and when the compose file, the
healthcheck and the smoke test stop agreeing on it. The edge does not know this port yet: no site
in `sites.ts` points at it.

## Inputs

See [`meta/argument_specs.yml`](meta/argument_specs.yml). The four SMTP values are required, have
no default, and the password is `no_log`. They are not passed to the role: `vars/main.yml` sets
each `publicpress_website_app1_smtp_*` to the matching `website_app1_smtp_*`, the branchleft.co.uk
site's own, because the owner ruled that this app reuses that SMTP login. The `host_inputs` loader
sets those once for the whole play from the host's inputs file, so this role adds no input, no
key to the loader and no secret. For the same reason the secret table of
`patterns/secrets_and_no_log/README.md` gives the password the source `none`: no loader row feeds
it under this role's name. `publicpress_website_app1_image` is empty by default, which means no
deploy and no smoke test.

## Requirements

- The host has the Docker CLI and Compose plugin, `branchleft-compose@.service` and the deploy
  program `/usr/local/sbin/branchleft-deploy`, installed by the host provisioning and the
  `deploy_tooling` role, not by this role.
- The deploy account can run that program with `sudo -n`.

## How it is delivered

It is applied by app1's pulled playbook (ANS-17), after the two pull roles, `host_inputs` and
`website_app1`. The play gives it no image, so the role writes the environment file and the
compose file, enables the unit, and does not deploy, restart, smoke test or write a stamp. The
image is delivered by the `branchLeft/publicpress-website` repository's CI deploy job.

## The deploy slot

The deploy job's key is a deploy slot, not the host-level deploy key the branchleft.co.uk site's
CI still uses: its `authorized_keys` line forces the command
`sudo -n /usr/local/sbin/branchleft-deploy --slot publicpress-website`, so the key can deploy
this stack and nothing else, and the image digest is read from standard input. Nothing in this
repository lists slots: they come from the `deploy_slot_keys_slots` input of the host's inputs
file (`roles/deploy_slot_keys/README.md`). The entry for this stack must set `adopt_existing` to
`true`, because this role, which runs before `deploy_slot_keys`, has already made
`/opt/branchleft/publicpress-website` when the slot is first granted, and the slot program refuses
a stack that already exists unless it is adopted.

## What is different, and why

- One service, not two. The branchleft.co.uk stack has a second container for the contact form's
  metrics counter. This app has none, so there is no metrics port and no shared volume.
- The healthcheck runs `node` and fetches the app's own port, so it needs no `wget` in the image.
  The deploy program refuses a stack whose service declares no health signal.
- The smoke test asks `/` only. The branchleft.co.uk site's `/about` and `/contact` are that
  site's routes.
- The compose file is not built from the `compose_stack` pattern, for the reason `website_app1`
  gives: that pattern refuses a compose file whose image is not pinned by digest at rest, and this
  file names `${IMAGE}`, which `branchleft-deploy` writes as a digest into the unit's environment.
- The CI steps that write the deploy key on the runner, pin the host key and remove the key are
  not in the role. They exist only because CI reaches the host over SSH with a key it holds.

## What the test proves, and what it does not

The Molecule scenario runs in a systemd container with no Docker. Its converge first gives the
role a tag in place of a digest, the other website's image, and a tab in an SMTP value, and checks
each refusal names its rule and writes no file. Then it applies the role with sentinel values and
verifies the directories, the compose file byte for byte against `files/compose.yml`, the
environment file's mode, owner and exact content, the absence of a stamp, and an enabled unit that
was not started. A second apply must report zero changes (idempotence).

The unit tests hold the port, the health signal and the inputs as described above.

It does not prove the deploy path or the smoke test. Those need Docker and the host's program, so
they are proven only by a live run on `app1`.
