# website_app1

This role puts the website Compose stack on `app1` the way the website repository's
deploy job and its runbook did by hand: it writes the stack's SMTP environment file,
copies the compose file, enables the stack's unit, and, when given an image, has the
host's deploy program pin that digest and restart the stack, then smoke tests the app.

It is a port, one step for one step. Where the port differs from the bash it replaces,
the difference is named under "What is different, and why" below.

## What the role does

1. Refuses, before anything is written, a project path, an environment path or an image
   that is not a plain absolute path or an image pinned by digest, and an SMTP value that
   is empty or not printable ASCII.
2. Creates `/etc/branchleft` (root, `0755`), the directory the stack's unit reads its
   secrets from.
3. Writes `/etc/branchleft/website.env` (root, `0600`, no backup) with four lines,
   `CONTACT_SMTP_HOST`, `CONTACT_SMTP_PORT`, `CONTACT_SMTP_USER` and
   `CONTACT_SMTP_PASSWORD`, from four values the play supplies at run time.
4. Creates `/opt/branchleft/website` (root, `0755`) and copies `files/compose.yml` into it
   (root, `0644`). The file is byte for byte `deploy/compose.yml` of `branchLeft/website`
   on `main` when the role was written.
5. Enables `branchleft-compose@website.service`. It does not start it.
6. When `website_app1_image` is set and the content differs from the content last deployed
   (a digest of the image and the compose file), runs
   `sudo -n /usr/local/sbin/branchleft-deploy website <image>` with argv, not a shell, then
   requests each path of `website_app1_smoke_paths` from `http://<private address>:8080`
   until it returns 200.
7. Records a stamp file (root, `0600`) only after step 6 has passed, so a run that fails
   part-way deploys again on the next run.

It never writes an image reference of its own, never writes `/etc/branchleft/website.image.env`
(the deploy program does), and never removes a volume.

## Inputs

See [`meta/argument_specs.yml`](meta/argument_specs.yml). The four SMTP values are
required, have no default, and the password is `no_log`. `website_app1_image` is empty by
default, which means no deploy and no smoke test.

## Requirements

- The host has the Docker CLI and Compose plugin, `branchleft-compose@.service` and the
  deploy program `/usr/local/sbin/branchleft-deploy`, installed by the host provisioning in
  `shared-infra`, not by this role.
- The deploy account can run that program with `sudo -n`.
- The image `ghcr.io/branchleft/website` is public (a platform-owner action, as the
  runbook says).

## Where the secrets come from

The role does not decide where the SMTP values come from. That is the owner's decision
(see `ansible/patterns/secrets_and_no_log/README.md`). Until it is made, no play in this
repository supplies them, and the role must not be run with invented values.

## What is different, and why

- The compose file is not built from the `compose_stack` pattern. That pattern refuses a
  compose file whose image is not pinned by digest at rest. This file names `${IMAGE}`,
  which `branchleft-deploy` writes as a digest into the unit's environment, so the pattern's
  refusal would fail on every correct file. The role copies the file whole instead.
- The CI steps that write the deploy key on the runner, pin the host key and remove the key
  are not in the role. They exist only because CI reaches the host over SSH with a key it
  holds. A gated Ansible path (ANS-17, not built) replaces them, and the role is the part
  that runs on the host.
- The compose validator of `compose_stack` (`docker compose config`) is not run. The file
  needs `IMAGE` and the SMTP variables, which are not known until the deploy, and the test
  container has no Docker.
- The smoke test runs `ansible.builtin.uri` on the host, not `ssh` plus `curl`, because the
  private address is reachable from the host only. It is the same request, with one difference:
  `uri` follows redirects and requires a final 200, where the CI step's `curl -fsS` accepted any
  status below 400, including a redirect that was never followed.
- The runbook's verify step also checks the containers' status and the metrics listener on
  port 9092 (`docker ps`, and the `branchleft_website_contact_form_send_failures_total` line).
  The role does not: its smoke test covers the app port only, and the metrics check stays a
  manual step in the runbook until a later change adds it.

## What the test proves, and what it does not

The Molecule scenario runs in a systemd container with no Docker. Its converge first
gives the role a tag in place of a digest, and a tab in an SMTP value, and checks each
refusal names its rule and writes no file. Then it applies the role with sentinel values
and verifies the directories, the compose file byte for byte against `files/compose.yml`,
the environment file's mode, owner and exact content, the absence of a stamp, and an
enabled unit that was not started. A second apply must report zero changes (idempotence).

It does not prove the deploy path or the smoke test. Those need Docker and the host's
program, so they are proven only by a live run on `app1`, which the ticket's Done-when
asks for and this PR does not perform.
