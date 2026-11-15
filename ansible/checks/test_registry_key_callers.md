# test_registry_key_callers.py: every pull or run of an image takes the registry read key's directory

A private image is pulled with the host's read key, which docker finds through `DOCKER_CONFIG`.
The directory is one constant, `deploy_verifier_registry_docker_dir`. A role imports no role
(ANS-12) and `deploy_verifier` is applied after some of the roles that pull, so each caller keeps
a copy in its own `vars/main.yml` (`<role>_registry_docker_config`), and this test holds the copies
to the constant. It scans the tasks and handlers of every role and pattern, so a new caller is
found and not named by hand. A caller is a task that runs `docker pull`, `docker run`,
`docker create` or `docker compose` with `up`, `run`, `pull` or `create`, a `community.docker`
module that pulls or starts, or a shell script from the role's `files/` that does one of those.
Each caller must set `DOCKER_CONFIG` in its `environment` (or its block's) to
`{{ <role>_registry_docker_config }}`, the variable must sit in `vars/` and equal the constant, and
no task file may hold the path as a literal. A role whose templates name `*_IMAGE=` lines for a
program to run (the restore drill) must carry a unit drop-in with the same `Environment=` line, or
a static unit under `files/` that sets `Environment=DOCKER_CONFIG=` to the constant's value (the
mail collector and the safety service).
Programs under `hetzner/provision` that pull (`branchleft-compose@.service`) must name the
constant's value in an `Environment=` line. A `docker compose up` in a `systemd` drop-in under
`hetzner/*/systemd` inherits the unit's `Environment=` and is not scanned.

A task that sets the directory and nothing else keeps whatever `no_log` it already had: the
directory is a path, and the tasks that read the key's content stay in `deploy_verifier`, where
they are `no_log` and `diff: false`.

The test is shown red on a synthetic tree for each rule, and red on the real tree with a pulling
task added to a role and green once it was removed. A new caller adds the line and the variable in
the same change, or the test names it.
