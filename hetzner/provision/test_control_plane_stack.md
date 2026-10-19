# test_control_plane_stack.py

## Module overview

The `control-plane` stack shares `ops1` with Nextcloud, which has no swap. Two
things have to stay true for that to be safe, and neither shows in review or in
`docker compose config`: every container is bounded, and the bounds together
leave real headroom on what the owner measured as available; and nothing in the
stack names a Nextcloud service or volume, so the two stacks cannot touch each
other.

The other assertions pin the contract the edge depends on (the two published
ports match `sites.ts`; only the host's private and loopback addresses are
published), the separation the portal design depends on (one database login and
one entry point per application), and the secrets rules (every credential read
from the env file and required, no vendor default password for the first
administrator).

The database administrator's credential is pinned out of the running sign-in
service. The runtime service starts from the setup phase and holds only its own
unprivileged login. The administrator's password is read by the `db` service
alone, and the one phase that needs it (Zitadel's `init`) lives in
`compose.init.yml`, an overlay the unit never reads. The tests fail if any
runtime service other than `db` names the credential, if the runtime command
runs the init phase, or if the overlay stops being init-only or takes a name
Compose would load by default.

The memory constants are the owner's measurement of the host, not a vendor
sizing figure. Raising a limit past the margin is a host-size decision, which is
the owner's.

Bump `EXPECTED_TEST_COUNT` in `test_suite_size.py` with any change here.
