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

The database mounts the directory `postgres/` (holding `pg_hba.conf` and nothing else) into the
container and selects the file inside it with `hba_file`, not the single file: a delivered file
replaces the old one by rename, which a single-file bind mount does not follow. The test reads
that wiring through `hba_wiring()`, which the real-server test uses too.

`pg_hba.conf` is read against one table, `EXPECTED_DATABASES`: the sign-in
service's login on its own database, the portal's three logins (tenant, owner and
provisioner) on the portal database, and the administrator on the three databases,
and nothing else. The provisioner is the login the provisioning program connects
as after its transaction commits, so it needs a rule as much as the other two.
`test_control_plane_hba_server.py` starts a real server on the file and connects
against the same table.

The two applications read their trusted proxy list (`PORTAL_TRUSTED_PROXIES`,
`CONSOLE_TRUSTED_PROXIES`) from their container environment. The env file only fills `${VAR}`
references in the compose file, so a variable the compose file does not name never reaches them.
The tests require both variables in the applications' `environment:`, equal to the edge's
private address read from `hetzner-host/addressPlan.ts` (`HOST_IPS.edge1`) and not copied here,
and require the address to be written once in the compose file, shared by an anchor.

Bump `EXPECTED_TEST_COUNT` in `test_suite_size.py` with any change here.
