# test_40_install_node_exporter.py

## Module overview

This is the installer `RUNBOOK-monitoring.md` runs against ops1 (section 15) and db1 (section 17), and its two
silent failure modes are exactly the ones worth a test rather
than a smoke check: a corrupted or substituted download getting installed
anyway, and a host with no estate-private address getting node_exporter
bound to its public interface -- the one thing every exporter in this
estate's firewall posture (hetzner-host/firewalls.ts) depends on never
happening.

The script talks to the network (`curl`), the package/user database
(`useradd`, `id`) and `systemctl`, none of which a test process may touch for
real, and it chowns installed files to `root:root`, which a non-root test
process cannot do either. All four are substituted: `curl`, `useradd`, `id`,
`ip` and `systemctl` are fakes earlier on `PATH`, `NODE_EXPORTER_OWNER`/
`_GROUP` are overridden to the test's own user so `install -o/-g` succeeds,
and every filesystem destination is redirected into a temporary directory via
the script's own override variables.
