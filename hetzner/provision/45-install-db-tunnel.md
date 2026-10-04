# 45-install-db-tunnel.sh and branchleft-db-tunnel.service

## Module overview

`db1`'s half of the tunnel that lets the tenant database host replicate the
blog's database during its migration. MySQL replication is started by the
replica, and the replica lives in the tenants project, which may not open a
connection into the org project. So `db1` opens the connection instead: an
outbound `ssh -R` that publishes `db1`'s MySQL port on the replica host's
loopback. MySQL still sees an ordinary replica-initiated stream.

The replica host's half, the restricted account this unit logs in as, is
`db/tunnel/tunnel_account.py` in `branchLeft/ghost-platform`, with the
control-case probes and a container proof beside it.

Deliberately outside `run-all.sh`, like `40-install-node-exporter.sh`: this
runs on `db1` only, by hand, for the length of the migration. The install
runbook is in `branchLeft/ghost-platform-docs`.

## The two subcommands, in order

1. `keygen` creates the system user `dbtunnel` (shell `nologin`, no home) and
   an ed25519 key at `/etc/branchleft/db-tunnel/id_ed25519`, owned by that
   user, mode `0600`, and prints the public half. An existing key is kept.
2. The replica host installs its account with that public key and prints its
   own host key.
3. `install <replica IPv4> '<ssh-ed25519 host key>'` pins the host key in
   `/etc/branchleft/db-tunnel/known_hosts`, writes `target.env`, installs the
   unit byte-identical to the committed file, and starts it. A re-run with
   nothing changed and the unit running is a no-op.

The replica address must be public: `db1` reaches it through `edge1`'s NAT,
so a private address is a mistake, not a choice. The host key must be the bare
`ssh-ed25519 <base64>` the replica host printed. A comment or another key
type is refused, so nothing but that one key is ever trusted.

`DB_TUNNEL_SOURCE_ADDRESS` is found on the host (the one address in
`10.20.1.0/24`), never passed in. mysqld binds that address only, so it is
both the forward's target and the address the metrics forward listens on.

## The unit

```bash
ssh -N -R 127.0.0.1:13306:<db1>:3306 -L <db1>:9105:127.0.0.1:9104 dbtunnel@<replica>
```

- `-R` publishes `db1`'s `10.20.1.20:3306` on the replica host's
  `127.0.0.1:13306`. The replica's `SOURCE_HOST` is `127.0.0.1`, port `13306`.
  mysqld on `db1` sees the connection come from `10.20.1.20`, which the
  container proof read back, so the replication account is
  `'<user>'@'10.20.1.20' REQUIRE SSL`. `require_secure_transport` is on, so the
  replica uses `SOURCE_SSL = 1`.
- `-L` publishes the replica's mysqld_exporter on `db1`'s `10.20.1.20:9105`,
  where `edge1`'s Prometheus scrapes it (`../monitoring/render.ts`,
  `MONITORED_REPLICA_HOST`). The scrape only succeeds while the ssh session is
  up, which makes it the tunnel's own liveness signal.
- `ExitOnForwardFailure=yes`: a forward that cannot bind ends the process
  rather than leaving a half-working session.
- `ServerAliveInterval=10`, `ServerAliveCountMax=3`: a dead link is noticed in
  about 30 seconds and ssh exits.
- `Restart=always` with `StartLimitIntervalSec=0`, `RestartSec=5`,
  `RestartSteps=6`, `RestartMaxDelaySec=120`: systemd restarts it forever,
  backing off from 5 seconds to 2 minutes. Needs systemd 254 or later; Debian
  13 has 257. No `autossh`: the keepalives detect, systemd restarts.
- `-F none`, `IdentitiesOnly`, `IdentityAgent=none`, `BatchMode`,
  `StrictHostKeyChecking=yes` with a `known_hosts` of its own: no other config,
  key, agent or host is ever used, and a changed host key stops the unit.
- Runs as `dbtunnel`, not root, with the usual sandboxing.

## What the replica sees when the tunnel is down

The IO thread goes to `Connecting` and retries on its own
(`SOURCE_CONNECT_RETRY`), and `Seconds_Behind_Source` reads NULL. Nothing is
lost: `db1` keeps its binary logs for 7 days (`binlog_expire_logs_seconds`),
and the replica resumes from its own position once the unit is back. The
container proof wrote a row during an outage and saw it arrive afterwards.

## Teardown

After the migration's cutover, stop and disable the unit, then remove it,
`/etc/branchleft/db-tunnel/` and the user. Remove the scrape target in the
same change, or `ReplicaTunnelDown` fires.
