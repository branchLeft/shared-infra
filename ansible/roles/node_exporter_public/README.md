# node_exporter_public

This role installs the Debian archive's `prometheus-node-exporter` on a host that has no
address in the estate subnet, and makes it answer only a client that presents the one client
certificate it is pinned to. It is for `demo1`, which is in a Hetzner project of its own and shares no private
network with the monitoring host, so its exporter is scraped over its public address.

This README is written for a maintainer who is new to the repository. It follows the order the
standard sets for a role README (ANS-14).

## Why a role of its own

The estate's `node_exporter` role downloads a pinned release from GitHub and binds the host's
estate-subnet address. demo1 may fetch nothing from the network (`test_demo1_no_github_fetch`
refuses `get_url` and GitHub in any role the host applies), and it has no estate-subnet address. The
Debian 13 archive carries `prometheus-node-exporter` 1.9.0, which supports the web config file
(`--web.config.file`, since 1.0), so this role installs that package with `apt` and fetches
nothing. It imports no other role (ANS-12).

## What the role does

1. Looks for three files in `/etc/branchleft/node-exporter-tls/`: `ca.crt`, `server.crt` and
   `server.key`. Until all three are regular files it installs nothing and says so, so no exporter
   ever starts without its certificates.
2. Holds the unit masked (the symlink to `/dev/null` that `systemctl mask` makes) when the package
   is not yet installed. The package's own postinst starts the service at once, in plain HTTP on
   every address, and this is what stops that.
3. Writes `/etc/default/prometheus-node-exporter` with the arguments
   `--web.listen-address=:9100 --web.config.file=/etc/node-exporter/web-config.yml` before the
   package is installed, so the package's own copy of that file never replaces it.
4. Installs the package.
5. Gives the certificate directory and the three files to the package's `prometheus` group, modes
   0750 and 0640, root-owned. Check mode skips these two tasks with a stated reason (ANS-10): it
   installs no package, so the group does not exist yet on a new host.
6. Writes `/etc/node-exporter/web-config.yml`: TLS 1.3 only, the server certificate and key, and
   `client_auth_type: RequireAndVerifyClientCert` against `ca.crt`. It holds paths and no key.
7. Releases the mask, only if it is a link to `/dev/null`, so a unit file an operator put there
   is never removed. Then it loads systemd, restarts the exporter on a change, enables it and
   starts it.

The listen address is every address of the host, because the host has no estate-subnet one. The
cloud firewall (`infra/demo-host/firewall.ts` in ghost-platform) admits port 9100 from edge1 only,
and the client certificate is the control that holds even if that rule is ever wrong.

## Inputs

None. The paths, the port and the package name are in `vars/main.yml`. No variable is a secret.

## Where it is applied

`demo1`, last, in `ansible/playbooks/demo1.yml` and `ansible/checks/host_roles/demo1.yml`.

## What the role leaves out, and why

- **Any certificate or key.** The role ships none and makes none. `host_tls_identity` makes demo1's
  key and self-signed server certificate on the host, and writes `ca.crt`: not a certificate
  authority but the one client certificate edge1's Prometheus presents (self-signed, `clientAuth`
  only), which the owner supplies from the repository. `client_ca_file` names it, so the exporter
  trusts that certificate and nothing else. The server certificate carries the name Prometheus
  verifies (`demo1`, in `hetzner/monitoring/render.ts`) as a DNS name and `serverAuth` only, so it
  cannot be used as a client certificate.
- **The `expected_up` flip.** That is a change to the monitoring render, made once the exporter
  is read back answering live.

## What the test proves, and what it does not

The unit tests (`tests/unit/`) read the role's files and fail if the exporter could start in
plain HTTP (the mask and ARGS-first order), if the client certificate check is weakened, if the
role fetches from the network, or if a PEM block is committed.

The Molecule scenario runs the role in one systemd container on Debian 13 with throwaway keys made in
the container, as `host_tls_identity` makes them: self-signed, with the client certificate pinned as `ca.crt`. Its `verify.yml` reads the package version, the files and their modes, the arguments
and the web config, and asks systemd that the exporter is active and enabled. It then scrapes
port 9100 four ways: the pinned client certificate answers 200, and no certificate, another
self-signed client certificate, and plain HTTP do not.

It does not prove that the real certificates, the firewall rule or Prometheus's scrape from edge1
work together on demo1; the read-back after delivery does.

## Owner steps

None of its own. The files are made by `host_tls_identity`, which goes before this role on demo1
(its README, "Owner steps", says how the owner carries each host's public certificate to the other).
The role installs nothing until all three files are in `/etc/branchleft/node-exporter-tls/`: `server.key`
and `server.crt`, which `host_tls_identity` makes on the first apply, and `ca.crt`, the pinned edge1
client certificate, which it writes once the owner has put that certificate in demo1's `owner_vars`
file. `/etc/branchleft` is made by `host_inputs`, which goes first on demo1: root's, mode 0755, so the
exporter's account can reach the directory the role opens to it. What good looks like: the exporter's
unit is active on the host, and a scrape with edge1's client certificate answers 200 while one without it
does not.
