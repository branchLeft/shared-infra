# host_tls_identity

This role gives a host its own TLS identity and tells it which one peer to trust. It exists for
the one scrape that crosses projects: edge1's Prometheus reads demo1's `node_exporter` over
demo1's public address, and each side must prove who it is to the other.

It makes a private key and a self-signed certificate on the host that uses them, and it installs
the peer's public certificate as the file the host's service trusts. There is no certificate
authority and so no authority key to keep: each side trusts exactly one certificate, the other
side's, and nothing else.

This README is written for a maintainer who is new to the repository. It follows the order the
standard sets for a role README (ANS-14).

## What the role does, and what it does not

1. Refuses a host with no row in `host_tls_identity_profiles` (`vars/main.yml`).
2. Installs `python3-cryptography` from the Debian archive. The certificate modules run under
   the host's own interpreter, not the toolchain's virtual environment.
3. Makes the directory, root-owned, mode 0750.
4. Reads any certificate already there. If it has less than 60 days left, or has lapsed, the run
   fails with `host_tls_identity[renew]`. Nothing is changed.
5. Makes the private key once (ECC, secp256r1, mode 0640, `regenerate: never`), on the host, with
   `community.crypto`. It is never read back, copied, fetched or printed, and the task is
   `no_log` and `diff: false`.
6. Makes the certificate request in memory and issues a self-signed certificate valid for 730
   days: `CA:FALSE`, digital signature only, and one extended key usage, `serverAuth` on demo1
   and `clientAuth` on edge1. demo1's certificate carries the name `demo1`, the name Prometheus
   verifies; edge1's carries none.
7. If `host_tls_identity_peer_cert` is set, checks it and writes it as `ca.crt` (below). If it is
   empty the role writes none and says so.

It does not reach another host, does not make a CA, does not renew a certificate by itself, does
not install or configure the exporter or Prometheus (`node_exporter_public` and the monitoring
stack read the files), and never writes a key anywhere but its own path.

### What a pin must be

The owner's value is refused, and `ca.crt` is left exactly as it was, unless it is:

| Code                                 | Requirement                                                              |
| ------------------------------------ | ------------------------------------------------------------------------ |
| `host_tls_identity[pin-shape]`       | exactly one PEM certificate, no private key, nothing else                |
| `host_tls_identity[pin-parse]`       | readable as a certificate                                                |
| `host_tls_identity[pin-self-signed]` | subject and issuer are the same name                                     |
| `host_tls_identity[pin-ca]`          | not a certificate authority (`CA:TRUE`): trusting it trusts one key only |
| `host_tls_identity[pin-usage]`       | for exactly the peer's use: `clientAuth` on demo1, `serverAuth` on edge1 |
| `host_tls_identity[pin-name]`        | on edge1, carries the name `demo1` (Prometheus verifies that name)       |
| `host_tls_identity[pin-validity]`    | valid now, and with 60 days or more left                                 |

## Files, per host

| Host  | Directory                           | Key          | Certificate  | Pin (`ca.crt`)             | Group that reads them         |
| ----- | ----------------------------------- | ------------ | ------------ | -------------------------- | ----------------------------- |
| demo1 | `/etc/branchleft/node-exporter-tls` | `server.key` | `server.crt` | edge1's client certificate | left alone (see below)        |
| edge1 | `/etc/branchleft/demo1-metrics-tls` | `client.key` | `client.crt` | demo1's server certificate | `65534`, the container's user |

All three files are root-owned, mode 0640. On demo1 the exporter's own role gives them to the
package's group once the package has made it, and sets the same mode; this role never sets that
group, so the two do not fight.

## Interface

`meta/argument_specs.yml` is the interface. One variable, `host_tls_identity_peer_cert`: the
peer's public certificate as PEM text, set in the host's file in `ansible/owner_vars/`. It is
public data, and no variable of this role is a secret. Paths, lifetimes and each host's row are in
`vars/main.yml`, which a caller's variables do not outrank except by an explicit parameter.

## Requirements

Debian 13, root, the Debian archive reachable for `python3-cryptography` (the role installs it).
It imports no other role (ANS-12).

## What it changes on a host

Under the directory above: the directory, the key, the certificate and `ca.crt`. And one package,
`python3-cryptography`. Nothing else.

Check mode makes no change. On a host that does not yet have the library, or the directory,
check mode installs and makes neither, so the certificate tasks are skipped there with that stated
reason (ANS-10): the first plan shows less than the first apply, and the apply never skips them.

## How it is tested

`tests/unit/` reads the role's files and fails if a key could be fetched, copied or committed, if
the lifetime or the window drifts, if the profiles or paths change, or if a pin check is removed.
The Molecule scenario runs both hosts' rows in one container: it checks the key and certificate
(modes, usage, name, `CA:FALSE`, 730 days), that a second run changes nothing, that every refusal
above leaves the trust file as it was, and that a TLS server using the pin accepts the pinned
client and refuses another certificate. Run it through the harness:
`.venv/bin/python ansible/harness/run_harness.py ansible/roles/host_tls_identity`.

It does not prove that the exporter or Prometheus accept the files; the read-back after the
delivery does (Owner steps, last item).

## How it is delivered

By the gated apply (ANS-17). On demo1 it follows the roles that make the host's accounts and goes
before `node_exporter_public`, which reads its files. On edge1 it goes before `monitoring_stack`,
which mounts its directory into Prometheus, so a run that fails here restarts nothing onto a
missing file. The owner's merge adds it to each host's list and the pin to each host's
`owner_vars` file (`ansible/checks/` and `ansible/owner_vars/` are the owner's).

`ansible/checks/test_edge1_prometheus_tls_files.py` holds edge1's Prometheus config to this role:
every TLS file the config names must be one the role writes on edge1, and the config may name the
pin only once `host_tls_identity_peer_cert` is set in `owner_vars/edge1.yml`.

## How to change it safely

- A change to a profile's path moves the file its consumer reads: change the consumer in the same
  pull request, and `tests/unit/` names each path so the change is seen.
- Keep `regenerate: never` on the key. A regenerated key invalidates the peer's pin.
- Do not add a `delegate_to`, a fetch or a copy of the key. The unit tests refuse them, and the
  design depends on there being none.

## Owner steps

The one hand step left is reading a host's public certificate off it and putting the text in the
repository for the other host. It is the same shape as carrying `tunnel_account`'s public key. The
certificate is public; the key is never touched.

**First time, after the first gated apply that includes the role on both hosts**

1. Read demo1's certificate. On demo1, as root:

   ```text
   openssl x509 -in /etc/branchleft/node-exporter-tls/server.crt -noout -fingerprint -sha256 -enddate
   cat /etc/branchleft/node-exporter-tls/server.crt
   ```

   Note the fingerprint. Put the whole `cat` output, one `-----BEGIN CERTIFICATE-----` block, as the
   value of `host_tls_identity_peer_cert` (a `|` block) in `ansible/owner_vars/edge1.yml`.

2. Read edge1's certificate the same way, from `/etc/branchleft/demo1-metrics-tls/client.crt`, and
   put it in `ansible/owner_vars/demo1.yml`.
3. Merge both. The next gated apply writes `ca.crt` on each host.

What good looks like: the apply's second run reports no change, and on each receiving host
`openssl x509 -in <directory>/ca.crt -noout -fingerprint -sha256` prints the fingerprint you noted
on the other host. A refusal (`host_tls_identity[pin-...]`) names what was wrong and leaves
`ca.crt` as it was.

**Renewal, once in two years**

From 670 days after the first apply the run fails on that host with `host_tls_identity[renew]`
(60 days left), and the peer fails with `host_tls_identity[pin-validity]` at the same time. Nothing
stops serving meanwhile. To renew, on the failing host, as root:

```text
rm /etc/branchleft/node-exporter-tls/server.crt
```

(edge1: `rm /etc/branchleft/demo1-metrics-tls/client.crt`). The key stays. The next gated apply issues a
new two-year certificate with the same key. Read it as in step 1 and replace the peer's value in
`owner_vars`; the apply after that writes it. What good looks like: the run is green on both hosts and
the fingerprints agree. Until the new value is applied, the peer still trusts the old certificate, so
do the two applies close together.

**Read-back, once the exporter and Prometheus use the files**

On edge1, the monitoring query `up{host="demo1"}` returns 1, and a scrape from anywhere else, with no
certificate, is refused. That is the check that the two services accept these files.
