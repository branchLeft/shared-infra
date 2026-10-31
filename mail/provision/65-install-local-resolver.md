# 65-install-local-resolver.sh

Installs unbound as a loopback-only, fully recursive resolver for mx1.

Spamhaus's free DNSBL tier answers 127.255.255.254 -- "query blocked" -- to
anything arriving from a high-volume shared resolver, which Hetzner's own
and every public one (8.8.8.8, 1.1.1.1) are. Only a resolver that walks the
root servers itself, from mx1's own address, gets real reputation data
back. So this config has no forwarders at all: adding one silently
reintroduces the exact failure this script exists to remove.

/etc/resolv.conf is deliberately left as-is -- Debian's
unbound-resolvconf.service would otherwise point the whole box at unbound
on install, a far wider blast radius than the DNSBL check needs. It is
masked before the package is installed and the file is verified unchanged
afterwards. See mail/RUNBOOK-mx1-provision.md's "Local recursive resolver"
section.

Idempotent: package install skipped when present, config compared
byte-for-byte before writing, service only restarted when something
actually changed.
