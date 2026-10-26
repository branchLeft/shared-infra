# list_and_clear_blocked_ips.py

## Scan-ban listing and clearing

Lists IPs Stalwart's own built-in scan-ban has blocked, and optionally
clears specific ones -- see mail/RUNBOOK-mx1-provision.md's "Scan-ban"
section for why this fires on nothing more hostile than an operator's own
verification commands, and why a blanket clear is dangerous: a genuinely
malicious scanner blocked alongside an operator's own false-positive would
get released too.
