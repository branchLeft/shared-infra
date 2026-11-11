# read_sending_state.py

A read-only report of what Stalwart on mx1 holds for sending: the domains,
their DKIM keys (selector and stage only), the mailbox accounts, and whether
the postmaster, abuse and complaints role addresses exist as mailboxes.

## Running it

It takes no arguments and is piped to the host's Python in isolated mode,
from a copy of the merged file:

    python3 -I - < read_sending_state.py

It needs the admin credential at `/root/.stalwart-admin-credentials` (read the
same way as `provision_sending_domain.py`) and the loopback API at
`http://127.0.0.1:8080`. It must run as root on the mail host.

## What it prints

Sorted lines, then three summaries and one note:

    dkim <domain> <selector> <stage>
    domain <domain>
    mailbox <local-part>@<domain>
    postmaster: present as mailbox|absent
    abuse: present as mailbox|absent
    complaints: present as mailbox|absent
    accounts without a matching domain: <count>
    aliases: not read (...)

An account with no `domainId`, or one naming a domain that was not read, is
skipped and counted on that line; the report does not fail for it.

The role checks look only at `branchleft.co.uk` mailbox accounts. A Stalwart
alias is a list field on an account, and this script does not read it, so
`absent` means no mailbox, not no alias.

On any failure it prints one `read_sending_state: <reason>` line to stderr and
exits 1. The reason is one of a fixed set of messages, or the Python exception
class name. No traceback, no URL and no response body is ever printed.

## What it never does

- It sends only `x:Domain/get`, `x:DkimSignature/get` and `x:Account/get` in one
  JMAP request. `assert_read_only` refuses any method not ending in `/get`
  before a byte is sent, and the unit tests check the request list.
- Each read names its fields (`properties`), so `privateKey` and `publicKey`
  never enter the process. Empty proxy handler: `http_proxy` is ignored.
- It never prints a credential, a `privateKey` or a `publicKey`. The tests feed
  fake values for each and assert none of them reach stdout or stderr.
- It is self-contained: it imports nothing from the provisioning modules, so
  the single file can be piped over ssh.

## Tests

    cd mail/provision && python3 -B -m unittest test_read_sending_state -v

The tests run against a fake JMAP reply. No host, no network.
