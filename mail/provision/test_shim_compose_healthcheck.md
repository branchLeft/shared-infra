# test_shim_compose_healthcheck.py: rationale

This is the narrative for `test_shim_compose_healthcheck.py`, moved out of its
docstrings so the code file stays within the CMT-3 comment-block limit. Every
fact the docstrings stated is kept here.

## Why the probe must use an IP literal

A Compose healthcheck that probes a name resolving to more than one address
family can race those families against each other: the client tries one, and
only falls back to the other after that attempt is timed out rather than
refused outright. That race can cost seconds even when the server itself
answers in milliseconds, and a `timeout:` sized for the server's own latency
has no margin for it.

The address test asserts every HTTP healthcheck probe committed in
`shim-compose.yml` targets a literal address rather than a name --
`ipaddress.ip_address()` raises on anything that isn't one, which a hostname
like `localhost` is, whether or not it happens to resolve to a single family
today. It is matched by regex rather than a YAML parser, the same way the
sibling suites in this directory and in `hetzner/provision/` do, to stay
stdlib-only.

## What these tests do not prove

The address and drain tests do not prove that the underlying service actually
listens on the family this probes, or that the multi-second stall the probed
name previously produced is gone. Both are host-observable facts this suite
has no access to; the delivery mechanism for this file is a human rsyncing it
to the host, and the healthcheck's own live status after that is what proves
it.

## The second stall: an undrained response

`HealthcheckResponseDrainTests` and `HealthcheckProbeTimingTests` cover a
second, unrelated stall in the same probe: the callback reads `r.statusCode`
but, absent a fix, never drains or destroys `r`. An unconsumed
`http.IncomingMessage` leaves its socket paused, so Node's event loop cannot
empty and the process survives until the _server's_ own `keepAliveTimeout`
(5000ms by default) closes the connection -- comfortably past this
healthcheck's 3s budget even though the server answers instantly.

The static test (`HealthcheckResponseDrainTests`) is what would have caught
that defect; the timing test is a live differential proof for anyone verifying
the fix rather than trusting the pattern match.

## HealthcheckProbeTimingTests: the fixture and the thresholds

The test runs the exact committed `node -e` script against a real local HTTP
server, the same way Docker's healthcheck runs it against the shim. The
server's `keepAliveTimeout` is 6s, deliberately longer than the production
default of 5s, so the stall an undrained response causes (about 7s) dwarfs
any load-induced slowness of a passing probe (0.05s to 0.2s; a bare
`node -e` measured at 151ms and 196ms end-to-end on a quiet machine). The
pass threshold is derived as half of that keepAliveTimeout, so a regression
fails clearly rather than racing the threshold.

A Node server, not Python's stdlib `http.server`, is the throwaway fixture
here even though it adds a second subprocess: the differential this test
relies on is specifically Node's `keepAliveTimeout` behaviour on the _server_
side, and Python's stdlib server has no equivalent knob to reproduce it with.
The client script under test already requires `node` (skip-guarded in the
test file), so this adds no new environment dependency.

The class is skipped, not failed, where `node` is unavailable: this
environment is not guaranteed to have it, and `HealthcheckResponseDrainTests`
is the assertion that must never be skippable.
