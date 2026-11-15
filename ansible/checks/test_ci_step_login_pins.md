# test_ci_step_login_pins.py: the step account's one command, one key and one list

The `ci_step_login` role gives the step account root-run sudo for one argument list and writes its
one key line. The role copies the ed25519 key shape of the `sudoers_and_keys` pattern and the
trigger program's path (ANS-12), so the test holds both to their homes. It fails when the sudoers
lines are anything but the `env_keep` line and the one `--mode step` grant (a wildcard, a second
command, a third line, or a step id or word named in the role); when the key template drops
`restrict`, the `from` option or the forced command, or names another mode; when the key task is
not exclusive or loses `no_log`/`diff: false`; when the sudoers task hides its diff or its `visudo`
validate; when the address pattern accepts a wildcard, a name, a negation or a range wider than
`/24`, or the key pattern accepts another type, a cut-short body, leading options or a trailing
line break; when the interface grows past the key and the addresses; when ops1's key or source is
not the owner's pinned value; and when ops1's step list holds an id or a word the sender
(`ansible-gated-step.yml`, whose shapes are copied in the test) would refuse, or not exactly the
three steps. Each pin runs red on a sabotaged copy of its files and green once the file is put back.
The sudo half is proved in the role's container scenario, not here.
