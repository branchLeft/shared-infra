# test_ci_login_pins.py: the ci_login copies and the missing source limit

The `ci_login` role carries its own copy of the key shapes of the `sudoers_and_keys` pattern
and of the trigger program's path, because a role may not call a pattern or another role
(ANS-12). The test fails when either copy differs from its home
(`sudoers_and_keys_key_shapes`, `pull_trigger_program_path`), when the sudoers lines are
anything but the `env_keep` line and the two-command grant, and when a source address option
(`from=`, `from_addresses`, or an interface option with `from` in its name) appears in the
key template, the tasks, the variables or the argument spec. The owner accepted keys with no
source limit; this keeps that visible, so a limit is added by an owner ruling that changes
the test too. Each pin runs red on a sabotaged copy of its files and green once the file is
put back.
