# test_no_new_hand_installers.py: the hand installers stay frozen

A hand installer is a bash script under any `provision/` directory, or under `hetzner/scripts`.
Each one is listed in `hand_installers.yml` with a reason: `stays-as-code`, or `pending-role`
naming the role that will replace it. The test walks the tree and fails on a script that is not
listed, and on an entry whose script is gone. The list is the baseline as it stood when the guard
was added, so a new installer needs a reviewed entry, which is an owner merge under CODEOWNERS.
The test reads the role name and does not check that the role exists, as `host_roles/` does.
