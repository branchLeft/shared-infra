# test_ci_jump_hosts.py: one role on edge1 and edge-t, and the two address rules

Two hosts apply `ci_jump`: edge1 and edge-t (`edget`, both in `JUMP_HOSTS`). The real-sshd proof in
the role's `molecule/default` (a destination not on the list is refused) covers both only if the role
is the same on both. The test fails when a jump host does not apply the role exactly once as a plain
role entry (no `when`, `vars` or `tags` on it), and when any part of the role that runs on a host
(tasks, templates, vars, defaults, meta, library, handlers, files) names the host or a group of
hosts (`enrolled_host`, `inventory_hostname`, `groups`, `hostvars` and the like). It also holds the
2 Nov ruling on the data: a tenants private address (read from `TENANTS_HOST_IPS` in
`hetzner-host/addressPlan.ts`, its one home, never copied) in `owner_vars/edge1.yml` is refused, so
the runner can only reach a tenants host through edge-t; edget's `ci_jump_own_address`, once set, must
equal `TENANTS_HOST_IPS.edgeT`; and a host that lists destinations must list its own address among
them. It fails when the address plan cannot be read, so an empty parse cannot let a list through. It
does not see edge-t's public address, which is in no file of the repository, nor whether a listed
address is the right one. Each pin runs red on a sabotaged copy of its files and green on the copy
left alone.
