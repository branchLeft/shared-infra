# check-hetzner-projects.py

The module docstring of `check-hetzner-projects.py` kept its summary paragraph; the rest of the narrative, usage notes and rationale is below, unchanged.

Every check here guards a failure that presents as success rather than as an
error, which is the only reason a checker exists for something this small.

**A project directory with no `main`, or the wrong `main`, runs a different
program.** The projects here deliberately share one npm package, so a project
in a subdirectory has no `package.json` of its own and Pulumi walks up to the
package root's. It then reads that file's `"main"` and resolves it against the
_package_ root, so the subdirectory project runs the package's entry point.
Observed directly against Pulumi v3.255.0: a subdirectory project with no
`main` previewed a create plan for the network program's resources, exited 0,
and reported nothing wrong. Naming that same entry point explicitly is the same
fault with a different spelling, so both are rejected.

**Two projects sharing a `name` share a state file.** A DIY backend stores a
stack at `.pulumi/stacks/<project-name>/<stack>.json`, keyed on the name in
`Pulumi.yaml` and not on the directory. Copy a project directory, change
`main`, forget `name`, and `pulumi up` in the copy loads the original's
checkpoint and plans to delete every resource the original created -- part-way
through which the firewall is already gone.

**A project with no pinned backend is operated against whichever backend the
workstation last logged into.** `pulumi login` is global state on a machine, so
the pin is what keeps `pulumi up` in this directory addressing this estate's
state. Two projects pinning _different_ backends is the other half: these
stacks reference each other, and a stack reference resolves inside one backend.

The single-package rule is what the first check depends on, and it carries its
own reason: a provider version is part of every resource's URN, so two packages
pinning `@pulumi/hcloud` differently would put hosts and the network they
attach to behind two provider instances.

    check-hetzner-projects.py [--root DIR]

Exits non-zero, listing every failure. Reads files only; contacts nothing.
