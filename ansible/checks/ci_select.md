# ci_select.py: which shards a run executes

`ci_select.py` narrows the shard list from `ansible/harness/list_shards.py` to the shards a
run needs, from the event and the files it changed. The rules, in the order they apply:

- the daily scheduled run and a manual run execute every shard, whatever changed: they are
  what finds drift in an external image or collection, which no diff shows;
- a push to `main` executes none, and runs no lint: the pushed tree is the tree the merge
  queue tested, and the delivery workflow runs its own checks before it applies anything
  (`delivery_select.py` picks its shards, with these same rules; see `delivery_select.md`);
- a pull request is compared with the commit it would merge into, not with the base sha
  of the event, which goes stale as the branch moves and then lists other pull requests'
  files. The checkout is the test merge: when HEAD has exactly two parents and the second
  is the pull request's head, the diff is taken from the first parent. In any other case
  the event's base is used, which lists more files, never fewer;
- a pull request or a merge-queue entry whose base commit is unknown, or whose changed
  files are not listed, executes every shard. The queue entry's changed files are the diff
  from its `base_sha` to its `head_sha`, so a shared file in that diff executes every shard,
  as it does in a pull request. An entry stacked on another is tested on that one's tree
  and diffed from it; if the earlier entry leaves the queue, the later one is tested again.
  The selection is still made for a queue entry, but the shard job's condition skips the
  shards in the queue (the pull request already ran them), so only the lint runs there;
- a changed file that is part of the harness, the lock, the lint config, or one of the three
  checks files the shards read (`ci_select.py`, `check_pins.py`, `pip-requirements.txt`)
  executes every shard, because it decides what every role is held to;
- any other file in `ansible/checks/` runs the lint job only, because lint runs its tests and
  no shard reads it;
- a changed file under `ansible/` that nothing here recognises executes every shard,
  because a new kind of file must be named in the program before it may skip a shard;
- a changed file in a role or pattern executes that role's or pattern's shards, and the
  shards of every role or pattern that reaches it, followed to the end (a cycle ends). A
  role reaches another when a file of it names it textually (`branchleft.name`, `../name`,
  `roles/name`, `patterns/name`, a README included), or when the structured scan reads one
  of these:
  - `include_role` or `import_role` (block, inline `{name: x}` or `name=x`), and a play's
    `roles:` or a role's `dependencies:` (`- x`, `- role: x`, `- { role: x }`, an inline
    list), naming `branchleft.x`, a bare `x`, or a path ending in `x`. A `{{ variable }}` is
    followed through the same role's own definitions of it (each must resolve, three deep);
    a `{{ playbook_dir }}` path is tried from the file's directory and each one above it up
    to the role's root; a name built with a trailing `~ "/x"` names `x`;
  - `import_playbook`, when the file it names lies in another role or pattern;
  - `notify:` of a handler that the role does not define itself (by `name:` or `listen:`)
    but another role or pattern does;
  - a symlink in the role whose target lies in another role or pattern;
- a changed file outside `ansible/` executes the shards of every role or pattern that
  reads it;
- a reference the scan cannot map to a role or pattern executes every shard whenever a role
  or pattern changed: a collection role, a name that is not a role here, a variable with no
  literal definition, a playbook outside any role, a handler defined nowhere, a symlink that
  is dangling, leaves the repository or points at a file under `ansible/` that no rule names,
  a line that names `include_role`, `import_role` or `roles:` in a form the scan does not read
  (a flow-style task, `action: include_role name=x`, a quoted key), and any file the scan
  cannot read. Such a reference may be a way the changed role is
  reached that the selection cannot see. A change that selects no role (a README, a
  lint-only file) still executes no shard, and the log names the first few such references.
  `test_ci_select.py` holds the real tree to none, so a new templated role name that the scan
  cannot place fails there before it sends every pull request to every shard; make the name
  literal, or give it through a variable of the same role with a literal value.

A shard that is wrongly left out is a gate that passes without running, so every rule
above errs towards running more.
