# check_delivery.py: C4, the environments of the other workflows

C4 fails when another workflow runs a job in the environment the Ansible apply is approved
in (`ansible-hosts`, compared without regard to case), because one approval would then release
both. It reads the `environment` of every other workflow's jobs, as a job key or as the
`with.environment` of a call, as a string or as a mapping's `name`.

An environment named by an expression cannot be read, so it is a finding that names the
expression. There is one exception, and it is one shape only:

```
${{ needs.<job>.outputs.<name> == '<A>' && '<A>' || '<B>' }}
```

`<A>` and `<B>` are plain literals (an ASCII letter or digit first, then letters, digits,
dots, underscores or hyphens). `<A>` is the same literal in the test and in the result, so the
job runs in `<A>` or in `<B>` and nowhere else. C4 reads both and judges each as if it were
named outright. This is how a Hetzner apply is routed to `production-free` or `production` by
the spend gate. Spaces and tabs may differ where the shape has them.

Every other expression stays a finding: another operator, a branch that is not a literal, a third
branch, a different literal in the test and the result, the `github`, `inputs` or `vars` context,
string concatenation, a function such as `format()`, a nested `${{ }}`, or any text before or
after the expression.
