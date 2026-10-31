"""Find a section of a runbook by that section's own heading.

A test that needs one section of a runbook must not define the section by the
text of a neighbouring one. Splitting on the next section's heading means that
renumbering or rewording the neighbour moves the slice, and the failure then
names something the edit never touched.
"""

import pathlib
import re

HEADING = re.compile(r"(#{1,6}) ")


def runbook_section(path, heading):
    """The text of the runbook at `path` under `heading`, up to the next heading
    of the same or a higher level, whatever that heading says. Lines inside a
    code fence are not headings: the grant procedure's bash blocks carry
    `# 1.`-style comments."""
    path = pathlib.Path(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    level = len(heading) - len(heading.lstrip("#"))
    start = None
    in_fence = False
    for index, line in enumerate(lines):
        if line.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if start is None:
            if line == heading:
                start = index + 1
            continue
        match = HEADING.match(line)
        if match and len(match.group(1)) <= level:
            return "\n".join(lines[start:index]) + "\n"
    if start is None:
        raise AssertionError(
            f"{path.name} has no heading {heading!r}; its section structure changed"
        )
    return "\n".join(lines[start:]) + "\n"
