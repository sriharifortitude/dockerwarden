# 0002. Suppressions are comment lines, and need a reason

**Status:** accepted

## Decision

A finding is suppressed by `# dockerwarden:ignore DW003 -- reason` on the
comment line directly above the instruction. There is no same-line form.
Without a reason the finding is **not** suppressed and a second finding, DW000,
points at the comment. Suppressed findings are counted in the summary.

A file that cannot be read or is not a Dockerfile is reported by name and makes
the exit code 2, even when every other file is clean.

## Reasoning

In a Dockerfile only a line that *starts* with `#` is a comment. A `#` after an
instruction is part of it: `RUN echo hi # x` prints `hi # x`. A same-line
suppression would therefore either not be a comment at all, or require the
linter to guess where an instruction's text ends and a comment begins, and it
would guess wrong for exactly the shell one-liners where suppressions are
needed. Putting the directive on its own line above is unambiguous.

Requiring the reason follows the same logic as any suppression mechanism: a
silence nobody can explain is a finding nobody will revisit. Refusing the
reasonless comment, rather than warning and obeying it, means it cannot be
used to turn a build green.

Exiting 2 for an unreadable file follows from what the tool is for. A security
check that exits 0 because it read nothing looks like a pass.

## Costs

A suppression must sit immediately above the instruction, so a comment block
in between breaks it; the finding then returns, which fails safe. There is no
baseline file and no rule-wide off switch. If a rule does not fit, the answer
is to change the rule.
