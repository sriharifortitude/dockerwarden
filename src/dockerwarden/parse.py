"""A Dockerfile reader: instructions, stages, and the few things the rules need.

It follows the Dockerfile reference for what matters to a linter: the escape
directive, continuation lines (with comments and blank lines allowed between
them), heredocs in RUN/COPY/ADD, ARG before FROM, and flags such as
``--from=`` and ``--mount=``. It does not run the build, so ``${VAR}``
expansion only knows the defaults written in the file.
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass, field

KEYWORDS = frozenset(
    [
        "FROM",
        "RUN",
        "CMD",
        "LABEL",
        "MAINTAINER",
        "EXPOSE",
        "ENV",
        "ADD",
        "COPY",
        "ENTRYPOINT",
        "VOLUME",
        "USER",
        "WORKDIR",
        "ARG",
        "ONBUILD",
        "STOPSIGNAL",
        "HEALTHCHECK",
        "SHELL",
    ]
)
_FLAG = re.compile(r"^--([A-Za-z][\w-]*)(?:=(\S*))?(?:\s+|$)")
_HEREDOC = re.compile(r"<<(-?)([\"']?)([A-Za-z_]\w*)\2")
_DIRECTIVE = re.compile(r"^\s*#\s*([A-Za-z][A-Za-z0-9]*)\s*=\s*(.+?)\s*$")
_MAX_LINES = 50_000


class DockerfileError(ValueError):
    """The file is not a Dockerfile Docker would accept."""


@dataclass(frozen=True)
class Instruction:
    keyword: str
    #: Everything after the keyword and its leading flags, continuations joined.
    args: str
    line: int
    end_line: int
    flags: dict[str, str] = field(default_factory=dict)
    #: Bodies of heredocs, in order of appearance.
    heredocs: tuple[str, ...] = ()

    @property
    def text(self) -> str:
        """The arguments plus any heredoc bodies: everything a shell would run."""
        return "\n".join((self.args, *self.heredocs)) if self.heredocs else self.args

    def words(self) -> list[str]:
        """Arguments as a list: from JSON form if it is one, otherwise shell-split."""
        stripped = self.args.strip()
        if stripped.startswith("["):
            try:
                value = json.loads(stripped)
            except json.JSONDecodeError:
                value = None
            if isinstance(value, list) and all(isinstance(v, str) for v in value):
                return list(value)
        return split_words(stripped)


def split_words(text: str) -> list[str]:
    try:
        return shlex.split(text, posix=True)
    except ValueError:
        return text.split()


@dataclass
class Stage:
    index: int
    line: int
    #: The FROM instruction's image text, exactly as written.
    image: str
    name: str | None
    platform: str | None
    instructions: list[Instruction] = field(default_factory=list)


@dataclass
class Dockerfile:
    path: str
    #: ARG instructions before the first FROM, which are the only ones FROM can use.
    global_args: list[Instruction]
    stages: list[Stage]
    directives: dict[str, str]

    def stage_named(self, name: str) -> Stage | None:
        lowered = name.lower()
        return next((s for s in self.stages if s.name is not None and s.name.lower() == lowered), None)


def _read_flags(args: str) -> tuple[dict[str, str], str]:
    flags: dict[str, str] = {}
    rest = args
    while (m := _FLAG.match(rest)) is not None:
        flags[m.group(1).lower()] = m.group(2) or ""
        rest = rest[m.end() :]
    return flags, rest


def _read_heredocs(lines: list[str], i: int, args: str, start: int) -> tuple[list[str], int]:
    bodies: list[str] = []
    for m in _HEREDOC.finditer(args):
        strip_tabs, marker = m.group(1) == "-", m.group(3)
        body: list[str] = []
        while True:
            if i >= len(lines):
                raise DockerfileError(f"line {start + 1}: heredoc <<{marker} is never terminated")
            candidate = lines[i].lstrip("\t") if strip_tabs else lines[i]
            i += 1
            if candidate.rstrip("\r") == marker:
                break
            body.append(lines[i - 1])
        bodies.append("\n".join(body))
    return bodies, i


def parse(text: str, path: str = "Dockerfile") -> Dockerfile:
    lines = text.splitlines()
    if len(lines) > _MAX_LINES:
        raise DockerfileError(f"more than {_MAX_LINES} lines; refusing it")
    directives: dict[str, str] = {}
    escape = "\\"
    i = 0
    while i < len(lines) and (m := _DIRECTIVE.match(lines[i])) is not None:
        key, value = m.group(1).lower(), m.group(2)
        directives[key] = value
        if key == "escape" and value in ("\\", "`"):
            escape = value
        i += 1

    instructions: list[Instruction] = []
    while i < len(lines):
        stripped = lines[i].strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        start = i
        parts: list[str] = []
        last = i
        while True:
            body = lines[i].rstrip()
            last = i
            i += 1
            if not body.endswith(escape):
                parts.append(body)
                break
            parts.append(body[:-1])
            while i < len(lines) and (not lines[i].strip() or lines[i].strip().startswith("#")):
                i += 1
            if i >= len(lines):
                break
        joined = "".join(parts).strip()
        keyword, _, rest = joined.partition(" ")
        if "\t" in keyword:
            keyword, _, tail = keyword.partition("\t")
            rest = f"{tail} {rest}"
        keyword = keyword.upper()
        if keyword not in KEYWORDS:
            raise DockerfileError(f"line {start + 1}: unknown instruction {keyword!r}")
        flags: dict[str, str] = {}
        args = rest.strip()
        if keyword in ("FROM", "RUN", "COPY", "ADD"):
            flags, args = _read_flags(args)
        heredocs: list[str] = []
        if keyword in ("RUN", "COPY", "ADD"):
            heredocs, i = _read_heredocs(lines, i, args, start)
            last = max(last, i - 1)
        instructions.append(Instruction(keyword, args, start + 1, last + 1, flags, tuple(heredocs)))

    return _into_stages(instructions, path, directives)


def _into_stages(instructions: list[Instruction], path: str, directives: dict[str, str]) -> Dockerfile:
    global_args: list[Instruction] = []
    stages: list[Stage] = []
    for ins in instructions:
        if ins.keyword == "FROM":
            words = split_words(ins.args)
            if not words:
                raise DockerfileError(f"line {ins.line}: FROM needs an image")
            name = None
            if len(words) >= 3 and words[1].lower() == "as":
                name = words[2]
            elif len(words) > 1:
                raise DockerfileError(f"line {ins.line}: FROM takes an image and optionally AS <name>")
            stages.append(Stage(len(stages), ins.line, words[0], name, ins.flags.get("platform"), []))
        elif not stages:
            if ins.keyword != "ARG":
                raise DockerfileError(f"line {ins.line}: {ins.keyword} before the first FROM")
            global_args.append(ins)
        else:
            stages[-1].instructions.append(ins)
    if not stages:
        raise DockerfileError("no FROM instruction, so this is not a Dockerfile")
    return Dockerfile(path, global_args, stages, directives)


def assignments(args: str, *, legacy: bool = False) -> list[tuple[str, str | None]]:
    """Name/value pairs from ENV or ARG arguments.

    Handles ``KEY=value KEY2="v 2"`` and ``ARG NAME`` with no default (value
    None). With ``legacy`` (ENV only), also the old ``ENV KEY some value`` form,
    where everything after the first word is the value.
    """
    words = split_words(args)
    if not words:
        return []
    if legacy and "=" not in words[0] and len(words) >= 2:
        head, _, tail = args.strip().partition(" ")
        return [(head, tail.strip().strip("\"'"))]
    out: list[tuple[str, str | None]] = []
    for word in words:
        key, eq, value = word.partition("=")
        out.append((key, value if eq else None))
    return out
