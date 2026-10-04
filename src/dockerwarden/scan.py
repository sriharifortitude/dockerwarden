"""Finding Dockerfiles, running the rules, and applying suppression comments."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import rules
from .parse import DockerfileError, parse

MAX_FILE_BYTES = 1 << 20
_SKIP_DIRS = frozenset({".git", "node_modules", ".venv", "venv", "__pycache__", "target", "dist", "vendor"})
_NAME = re.compile(r"^(?:dockerfile|containerfile)(?:\..+)?$|^.+\.(?:dockerfile|containerfile)$", re.I)
_DIRECTIVE = re.compile(r"^\s*#\s*dockerwarden:ignore\s+(DW\d{3})(?:[\s:]|$)(.*)$")


@dataclass
class Result:
    files: int = 0
    findings: list[rules.Finding] = field(default_factory=list)
    suppressed: int = 0
    #: Files that could not be read or are not Dockerfiles; a file that was
    #: not read says nothing about its safety, so these are not findings.
    errors: list[str] = field(default_factory=list)


def find_files(paths: list[str]) -> list[Path]:
    found: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_file():
            found.append(p)
        elif p.is_dir():
            for root, dirs, names in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
                found.extend(Path(root) / n for n in sorted(names) if _NAME.match(n))
        else:
            raise FileNotFoundError(f"{raw}: no such file or directory")
    return found


def _read(path: Path) -> str:
    with path.open("rb") as handle:
        data = handle.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise DockerfileError(f"larger than {MAX_FILE_BYTES >> 20} MiB; refusing it")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as e:
        raise DockerfileError(f"not valid UTF-8 (byte {e.start})") from None


def scan_source(path: str, text: str) -> tuple[list[rules.Finding], int]:
    """Findings that remain after suppression, and how many were suppressed.

    A suppression is a comment line directly above the instruction. Dockerfiles
    have no trailing comments (a ``#`` after an instruction is part of it), so
    there is no same-line form.
    """
    lines = text.splitlines()
    kept: list[rules.Finding] = []
    suppressed = 0
    reasonless: set[int] = set()
    for f in rules.run(parse(text, path)):
        above = lines[f.line - 2] if 2 <= f.line <= len(lines) + 1 else ""
        m = _DIRECTIVE.match(above)
        if m is None or m.group(1) != f.rule:
            kept.append(f)
            continue
        reason = m.group(2).strip().removeprefix("--").removeprefix(":").strip()
        if reason:
            suppressed += 1
            continue
        kept.append(f)
        if f.line - 1 not in reasonless:
            reasonless.add(f.line - 1)
            kept.append(
                rules.Finding(
                    rules.META.id,
                    rules.META.severity,
                    path,
                    f.line - 1,
                    f"this comment suppresses {f.rule} but gives no reason, so it suppresses nothing",
                    rules.META.fix,
                )
            )
    kept.sort(key=lambda x: (x.line, x.rule, x.message))
    return kept, suppressed


def scan_paths(paths: list[str]) -> Result:
    result = Result()
    for path in find_files(paths):
        display = path.as_posix()
        try:
            findings, suppressed = scan_source(display, _read(path))
        except (DockerfileError, OSError) as e:
            result.errors.append(f"{display}: {e}")
            continue
        result.files += 1
        result.findings.extend(findings)
        result.suppressed += suppressed
    return result
