"""Just enough shell to look at what a RUN instruction runs.

This is not a shell parser. It splits a script into simple commands at ``&&``,
``||``, ``;``, ``|`` and newlines outside quotes, then splits each command into
words. That is accurate for the shapes Dockerfiles use, and wrong for exotic
ones (subshells, here-strings), which is why rules built on it say "looks like".
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from .parse import split_words

_SEPARATORS = ("&&", "||", ";", "|", "\n")


def segments(script: str) -> Iterator[str]:
    """Split a script into simple commands, honouring quotes and backslash-escapes."""
    start = 0
    i = 0
    quote = ""
    while i < len(script):
        c = script[i]
        if quote:
            if c == "\\" and quote == '"':
                i += 1
            elif c == quote:
                quote = ""
        elif c in "'\"":
            quote = c
        elif c == "\\":
            i += 1
        else:
            for sep in _SEPARATORS:
                if script.startswith(sep, i):
                    yield script[start:i]
                    i += len(sep) - 1
                    start = i + 1
                    break
        i += 1
    yield script[start:]


def commands(script: str) -> list[list[str]]:
    """Each simple command as a list of words, with leading ``VAR=value`` and ``sudo`` kept."""
    out: list[list[str]] = []
    for seg in segments(script):
        words = split_words(seg.strip())
        # Drop `# comment` tails and empty commands.
        for k, w in enumerate(words):
            if w.startswith("#"):
                words = words[:k]
                break
        if words:
            out.append(words)
    return out


def program(words: list[str]) -> str | None:
    """The program a command runs, skipping ``VAR=value`` prefixes, ``sudo``, ``exec`` and ``env``."""
    for w in words:
        if re.fullmatch(r"[A-Za-z_]\w*=.*", w) or w in ("sudo", "exec", "env", "time", "nohup", "command"):
            continue
        if w.startswith("-"):
            continue
        return w.rsplit("/", 1)[-1]
    return None
