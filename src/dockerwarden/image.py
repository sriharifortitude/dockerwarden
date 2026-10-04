"""Reading an image reference, and expanding the ARG defaults FROM may use."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .parse import Dockerfile, assignments

_VAR = re.compile(r"\$\{(\w+)(?::?-([^}]*))?\}|\$(\w+)")


@dataclass(frozen=True)
class ImageRef:
    raw: str
    name: str
    tag: str | None
    digest: str | None
    #: False when the reference still contains an unexpanded variable.
    resolved: bool

    @property
    def is_scratch(self) -> bool:
        return self.name.lower() == "scratch"


def expand(text: str, defaults: dict[str, str | None]) -> tuple[str, bool]:
    """Substitute ``$VAR`` / ``${VAR}`` / ``${VAR:-default}`` from ARG defaults."""
    complete = True

    def replace(m: re.Match[str]) -> str:
        nonlocal complete
        name = m.group(1) or m.group(3)
        value = defaults.get(name)
        if value:
            return value
        if m.group(2) is not None:
            return m.group(2)
        complete = False
        return m.group(0)

    return _VAR.sub(replace, text), complete


def global_defaults(dockerfile: Dockerfile) -> dict[str, str | None]:
    defaults: dict[str, str | None] = {}
    for ins in dockerfile.global_args:
        for key, value in assignments(ins.args):
            defaults[key] = value
    return defaults


def parse_image(text: str, defaults: dict[str, str | None] | None = None) -> ImageRef:
    expanded, resolved = expand(text, defaults or {})
    name = expanded
    digest = None
    if "@" in name:
        name, _, digest = name.partition("@")
    tag = None
    last_slash = name.rfind("/")
    colon = name.rfind(":")
    if colon > last_slash:
        name, tag = name[:colon], name[colon + 1 :]
    return ImageRef(text, name, tag or None, digest or None, resolved)
