"""Terminal, JSON and SARIF output. All three are deterministic."""

from __future__ import annotations

import json
from typing import Any

from . import rules
from .scan import Result

_ORDER = (rules.Severity.CRITICAL, rules.Severity.HIGH, rules.Severity.MEDIUM, rules.Severity.LOW)


def _sorted(result: Result) -> list[rules.Finding]:
    return sorted(result.findings, key=lambda f: (f.file, f.line, f.rule, f.message))


def summary(result: Result) -> str:
    counts = {s: sum(1 for f in result.findings if f.severity == s) for s in _ORDER}
    parts = [f"{n} {s}" for s, n in counts.items() if n]
    text = f"{len(result.findings)} finding(s): {', '.join(parts) or 'none'}, in {result.files} Dockerfile(s)"
    if result.suppressed:
        text += f"; {result.suppressed} suppressed with a reason"
    return text


def terminal(result: Result, *, brief: bool = False) -> str:
    out: list[str] = []
    for f in _sorted(result):
        head = f"{f.file}:{f.line}  {str(f.severity).upper():<8} {f.rule}  "
        if brief:
            out.append(head + f.message)
            continue
        rule = rules.by_id(f.rule)
        out.append(head + (rule.title if rule else f.rule))
        out.append(f"    {f.message}")
        if f.fix:
            out.append(f"    fix: {f.fix}")
    if result.findings:
        out.append("")
    out.append(summary(result))
    return "\n".join(out) + "\n"


def as_json(result: Result) -> str:
    doc: dict[str, Any] = {
        "dockerfiles": result.files,
        "suppressed": result.suppressed,
        "findings": [
            {
                "rule": f.rule,
                "name": (rules.by_id(f.rule) or rules.META).name,
                "severity": str(f.severity),
                "file": f.file,
                "line": f.line,
                "message": f.message,
                "fix": f.fix,
            }
            for f in _sorted(result)
        ],
        "errors": result.errors,
    }
    return json.dumps(doc, indent=2) + "\n"


def _level(severity: rules.Severity) -> str:
    if severity >= rules.Severity.HIGH:
        return "error"
    return "warning" if severity == rules.Severity.MEDIUM else "note"


def as_sarif(result: Result) -> str:
    descriptors = [
        {
            "id": r.id,
            "name": r.name,
            "shortDescription": {"text": r.title},
            "fullDescription": {"text": r.why},
            "help": {"text": r.fix},
            "defaultConfiguration": {"level": _level(r.severity)},
        }
        for r in (rules.META, *rules.RULES)
    ]
    results = [
        {
            "ruleId": f.rule,
            "level": _level(f.severity),
            "message": {"text": f.message},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file}, "region": {"startLine": f.line}}}],
        }
        for f in _sorted(result)
    ]
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "dockerwarden",
                        "informationUri": "https://github.com/sriharifortitude/dockerwarden",
                        "rules": descriptors,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2) + "\n"
