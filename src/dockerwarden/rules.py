"""The checks. Each rule is a function over a parsed Dockerfile plus the text a
person needs to understand and fix what it found."""

from __future__ import annotations

import enum
import re
from collections.abc import Callable
from dataclasses import dataclass

from .image import global_defaults, parse_image
from .parse import Dockerfile, Instruction, Stage, assignments, split_words
from .shell import commands, program


class Severity(enum.IntEnum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3

    def __str__(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: Severity
    file: str
    line: int
    message: str
    fix: str = ""


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    title: str
    severity: Severity
    why: str
    fix: str
    check: Callable[[Dockerfile], list[Finding]]


def _f(df: Dockerfile, rule: str, severity: Severity, line: int, message: str, fix: str = "") -> Finding:
    return Finding(rule, severity, df.path, line, message, fix)


def _all(df: Dockerfile) -> list[tuple[Stage, Instruction]]:
    return [(s, i) for s in df.stages for i in s.instructions]


def _is_stage_ref(df: Dockerfile, image: str, before: int) -> bool:
    return any(s.name is not None and s.name.lower() == image.lower() for s in df.stages[:before])


# ---- DW001 / DW002: base images ------------------------------------------------


def _external_bases(df: Dockerfile) -> list[tuple[Stage, str, str | None, str | None]]:
    """(stage, image name, tag, digest) for each FROM that names a registry image."""
    defaults = global_defaults(df)
    out = []
    for stage in df.stages:
        if _is_stage_ref(df, stage.image, stage.index):
            continue
        ref = parse_image(stage.image, defaults)
        if ref.is_scratch or not ref.resolved:
            continue
        out.append((stage, ref.name, ref.tag, ref.digest))
    return out


def check_latest(df: Dockerfile) -> list[Finding]:
    out = []
    for stage, name, tag, digest in _external_bases(df):
        if digest:
            continue
        if tag is None:
            out.append(
                _f(
                    df,
                    "DW001",
                    Severity.MEDIUM,
                    stage.line,
                    f"base image {name} has no tag, so it resolves to :latest, which changes under you",
                )
            )
        elif tag.lower() == "latest":
            out.append(
                _f(
                    df,
                    "DW001",
                    Severity.MEDIUM,
                    stage.line,
                    f"base image {name}:latest changes whenever the publisher pushes",
                )
            )
    return out


def check_digest(df: Dockerfile) -> list[Finding]:
    return [
        _f(
            df,
            "DW002",
            Severity.LOW,
            stage.line,
            f"base image {name}:{tag} is pinned by tag, and a tag can be re-pushed to different content",
        )
        for stage, name, tag, digest in _external_bases(df)
        if tag and tag.lower() != "latest" and not digest
    ]


# ---- DW003: root ---------------------------------------------------------------


# Image families that publish a non-root default user, recognised by name. This
# is a naming convention, not a lookup: it cannot see inside the image, so it
# trusts a name that says nonroot to mean it, and a Dockerfile whose base sets a
# user under another name can still suppress the finding.
_NON_ROOT_BASE = re.compile(r"nonroot|unprivileged|chiseled|rootless", re.IGNORECASE)
NON_ROOT_BASE = "<base image>"


def _user_of(df: Dockerfile, stage: Stage, depth: int = 0) -> tuple[str | None, int]:
    """The user the stage ends as, and the line that set it; (None, 0) when never set."""
    for ins in reversed(stage.instructions):
        if ins.keyword == "USER":
            words = split_words(ins.args)
            return (words[0].split(":", 1)[0] if words else ""), ins.line
    parent = next((s for s in df.stages[: stage.index] if s.name and s.name.lower() == stage.image.lower()), None)
    if parent is not None and depth < 50:
        return _user_of(df, parent, depth + 1)
    if _NON_ROOT_BASE.search(stage.image):
        return NON_ROOT_BASE, 0
    return None, 0


def check_root(df: Dockerfile) -> list[Finding]:
    final = df.stages[-1]
    user, line = _user_of(df, final)
    if user is None:
        return [
            _f(
                df,
                "DW003",
                Severity.MEDIUM,
                final.line,
                "the final stage never sets USER, so the container runs as root unless its base image sets another user",
            )
        ]
    if user in ("root", "0"):
        return [_f(df, "DW003", Severity.MEDIUM, line, "the final stage ends as root")]
    return []


# ---- DW004: secrets ------------------------------------------------------------

_SECRET_NAME = re.compile(
    r"(?<![A-Za-z])(?:PASS(?:WORD|WD)?|SECRETS?|TOKENS?|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|CREDENTIALS?|AUTH(?:ORIZATION)?)(?![A-Za-z])",
    re.I,
)
_POINTS_AT_A_FILE = re.compile(r"_(?:FILE|PATH|DIR)$", re.I)
_TOKEN_SHAPES = {
    "an AWS access key ID": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "a GitHub token": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b|\bgithub_pat_[0-9A-Za-z_]{40,}\b"),
    "a Slack token": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    "a Google API key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "a Stripe live key": re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b"),
    "a private key": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY"),
}


def check_secrets(df: Dockerfile) -> list[Finding]:
    out: list[Finding] = []
    for _, ins in _all(df) + [(df.stages[0], g) for g in df.global_args]:
        if ins.keyword in ("ENV", "ARG"):
            for key, value in assignments(ins.args, legacy=ins.keyword == "ENV"):
                if value and "$" not in value and _SECRET_NAME.search(key) and not _POINTS_AT_A_FILE.search(key):
                    if ins.keyword == "ENV":
                        out.append(
                            _f(
                                df,
                                "DW004",
                                Severity.HIGH,
                                ins.line,
                                f"ENV {key} stores a literal secret in the image's configuration, readable by anyone who can pull the image",
                            )
                        )
                    else:
                        out.append(
                            _f(
                                df,
                                "DW004",
                                Severity.MEDIUM,
                                ins.line,
                                f"ARG {key} has a literal default, which stays in the image history (docker history)",
                            )
                        )
        for what, pattern in _TOKEN_SHAPES.items():
            if pattern.search(ins.text):
                out.append(
                    _f(df, "DW004", Severity.HIGH, ins.line, f"this instruction contains what looks like {what}")
                )
    return out


# ---- DW005: pipe to shell ------------------------------------------------------

_PIPE_TO_SHELL = re.compile(r"\b(?:curl|wget)\b[^\n]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:ba|z|da|k)?sh\b")
_PROC_SUBST = re.compile(r"\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b")


def check_pipe_to_shell(df: Dockerfile) -> list[Finding]:
    return [
        _f(
            df,
            "DW005",
            Severity.MEDIUM,
            ins.line,
            "downloads a script and pipes it into a shell, so the image is built from whatever the server returns that day",
        )
        for _, ins in _all(df)
        if ins.keyword == "RUN" and (_PIPE_TO_SHELL.search(ins.text) or _PROC_SUBST.search(ins.text))
    ]


# ---- DW006: ADD ----------------------------------------------------------------

_ARCHIVE = re.compile(r"\.(?:tar|tar\.gz|tgz|tar\.bz2|tbz2|tar\.xz|txz|tar\.zst)$", re.I)
_URL = re.compile(r"^(?:https?|git)://|^git@", re.I)


def check_add(df: Dockerfile) -> list[Finding]:
    out = []
    for _, ins in _all(df):
        if ins.keyword != "ADD" or ins.heredocs:
            continue
        sources = ins.words()[:-1]
        for src in sources:
            if _URL.match(src):
                if "checksum" not in ins.flags:
                    out.append(
                        _f(
                            df,
                            "DW006",
                            Severity.MEDIUM,
                            ins.line,
                            f"ADD fetches {src} with no --checksum, so nothing verifies what arrives",
                        )
                    )
            elif not _ARCHIVE.search(src) and "$" not in src:
                out.append(
                    _f(
                        df,
                        "DW006",
                        Severity.LOW,
                        ins.line,
                        f"ADD {src} does nothing COPY would not; ADD also unpacks archives and fetches URLs, which is rarely intended",
                    )
                )
    return out


# ---- DW007: package manager hygiene -------------------------------------------


def _has_cache_mount(ins: Instruction) -> bool:
    return "type=cache" in ins.flags.get("mount", "")


def check_packages(df: Dockerfile) -> list[Finding]:
    out: list[Finding] = []
    for _, ins in _all(df):
        if ins.keyword != "RUN" or _has_cache_mount(ins):
            continue
        cmds = commands(ins.text)
        apt = [c for c in cmds if program(c) in ("apt-get", "apt")]
        installs = [c for c in apt if "install" in c]
        if any("--no-install-recommends" not in c for c in installs):
            out.append(
                _f(
                    df,
                    "DW007",
                    Severity.LOW,
                    ins.line,
                    "apt-get install without --no-install-recommends pulls in packages nobody asked for, each one more to patch",
                )
            )
        if any(w in c for c in apt for w in ("upgrade", "dist-upgrade")):
            out.append(
                _f(
                    df,
                    "DW007",
                    Severity.LOW,
                    ins.line,
                    "apt-get upgrade makes the image depend on the day it was built; pin the base image and install what you need",
                )
            )
        if any("update" in c for c in apt) and not installs:
            out.append(
                _f(
                    df,
                    "DW007",
                    Severity.LOW,
                    ins.line,
                    "apt-get update in a RUN of its own is cached as a layer and goes stale; run it in the same RUN as the install",
                )
            )
        if installs and "/var/lib/apt/lists" not in ins.text and "dist-clean" not in ins.text:
            out.append(
                _f(
                    df,
                    "DW007",
                    Severity.LOW,
                    ins.line,
                    "apt-get install leaves /var/lib/apt/lists in the layer; remove it in the same RUN",
                )
            )
        apk = [c for c in cmds if program(c) == "apk" and "add" in c]
        if any("--no-cache" not in c for c in apk) and "/var/cache/apk" not in ins.text:
            out.append(
                _f(
                    df,
                    "DW007",
                    Severity.LOW,
                    ins.line,
                    "apk add without --no-cache leaves the package index in the layer",
                )
            )
    return out


# ---- DW008: sudo ---------------------------------------------------------------


def check_sudo(df: Dockerfile) -> list[Finding]:
    return [
        _f(
            df,
            "DW008",
            Severity.LOW,
            ins.line,
            "RUN uses sudo; build steps already run as the current USER, so sudo only adds a setuid binary to the image",
        )
        for _, ins in _all(df)
        if ins.keyword == "RUN" and any(c[0] == "sudo" for c in commands(ins.text))
    ]


# ---- DW009: chmod --------------------------------------------------------------

_BAD_MODES = {"777", "0777", "666", "a+rwx", "ugo+rwx", "a+w", "o+w", "o+rwx", "a=rwx"}


def check_chmod(df: Dockerfile) -> list[Finding]:
    out = []
    for _, ins in _all(df):
        if ins.keyword != "RUN":
            continue
        for c in commands(ins.text):
            if program(c) in ("chmod",) and any(w in _BAD_MODES for w in c[1:]):
                mode = next(w for w in c[1:] if w in _BAD_MODES)
                out.append(
                    _f(
                        df,
                        "DW009",
                        Severity.MEDIUM,
                        ins.line,
                        f"chmod {mode} makes files writable by every user in the container, including whatever process an attacker gets",
                    )
                )
                break
    return out


# ---- DW010: ssh ----------------------------------------------------------------


def check_ssh(df: Dockerfile) -> list[Finding]:
    out = []
    for _, ins in _all(df):
        if ins.keyword == "EXPOSE" and any(re.fullmatch(r"22(?:/(?:tcp|udp))?", w) for w in ins.words()):
            out.append(
                _f(
                    df,
                    "DW010",
                    Severity.MEDIUM,
                    ins.line,
                    "EXPOSE 22: an SSH server in a container is a second way in, and one the image has to keep patched",
                )
            )
        elif ins.keyword == "RUN" and any(w in ("openssh-server", "dropbear") for c in commands(ins.text) for w in c):
            out.append(
                _f(
                    df,
                    "DW010",
                    Severity.MEDIUM,
                    ins.line,
                    "installs an SSH server into the image; use the orchestrator's exec instead",
                )
            )
    return out


# ---- DW011: unknown --from -----------------------------------------------------


def check_unknown_stage(df: Dockerfile) -> list[Finding]:
    out = []
    for stage, ins in _all(df):
        source = ins.flags.get("from")
        if ins.keyword != "COPY" or not source or source.isdigit() or "$" in source:
            continue
        if any(c in source for c in "/:.@") or _is_stage_ref(df, source, stage.index):
            continue
        if df.stage_named(source) is not None:
            why = f"the stage named {source!r} is defined later, and COPY can only read earlier stages"
        else:
            why = f"no stage is named {source!r}"
        out.append(
            _f(
                df,
                "DW011",
                Severity.MEDIUM,
                ins.line,
                f"COPY --from={source}: {why}, so Docker will pull an image called {source!r} from the registry instead",
            )
        )
    return out


# ---- DW012: sensitive files ----------------------------------------------------

_EXACT_SENSITIVE = re.compile(
    r"^(?:\.env(?:\..+)?|id_rsa|id_dsa|id_ecdsa|id_ed25519|\.npmrc|\.pypirc|\.netrc|\.git-credentials|credentials|"
    r"\.aws|\.ssh|\.docker|.*\.(?:key|p12|pfx|jks|keystore)|privkey\.pem|.*-key\.pem)$",
    re.I,
)
_PEM = re.compile(r"\.pem$", re.I)


def check_sensitive_files(df: Dockerfile) -> list[Finding]:
    out = []
    for _, ins in _all(df):
        if ins.keyword not in ("COPY", "ADD") or ins.heredocs or "from" in ins.flags:
            continue
        for src in ins.words()[:-1]:
            base = src.rstrip("/").rsplit("/", 1)[-1]
            if _EXACT_SENSITIVE.match(base):
                out.append(
                    _f(
                        df,
                        "DW012",
                        Severity.HIGH,
                        ins.line,
                        f"copies {src} into the image; files like this carry credentials and stay in the layer even if a later step deletes them",
                    )
                )
            elif _PEM.search(base):
                out.append(
                    _f(
                        df,
                        "DW012",
                        Severity.MEDIUM,
                        ins.line,
                        f"copies {src}; if it is a private key it is now in the image (a certificate is fine)",
                    )
                )
    return out


# ---- DW013: verification off ---------------------------------------------------

_DISABLED = {
    "curl --insecure (or -k)": re.compile(r"\bcurl\b[^|;&\n]*\s(?:--insecure|-[A-Za-z]*k[A-Za-z]*)(?=\s|$)"),
    "wget --no-check-certificate": re.compile(r"--no-check-certificate"),
    "git http.sslVerify=false": re.compile(r"(?:http\.)?sslverify[=\s]+false|GIT_SSL_NO_VERIFY", re.I),
    "NODE_TLS_REJECT_UNAUTHORIZED=0": re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED\s*=?\s*[\"']?0"),
    "npm strict-ssl false": re.compile(r"strict-ssl\s+false"),
    "pip --trusted-host": re.compile(r"--trusted-host"),
    "apt --allow-unauthenticated": re.compile(r"--allow-unauthenticated|--allow-insecure-repositories"),
}


def check_verification(df: Dockerfile) -> list[Finding]:
    out = []
    for _, ins in _all(df):
        if ins.keyword not in ("RUN", "ENV"):
            continue
        hits = [what for what, pattern in _DISABLED.items() if pattern.search(ins.text)]
        if hits:
            out.append(
                _f(
                    df,
                    "DW013",
                    Severity.MEDIUM,
                    ins.line,
                    f"turns off verification: {', '.join(hits)}; the build then trusts whoever answers",
                )
            )
    return out


RULES: tuple[Rule, ...] = (
    Rule(
        "DW001",
        "latest-image",
        "base image is untagged or :latest",
        Severity.MEDIUM,
        "An untagged or :latest base image is a different image every time the publisher pushes, so the same Dockerfile builds different software on different days and a fix or a regression arrives unreviewed.",
        "Pin a specific version: FROM python:3.12.7-slim, and ideally the digest.",
        check_latest,
    ),
    Rule(
        "DW002",
        "unpinned-digest",
        "base image pinned by tag, not by digest",
        Severity.LOW,
        "A tag can be re-pushed to different content; a digest cannot. Pinning by digest makes the build reproducible and means a compromised tag cannot reach it.",
        "FROM image:tag@sha256:<digest>, and let a bot propose updates.",
        check_digest,
    ),
    Rule(
        "DW003",
        "runs-as-root",
        "container runs as root",
        Severity.MEDIUM,
        "Without USER the process runs as root inside the container. A bug in the application then hands an attacker root there, which makes every container escape and every writable mount easier.",
        "Create an unprivileged user and switch to it with USER before the entrypoint.",
        check_root,
    ),
    Rule(
        "DW004",
        "secret-in-image",
        "secret stored in the image",
        Severity.HIGH,
        "ENV values are part of the image configuration and ARG values are in its history. Anyone who can pull the image can read both. A secret in a layer stays there even if a later instruction removes it.",
        "Use RUN --mount=type=secret for build-time secrets and pass runtime secrets at run time.",
        check_secrets,
    ),
    Rule(
        "DW005",
        "pipe-to-shell",
        "download piped into a shell",
        Severity.MEDIUM,
        "curl ... | sh runs whatever the server returns at that moment, unverified. The build is only as trustworthy as that server, on that day.",
        "Download the file, verify a checksum or signature you pinned, then run it; or install from a package manager.",
        check_pipe_to_shell,
    ),
    Rule(
        "DW006",
        "add-instead-of-copy",
        "ADD used where COPY or a verified download is meant",
        Severity.MEDIUM,
        "ADD fetches URLs and unpacks archives. From a URL with no --checksum it builds the image from unverified remote content; for a plain local file it does the same as COPY with more surprises.",
        "Use COPY for local files, and ADD --checksum=sha256:... for a URL.",
        check_add,
    ),
    Rule(
        "DW007",
        "package-hygiene",
        "package manager used in a way that bloats or stales the image",
        Severity.LOW,
        "apt-get install without --no-install-recommends adds unrequested packages; leaving the package lists in the layer adds size; apt-get update in its own RUN is cached and goes stale; upgrade ties the image to the build date.",
        "RUN apt-get update && apt-get install -y --no-install-recommends <pkgs> && rm -rf /var/lib/apt/lists/*",
        check_packages,
    ),
    Rule(
        "DW008",
        "sudo",
        "sudo used in a build step",
        Severity.LOW,
        "Build steps already run as the current USER. sudo in a Dockerfile means either that user is root (so it is pointless) or that a setuid binary was added to the image (so it is a risk).",
        "Drop sudo, and switch USER around the steps that need root.",
        check_sudo,
    ),
    Rule(
        "DW009",
        "world-writable",
        "chmod makes files world-writable",
        Severity.MEDIUM,
        "chmod 777 lets any process in the container rewrite the files, including one an attacker controls, and usually hides a real ownership problem.",
        "Set ownership with COPY --chown or chown, and the narrowest mode that works.",
        check_chmod,
    ),
    Rule(
        "DW010",
        "ssh-in-container",
        "SSH server in the image",
        Severity.MEDIUM,
        "An SSH server is another way into the container, with its own keys, configuration and patches to keep up with. Orchestrators already provide exec.",
        "Remove the SSH server and EXPOSE 22; use docker exec or kubectl exec.",
        check_ssh,
    ),
    Rule(
        "DW011",
        "unknown-stage",
        "COPY --from names a stage that does not exist",
        Severity.MEDIUM,
        "If the name matches no earlier stage, Docker treats it as an image and pulls it from the registry. A typo in a stage name silently copies files from whoever owns that name on Docker Hub.",
        "Fix the name, or write the full image reference if an image is meant.",
        check_unknown_stage,
    ),
    Rule(
        "DW012",
        "sensitive-file",
        "credentials copied into the image",
        Severity.HIGH,
        "Files such as .env, private keys and .npmrc carry credentials. Copying one puts it in a layer, and deleting it in a later instruction does not remove it from the earlier layer.",
        "Keep them out of the build context with .dockerignore, and use RUN --mount=type=secret.",
        check_sensitive_files,
    ),
    Rule(
        "DW013",
        "verification-disabled",
        "certificate or signature verification turned off",
        Severity.MEDIUM,
        "Flags like curl -k, --no-check-certificate, --trusted-host and apt --allow-unauthenticated make the build accept anything an attacker on the network, or a compromised mirror, sends.",
        "Fix the certificate chain (install ca-certificates) instead of turning checking off.",
        check_verification,
    ),
)

META = Rule(
    "DW000",
    "ignore-without-reason",
    "suppression comment without a reason",
    Severity.LOW,
    "A suppression nobody can explain is a finding nobody will revisit.",
    "Write `# dockerwarden:ignore DW001 -- why this is acceptable`.",
    lambda _df: [],
)


def by_id(rule_id: str) -> Rule | None:
    return META if rule_id == META.id else next((r for r in RULES if r.id == rule_id), None)


def run(df: Dockerfile) -> list[Finding]:
    found: list[Finding] = []
    for rule in RULES:
        for f in rule.check(df):
            found.append(f if f.fix else Finding(f.rule, f.severity, f.file, f.line, f.message, rule.fix))
    return sorted(found, key=lambda f: (f.line, f.rule, f.message))
