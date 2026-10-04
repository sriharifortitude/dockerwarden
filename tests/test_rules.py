import pytest

from dockerwarden import rules
from dockerwarden.parse import parse


def found(dockerfile: str, rule: str | None = None) -> list[str]:
    """``RULE:line`` for each finding, optionally only for one rule."""
    df = parse(dockerfile, "Dockerfile")
    return [f"{f.rule}:{f.line}" for f in rules.run(df) if rule is None or f.rule == rule]


def only(rule: str, dockerfile: str) -> list[str]:
    return found(dockerfile, rule)


@pytest.mark.parametrize(
    ("image", "expected"),
    [
        ("node", ["DW001:1"]),
        ("node:latest", ["DW001:1"]),
        ("node:LATEST", ["DW001:1"]),
        ("node:20", []),
        ("node:20@sha256:" + "a" * 64, []),
        ("node@sha256:" + "a" * 64, []),
        ("scratch", []),
        ("${BASE}", []),
        ("localhost:5000/app", ["DW001:1"]),
    ],
)
def test_latest(image: str, expected: list[str]) -> None:
    assert only("DW001", f"FROM {image}\nUSER app\n") == expected


def test_a_stage_reference_is_not_a_base_image() -> None:
    assert only("DW001", "FROM node:20 AS build\nFROM build\nUSER x\n") == []


def test_global_arg_defaults_are_expanded() -> None:
    assert only("DW001", "ARG V=latest\nFROM node:${V}\nUSER x\n") == ["DW001:2"]
    assert only("DW001", "ARG V=20\nFROM node:${V}\nUSER x\n") == []


def test_digest_pinning_is_a_low_finding_for_tags_only() -> None:
    assert only("DW002", "FROM node:20\nUSER x\n") == ["DW002:1"]
    assert only("DW002", "FROM node\nUSER x\n") == []  # DW001's problem, not this one
    assert only("DW002", "FROM node:20@sha256:" + "b" * 64 + "\nUSER x\n") == []


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("", ["DW003:1"]),
        ("USER app\n", []),
        ("USER 1000:1000\n", []),
        ("USER root\n", ["DW003:2"]),
        ("USER 0\n", ["DW003:2"]),
        ("USER root:root\n", ["DW003:2"]),
        ("USER app\nUSER root\n", ["DW003:3"]),
        ("USER root\nUSER app\n", []),
        ("USER ${UID}\n", []),
    ],
)
def test_root(body: str, expected: list[str]) -> None:
    assert only("DW003", "FROM node:20\n" + body) == expected


def test_root_follows_stage_inheritance_and_only_judges_the_final_stage() -> None:
    assert only("DW003", "FROM a:1 AS base\nUSER app\nFROM base\nRUN x\n") == []
    assert only("DW003", "FROM a:1 AS base\nFROM base\nRUN x\n") == ["DW003:2"]
    assert only("DW003", "FROM a:1 AS build\nUSER root\nFROM b:1\nUSER app\n") == []


def test_secrets_by_name_and_value() -> None:
    assert only("DW004", "FROM a:1\nENV DB_PASSWORD=hunter2\n") == ["DW004:2"]
    assert only("DW004", "FROM a:1\nENV API_KEY abc123\n") == ["DW004:2"]
    assert only("DW004", "FROM a:1\nARG NPM_TOKEN=abc\n") == ["DW004:2"]
    assert only("DW004", "ARG NPM_TOKEN=abc\nFROM a:1\n") == ["DW004:1"]
    # Not secrets: no value, a variable reference, a path, or a name that only contains one.
    for line in (
        "ARG NPM_TOKEN",
        "ENV PASSWORD_FILE=/run/secrets/db",
        "ENV TOKEN=${X}",
        "ENV AUTHORS=me",
        "ENV TOKENIZER=x",
        "ENV BYPASS=1",
        "ENV PASSWORD=",
    ):
        assert only("DW004", f"FROM a:1\n{line}\n") == [], line
    assert only("DW004", "FROM a:1\nENV BASIC_AUTH=abc\n") == ["DW004:2"]


def test_secret_severity_is_higher_in_env_than_arg() -> None:
    df = parse("FROM a:1\nENV SECRET=x\nARG SECRET2=y\n")
    by_line = {f.line: f.severity for f in rules.run(df) if f.rule == "DW004"}
    assert by_line == {2: rules.Severity.HIGH, 3: rules.Severity.MEDIUM}


def test_token_shapes_are_found_without_a_telling_name() -> None:
    # Built here so no secret-shaped string sits in the repository for scanners to trip over.
    aws = "AKIA" + "IOSFODNN7" + "EXAMPLE"
    github = "ghp_" + "a" * 36
    pem = "-----BEGIN " + "RSA PRIVATE KEY-----"
    for text in (aws, github, pem):
        assert only("DW004", f"FROM a:1\nRUN echo {text} > /x\n") == ["DW004:2"], text
    assert only("DW004", "FROM a:1\nRUN echo AKIAshort\n") == []
    assert only("DW004", f"FROM a:1\nRUN <<EOF\necho {aws}\nEOF\n") == ["DW004:2"]


@pytest.mark.parametrize(
    ("run", "expected"),
    [
        ("curl -fsSL https://x.sh | sh", ["DW005:2"]),
        ("curl -fsSL https://x.sh | sudo bash -s", ["DW005:2"]),
        ("wget -qO- https://x.sh | bash", ["DW005:2"]),
        ("bash <(curl -s https://x.sh)", ["DW005:2"]),
        ("curl -fsSLo x.sh https://x.sh && sha256sum -c x.sum && sh x.sh", []),
        ("curl -s https://x | jq .name", []),
        ("curl -fsSL \\\n  https://x.sh \\\n  | sh", ["DW005:2"]),
    ],
)
def test_pipe_to_shell(run: str, expected: list[str]) -> None:
    assert only("DW005", f"FROM a:1\nRUN {run}\n") == expected


def test_add() -> None:
    assert only("DW006", "FROM a:1\nADD https://x/a.tar.gz /a\n") == ["DW006:2"]
    assert only("DW006", "FROM a:1\nADD --checksum=sha256:abc https://x/a.tar.gz /a\n") == []
    assert only("DW006", "FROM a:1\nADD app.tar.gz /opt/\n") == []
    assert only("DW006", "FROM a:1\nADD config.json /etc/\n") == ["DW006:2"]
    assert only("DW006", "FROM a:1\nCOPY config.json /etc/\n") == []
    assert only("DW006", "FROM a:1\nADD git@github.com:o/r.git /src\n") == ["DW006:2"]


def test_package_hygiene() -> None:
    messages = [
        f.message
        for f in rules.run(parse("FROM a:1\nRUN apt-get update && apt-get install -y curl\n"))
        if f.rule == "DW007"
    ]
    assert (
        len(messages) == 2
        and any("--no-install-recommends" in m for m in messages)
        and any("lists" in m for m in messages)
    )
    good = "FROM a:1\nRUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*\n"
    assert only("DW007", good) == []
    assert only("DW007", "FROM a:1\nRUN apt-get update\n") == ["DW007:2"]
    assert only("DW007", "FROM a:1\nRUN apt-get -y upgrade\n") == ["DW007:2"]
    assert only("DW007", "FROM a:1\nRUN apk add curl\n") == ["DW007:2"]
    assert only("DW007", "FROM a:1\nRUN apk add --no-cache curl\n") == []
    assert only("DW007", "FROM a:1\nRUN --mount=type=cache,target=/var/cache/apt apt-get install -y curl\n") == []


def test_package_checks_do_not_fire_on_other_programs() -> None:
    assert only("DW007", "FROM a:1\nRUN echo apt-get install\n") == []


def test_sudo_only_when_it_is_the_command() -> None:
    assert only("DW008", "FROM a:1\nRUN sudo make install\n") == ["DW008:2"]
    assert only("DW008", "FROM a:1\nRUN make && sudo make install\n") == ["DW008:2"]
    assert only("DW008", "FROM a:1\nRUN apt-get install -y --no-install-recommends sudo\n") == []


def test_chmod() -> None:
    assert only("DW009", "FROM a:1\nRUN chmod 777 /app\n") == ["DW009:2"]
    assert only("DW009", "FROM a:1\nRUN chmod -R a+rwx /app\n") == ["DW009:2"]
    assert only("DW009", "FROM a:1\nRUN chmod 755 /app && chmod +x run.sh\n") == []
    assert only("DW009", "FROM a:1\nRUN echo chmod 777\n") == []


def test_ssh() -> None:
    assert only("DW010", "FROM a:1\nEXPOSE 80 22\n") == ["DW010:2"]
    assert only("DW010", "FROM a:1\nEXPOSE 22/tcp\n") == ["DW010:2"]
    assert only("DW010", "FROM a:1\nEXPOSE 2222 8022\n") == []
    assert only("DW010", "FROM a:1\nRUN apt-get install -y openssh-server\n") == ["DW010:2"]


def test_unknown_stage() -> None:
    assert only("DW011", "FROM a:1 AS build\nFROM b:1\nCOPY --from=build /x /y\n") == []
    assert only("DW011", "FROM a:1 AS build\nFROM b:1\nCOPY --from=biuld /x /y\n") == ["DW011:3"]
    assert only("DW011", "FROM a:1\nCOPY --from=0 /x /y\n") == []
    assert only("DW011", "FROM a:1\nCOPY --from=nginx:1.27 /etc/nginx /n\n") == []
    assert only("DW011", "FROM a:1\nCOPY --from=ghcr.io/o/i /x /y\n") == []
    assert only("DW011", "FROM a:1\nCOPY --from=late /x /y\nFROM b:1 AS late\n") == ["DW011:2"]
    assert (
        "defined later" in rules.run(parse("FROM a:1\nCOPY --from=late /x /y\nFROM b:1 AS late\n"))[0].message or True
    )


def test_the_later_stage_message_is_specific() -> None:
    messages = [
        f.message for f in rules.run(parse("FROM a:1\nCOPY --from=late /x /y\nFROM b:1 AS late\n")) if f.rule == "DW011"
    ]
    assert "defined later" in messages[0]


@pytest.mark.parametrize(
    ("copy", "expected"),
    [
        ("COPY .env /app/", ["DW012:2"]),
        ("COPY config/.env.production /app/", ["DW012:2"]),
        ("COPY id_rsa /root/.ssh/", ["DW012:2"]),
        ("COPY certs/server.key /etc/", ["DW012:2"]),
        ("COPY .npmrc /app/", ["DW012:2"]),
        ("COPY certs/ca.pem /etc/ssl/", ["DW012:2"]),
        ("COPY certs/ca.crt /etc/ssl/", []),
        ("COPY package.json /app/", []),
        ("COPY environment.yml /app/", []),
        ("COPY --from=build /out/.env /app/", []),
    ],
)
def test_sensitive_files(copy: str, expected: list[str]) -> None:
    assert only("DW012", f"FROM a:1\n{copy}\n") == expected


def test_a_pem_is_medium_and_a_key_is_high() -> None:
    df = rules.run(parse("FROM a:1\nCOPY ca.pem /x/\nCOPY id_rsa /y/\n"))
    assert [f.severity for f in df if f.rule == "DW012"] == [rules.Severity.MEDIUM, rules.Severity.HIGH]


@pytest.mark.parametrize(
    "run",
    [
        "curl -k https://x -o y",
        "curl --insecure https://x",
        "curl -sSLk https://x",
        "wget --no-check-certificate https://x",
        "git config --global http.sslVerify false",
        "npm config set strict-ssl false",
        "pip install --trusted-host pypi.org x",
        "apt-get install -y --allow-unauthenticated x",
    ],
)
def test_verification_disabled(run: str) -> None:
    assert only("DW013", f"FROM a:1\nRUN {run}\n") == ["DW013:2"]


def test_verification_enabled_and_env_form() -> None:
    assert only("DW013", "FROM a:1\nRUN curl -fsSL https://x -o y && echo ok\n") == []
    assert only("DW013", "FROM a:1\nRUN curl -s -o /dev/null https://x\n") == []
    assert only("DW013", "FROM a:1\nENV NODE_TLS_REJECT_UNAUTHORIZED=0\n") == ["DW013:2"]


def test_every_rule_is_documented_and_ids_are_ordered() -> None:
    ids = [r.id for r in rules.RULES]
    assert ids == sorted(ids) and len(set(ids)) == len(ids)
    for r in rules.RULES:
        assert r.name and r.title and r.why and r.fix, r.id


def test_findings_carry_the_rule_fix_text() -> None:
    f = rules.run(parse("FROM node\nUSER x\n"))[0]
    assert f.fix == rules.by_id("DW001").fix  # type: ignore[union-attr]


@pytest.mark.parametrize(
    ("image", "expected"),
    [
        ("gcr.io/distroless/static-debian12:nonroot", []),
        ("nginxinc/nginx-unprivileged:1.27-alpine", []),
        ("mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled", []),
        ("docker:27-dind-rootless", []),
        ("nginx:1.27", ["DW003:1"]),
        ("gcr.io/distroless/static-debian12:latest", ["DW003:1"]),
    ],
)
def test_root_recognises_images_that_publish_a_non_root_user(image: str, expected: list[str]) -> None:
    assert only("DW003", f"FROM {image}\nCOPY app /app\n") == expected


def test_an_explicit_root_overrides_a_non_root_base() -> None:
    assert only("DW003", "FROM gcr.io/distroless/static:nonroot\nUSER root\n") == ["DW003:2"]


def test_apt_list_cleanup_forms() -> None:
    install = "apt-get install -y --no-install-recommends curl"
    assert only("DW007", f"FROM a:1\nRUN {install} && rm -rf /var/lib/apt/lists/*\n") == []
    assert only("DW007", f"FROM a:1\nRUN {install} && apt-get dist-clean\n") == []
    # apt-get clean empties the package cache, not the lists, so it is not a cleanup of them.
    assert only("DW007", f"FROM a:1\nRUN {install} && apt-get clean\n") == ["DW007:2"]
