import pytest

from dockerwarden.image import expand, parse_image
from dockerwarden.parse import DockerfileError, assignments, parse
from dockerwarden.shell import commands, program, segments


def test_instructions_stages_and_global_args() -> None:
    df = parse("ARG BASE=python:3.12\nFROM ${BASE} AS build\nRUN echo hi\nFROM scratch\nCOPY --from=build /a /b\n")
    assert [i.keyword for i in df.global_args] == ["ARG"]
    assert [(s.index, s.image, s.name) for s in df.stages] == [(0, "${BASE}", "build"), (1, "scratch", None)]
    assert df.stages[1].instructions[0].flags == {"from": "build"}
    assert df.stages[1].instructions[0].args == "/a /b"


def test_continuation_lines_comments_and_blank_lines_between() -> None:
    df = parse(
        "FROM a\nRUN apt-get update && \\\n    # a comment in the middle\n\n    apt-get install -y x\nUSER app\n"
    )
    run = df.stages[0].instructions[0]
    assert run.line == 2 and run.end_line == 5
    assert "apt-get install -y x" in run.args and "comment" not in run.args
    assert df.stages[0].instructions[1].line == 6


def test_escape_directive_changes_the_continuation_character() -> None:
    df = parse("# escape=`\nFROM a\nRUN echo one `\n  two\n")
    assert df.stages[0].instructions[0].args == "echo one   two"
    # With the default escape a trailing backtick is just text.
    plain = parse("FROM a\nRUN echo `\nUSER x\n")
    assert [i.keyword for i in plain.stages[0].instructions] == ["RUN", "USER"]


def test_a_trailing_hash_is_part_of_the_instruction() -> None:
    assert parse("FROM a\nRUN echo hi # not a comment\n").stages[0].instructions[0].args == "echo hi # not a comment"


def test_heredocs() -> None:
    df = parse("FROM a\nRUN <<EOF\napt-get install -y x\nEOF\nRUN <<-'END' cat\n\tbody\n\tEND\nUSER u\n")
    first, second, user = df.stages[0].instructions
    assert first.heredocs == ("apt-get install -y x",) and first.end_line == 4
    assert second.heredocs == ("\tbody",)
    assert user.keyword == "USER" and user.line == 8
    assert "apt-get install -y x" in first.text


def test_an_unterminated_heredoc_is_an_error() -> None:
    with pytest.raises(DockerfileError, match="line 2: heredoc <<EOF is never terminated"):
        parse("FROM a\nRUN <<EOF\nstill going\n")


def test_run_flags_are_split_from_the_command() -> None:
    run = parse("FROM a\nRUN --mount=type=cache,target=/x --network=none make\n").stages[0].instructions[0]
    assert run.flags == {"mount": "type=cache,target=/x", "network": "none"} and run.args == "make"


def test_json_form_words() -> None:
    cmd = parse('FROM a\nCMD ["node", "a b.js"]\nCOPY x "y z" /dest\n').stages[0].instructions
    assert cmd[0].words() == ["node", "a b.js"]
    assert cmd[1].words() == ["x", "y z", "/dest"]


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "no FROM"),
        ("RUN echo\n", "RUN before the first FROM"),
        ("FROM a\nRUm echo\n", "line 2: unknown instruction 'RUM'"),
        ("FROM\n", "FROM needs an image"),
        ("FROM a b c d\n", "FROM takes an image"),
        ("# just a comment\n", "no FROM"),
    ],
)
def test_not_a_dockerfile(text: str, message: str) -> None:
    with pytest.raises(DockerfileError, match=message):
        parse(text)


def test_the_instruction_keyword_is_case_insensitive() -> None:
    assert parse("from a\nrun echo\n").stages[0].instructions[0].keyword == "RUN"


def test_assignments() -> None:
    assert assignments('A=1 B="two words" C=') == [("A", "1"), ("B", "two words"), ("C", "")]
    assert assignments("NAME") == [("NAME", None)]
    assert assignments("A B", legacy=False) == [("A", None), ("B", None)]
    assert assignments("KEY some value here", legacy=True) == [("KEY", "some value here")]


@pytest.mark.parametrize(
    ("text", "name", "tag", "digest"),
    [
        ("node", "node", None, None),
        ("node:20", "node", "20", None),
        ("localhost:5000/team/app:1.2", "localhost:5000/team/app", "1.2", None),
        ("localhost:5000/app", "localhost:5000/app", None, None),
        ("ghcr.io/o/i:v1@sha256:abc", "ghcr.io/o/i", "v1", "sha256:abc"),
        ("img@sha256:abc", "img", None, "sha256:abc"),
    ],
)
def test_image_references(text: str, name: str, tag: str | None, digest: str | None) -> None:
    ref = parse_image(text)
    assert (ref.name, ref.tag, ref.digest) == (name, tag, digest)


def test_variable_expansion_in_from() -> None:
    assert expand("${V}", {"V": "a:1"}) == ("a:1", True)
    assert expand("x:${T:-latest}", {}) == ("x:latest", True)
    assert expand("x:${T:-latest}", {"T": "2"}) == ("x:2", True)
    assert expand("$MISSING", {}) == ("$MISSING", False)


def test_shell_splitting_respects_quotes() -> None:
    script = "apt-get update && echo 'a && b' | cat; ls\nwhoami"
    assert list(segments(script)) == ["apt-get update ", " echo 'a && b' ", " cat", " ls", "whoami"]
    assert commands("sudo -E apt-get install -y x # trailing") == [["sudo", "-E", "apt-get", "install", "-y", "x"]]
    assert program(["FOO=1", "sudo", "-E", "/usr/bin/apt-get", "install"]) == "apt-get"


def test_a_pathological_file_does_not_hang() -> None:
    df = parse("FROM a\n" + "RUN echo " + "\\\n" * 5000 + "done\n")
    assert len(df.stages[0].instructions) == 1
