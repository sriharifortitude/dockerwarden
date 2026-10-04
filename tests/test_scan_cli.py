import json
from pathlib import Path

import pytest

from dockerwarden import scan
from dockerwarden.cli import main
from dockerwarden.parse import DockerfileError

ROOT = Path(__file__).resolve().parent.parent
VULNERABLE = str(ROOT / "testdata" / "vulnerable")
CLEAN = str(ROOT / "testdata" / "clean")


def rules_in(text: str) -> list[str]:
    findings, _ = scan.scan_source("Dockerfile", text)
    return [f.rule for f in findings]


# ---- suppression -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected", "suppressed"),
    [
        ("FROM node\nUSER x\n", ["DW001"], 0),
        ("# dockerwarden:ignore DW001 -- pinned by the registry mirror\nFROM node\nUSER x\n", [], 1),
        ("# dockerwarden:ignore DW001: pinned by the mirror\nFROM node\nUSER x\n", [], 1),
        ("# dockerwarden:ignore DW001\nFROM node\nUSER x\n", ["DW000", "DW001"], 0),
        ("# dockerwarden:ignore DW001 --   \nFROM node\nUSER x\n", ["DW000", "DW001"], 0),
        ("# dockerwarden:ignore DW002 -- reason\nFROM node\nUSER x\n", ["DW001"], 0),
        ("# dockerwarden:ignore DW001 -- reason\n\nFROM node\nUSER x\n", ["DW001"], 0),
        (
            "FROM node:20@sha256:"
            + "a" * 64
            + "\nUSER x\nRUN sudo make # dockerwarden:ignore DW008 -- a trailing # is not a comment\n",
            ["DW008"],
            0,
        ),
    ],
)
def test_a_suppression_needs_a_reason(text: str, expected: list[str], suppressed: int) -> None:
    findings, count = scan.scan_source("Dockerfile", text)
    assert [f.rule for f in findings] == expected
    assert count == suppressed


def test_a_suppression_only_covers_the_instruction_below_it() -> None:
    text = "FROM node:20\n# dockerwarden:ignore DW003 -- the base sets a non-root user\nRUN echo\nUSER root\n"
    assert rules_in(text) == ["DW002", "DW003"]


def test_suppression_works_with_windows_line_endings() -> None:
    text = "# dockerwarden:ignore DW001 -- reason\r\nFROM node\r\nUSER x\r\n"
    assert rules_in(text) == []


# ---- files -----------------------------------------------------------------------


def write(root: Path, name: str, text: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_discovery_finds_dockerfile_names_and_skips_noise(tmp_path: Path) -> None:
    for name in (
        "Dockerfile",
        "app/Dockerfile.prod",
        "svc/api.Dockerfile",
        "svc/Containerfile",
        "node_modules/x/Dockerfile",
        ".git/Dockerfile",
        "notes.txt",
        "Dockerfiles.md",
    ):
        write(tmp_path, name, "FROM a:1\nUSER x\n")
    found = [p.relative_to(tmp_path).as_posix() for p in scan.find_files([str(tmp_path)])]
    assert found == ["Dockerfile", "app/Dockerfile.prod", "svc/Containerfile", "svc/api.Dockerfile"]


def test_a_named_file_is_scanned_whatever_it_is_called(tmp_path: Path) -> None:
    path = write(tmp_path, "build.txt", "FROM node\nUSER x\n")
    result = scan.scan_paths([str(path)])
    assert result.files == 1 and [f.rule for f in result.findings] == ["DW001"]


def test_a_missing_path_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="no such file or directory"):
        scan.find_files([str(tmp_path / "nope")])


def test_a_bad_file_is_reported_and_the_rest_still_scanned(tmp_path: Path) -> None:
    write(tmp_path, "Dockerfile", "FROM node\nUSER x\n")
    write(tmp_path, "Dockerfile.bad", "RUM echo\n")
    (tmp_path / "Dockerfile.binary").write_bytes(b"FROM a\n\xff\xfe\n")
    result = scan.scan_paths([str(tmp_path)])
    assert result.files == 1 and len(result.findings) == 1
    assert len(result.errors) == 2
    assert any("Dockerfile.bad: line 1: unknown instruction" in e for e in result.errors)
    assert any("Dockerfile.binary: not valid UTF-8" in e for e in result.errors)


def test_an_oversized_file_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "Dockerfile"
    path.write_bytes(b"FROM a\n" + b"#" * scan.MAX_FILE_BYTES)
    result = scan.scan_paths([str(path)])
    assert result.files == 0 and "larger than 1 MiB" in result.errors[0]


def test_a_byte_order_mark_is_tolerated(tmp_path: Path) -> None:
    path = tmp_path / "Dockerfile"
    path.write_bytes(b"\xef\xbb\xbfFROM node:20\nUSER x\n")
    assert scan.scan_paths([str(path)]).errors == []


def test_read_errors_surface_as_dockerfile_errors(tmp_path: Path) -> None:
    with pytest.raises(DockerfileError):
        scan.scan_source("Dockerfile", "")


# ---- command line ----------------------------------------------------------------


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_vulnerable_fixture(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "scan", "--brief", VULNERABLE)
    assert code == 1
    assert "18 finding(s): 2 high, 9 medium, 7 low, in 2 Dockerfile(s)" in out
    for expected in (
        "Dockerfile:3  HIGH     DW004",
        "Dockerfile:8  HIGH     DW012",
        "Dockerfile.multistage:8  MEDIUM   DW011",
    ):
        assert expected in out


def test_clean_fixture(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = run(capsys, "scan", "--fail-on", "low", CLEAN)
    assert (code, err) == (0, "")
    assert "0 finding(s): none, in 1 Dockerfile(s)" in out


def test_fail_on(capsys: pytest.CaptureFixture[str]) -> None:
    assert [
        run(capsys, "scan", "--fail-on", level, VULNERABLE)[0]
        for level in ("low", "medium", "high", "critical", "none")
    ] == [1, 1, 1, 0, 0]


def test_full_output_has_the_fix_and_brief_does_not(capsys: pytest.CaptureFixture[str]) -> None:
    _, full, _ = run(capsys, "scan", VULNERABLE)
    _, brief, _ = run(capsys, "scan", "--brief", VULNERABLE)
    assert "    fix: " in full and "fix:" not in brief
    assert brief.count("\n") == 20  # 18 findings, a blank line, the summary


def test_json_output(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "scan", "--format", "json", VULNERABLE)
    doc = json.loads(out)
    assert code == 1 and doc["dockerfiles"] == 2 and len(doc["findings"]) == 18 and doc["errors"] == []
    first = doc["findings"][0]
    assert {"rule", "name", "severity", "file", "line", "message", "fix"} <= first.keys()
    _, clean, _ = run(capsys, "scan", "--format", "json", CLEAN)
    assert json.loads(clean)["findings"] == []


def test_sarif_output(capsys: pytest.CaptureFixture[str]) -> None:
    _, out, _ = run(capsys, "scan", "--format", "sarif", VULNERABLE)
    doc = json.loads(out)
    run0 = doc["runs"][0]
    assert doc["version"] == "2.1.0" and run0["tool"]["driver"]["name"] == "dockerwarden"
    assert len(run0["tool"]["driver"]["rules"]) == 14 and len(run0["results"]) == 18
    levels = [r["level"] for r in run0["results"]]
    assert (levels.count("error"), levels.count("warning"), levels.count("note")) == (2, 9, 7)
    assert all("\\" not in r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in run0["results"])


def test_output_is_deterministic(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(capsys, "scan", VULNERABLE)[1] == run(capsys, "scan", VULNERABLE)[1]


def test_rules_command(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "rules")
    assert code == 0 and out.count("    why: ") == 13 and out.count("    fix: ") == 13 and "DW013" in out


def test_an_unreadable_file_fails_the_run_even_when_the_rest_is_clean(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write(tmp_path, "Dockerfile", "FROM node:20@sha256:" + "a" * 64 + "\nUSER x\n")
    write(tmp_path, "Dockerfile.bad", "RUM echo\n")
    code, out, err = run(capsys, "scan", str(tmp_path))
    assert code == 2
    assert "0 finding(s): none, in 1 Dockerfile(s)" in out
    assert "Dockerfile.bad: line 1: unknown instruction" in err and "1 file(s) could not be read" in err


def test_a_missing_path_and_an_empty_directory_are_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(capsys, "scan", str(tmp_path / "nope"))
    assert code == 2 and "no such file or directory" in err
    code, _, err = run(capsys, "scan", str(tmp_path))
    assert code == 2 and "no Dockerfiles found" in err


@pytest.mark.parametrize(
    "argv", [[], ["nope"], ["scan", "--format", "xml"], ["scan", "--fail-on", "urgent"], ["scan", "--bogus"]]
)
def test_usage_errors_exit_2(argv: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(argv)
    assert exit_info.value.code == 2
    assert "dockerwarden:" in capsys.readouterr().err
