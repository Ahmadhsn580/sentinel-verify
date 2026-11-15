from __future__ import annotations

from sentinel.cli import EXIT_OK, EXIT_UNREACHABLE, EXIT_USAGE, main


def test_list_checks() -> None:
    assert main(["list-checks"]) == EXIT_OK


def test_explain_known_check(capsys) -> None:  # noqa: ANN001
    assert main(["explain", "hdr.hsts"]) == EXIT_OK
    assert "HSTS" in capsys.readouterr().out


def test_explain_unknown_check() -> None:
    assert main(["explain", "nope"]) == EXIT_USAGE


def test_dry_run_lists_checks(capsys) -> None:  # noqa: ANN001
    assert main(["scan", "https://example.com", "--dry-run", "--allow-private"]) == EXIT_OK
    assert "hdr.hsts" in capsys.readouterr().out


def test_bad_scheme() -> None:
    assert main(["scan", "ftp://example.com"]) == EXIT_USAGE


def test_unreachable_target() -> None:
    code = main(["scan", "http://127.0.0.1:1/", "--allow-private", "--retries", "0"])
    assert code == EXIT_UNREACHABLE


def test_scan_against_local_server(server_url: str, tmp_path, capsys) -> None:  # noqa: ANN001
    out = tmp_path / "r.json"
    code = main(
        ["scan", server_url + "/", "--allow-private", "--format", "json", "--out", str(out),
         "--checks", "hdr.xcto"]
    )
    assert code == EXIT_OK
    assert out.read_text().strip()
