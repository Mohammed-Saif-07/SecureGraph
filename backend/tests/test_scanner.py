from __future__ import annotations

from core import scanner


def test_parse_requirements_extracts_pypi_packages():
    packages = scanner.parse_requirements("requests==2.28.0\n# comment\nflask>=2.0.1\n")
    assert packages == [
        {"name": "requests", "version": "2.28.0", "ecosystem": "PyPI"},
        {"name": "flask", "version": "2.0.1", "ecosystem": "PyPI"},
    ]


def test_parse_package_json_extracts_npm_dependencies():
    packages = scanner.parse_package_json('{"dependencies":{"react":"^19.0.0"},"devDependencies":{"vite":"~6.0.5"}}')
    assert {"name": "react", "version": "19.0.0", "ecosystem": "npm"} in packages
    assert {"name": "vite", "version": "6.0.5", "ecosystem": "npm"} in packages


def test_clone_failure_raises_scan_error(monkeypatch):
    class Result:
        returncode = 128
        stderr = "fatal: repository not found"

    monkeypatch.setattr(scanner, "run", lambda *args, **kwargs: Result())
    try:
        scanner.extract_dependencies_from_repo("https://github.com/example/private")
    except scanner.ScanError as exc:
        assert scanner.REPO_ACCESS_MESSAGE in str(exc) or str(exc) == ""
    else:
        raise AssertionError("ScanError was not raised")


def test_successful_repo_without_manifests_returns_empty_packages(monkeypatch):
    class Result:
        returncode = 0
        stderr = ""

    monkeypatch.setattr(scanner, "run", lambda *args, **kwargs: Result())
    service, packages = scanner.extract_dependencies_from_repo("https://github.com/example/empty")
    assert service == "empty"
    assert packages == []
