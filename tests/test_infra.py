"""Infrastructure, container hardening, dependency lock, and CI supply-chain tests."""

from __future__ import annotations

import importlib.metadata
from pathlib import Path
import re
import tomllib
from typing import Any

from packaging.requirements import Requirement
from packaging.version import Version
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent

SHA_PIN_RE = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
LOCK_LINE_RE = re.compile(r"^([a-z0-9][a-z0-9._-]*)==([0-9A-Za-z.+!_-]+)$")


def _normalize_pkg(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse_lockfile(path: Path, expected_header: str) -> dict[str, str]:
    assert path.is_file(), f"Missing lockfile: {path}"
    lock_lines = path.read_text(encoding="utf-8").splitlines()
    assert lock_lines and lock_lines[0].startswith(expected_header)

    locked: dict[str, str] = {}
    for line in lock_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = LOCK_LINE_RE.match(stripped)
        assert match is not None, f"Unpinned or invalid lockfile entry: {stripped!r}"
        pkg_norm = _normalize_pkg(match.group(1))
        assert pkg_norm not in locked, f"Duplicate lockfile entry: {pkg_norm!r}"
        locked[pkg_norm] = match.group(2)
    return locked


def _verify_locked_requirements(deps: list[str], locked: dict[str, str]) -> None:
    for dep in deps:
        req = Requirement(dep.strip())
        pkg_norm = _normalize_pkg(req.name)
        assert pkg_norm in locked, f"Missing dependency in lockfile: {req.name!r}"
        assert req.specifier.contains(Version(locked[pkg_norm])), (
            f"{req.name}=={locked[pkg_norm]} does not satisfy {dep!r}"
        )


def test_pyproject_dependencies_and_lockfile() -> None:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    deps: list[str] = pyproject["project"]["dependencies"]
    assert "regex>=2024.11.6" in deps

    # Existing tool configs remain intact
    for section in ("pytest", "ruff", "mypy"):
        assert section in pyproject["tool"]

    locked = _parse_lockfile(
        REPO_ROOT / "requirements.lock",
        "# Generated from pyproject.toml runtime dependencies",
    )

    # Dev-only packages and package itself must be excluded
    for forbidden in ("pricewatcher", "pytest", "pytest-asyncio", "ruff", "mypy", "pip-audit"):
        assert forbidden not in locked

    # Every direct runtime dependency + uvicorn[standard] extras must be locked
    _verify_locked_requirements(deps, locked)

    for standard_extra in (
        "click",
        "h11",
        "httptools",
        "python-dotenv",
        "pyyaml",
        "uvloop",
        "watchfiles",
        "websockets",
    ):
        assert standard_extra in locked

    # Every locked entry resolves in the active environment at the pinned version
    for pkg_name, pkg_version in locked.items():
        dist = importlib.metadata.distribution(pkg_name)
        assert dist.version == pkg_version


def test_playwright_lockfile_and_dockerfile() -> None:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    pw_deps: list[str] = pyproject["project"]["optional-dependencies"]["playwright"]
    assert any(_normalize_pkg(Requirement(dep).name) == "playwright" for dep in pw_deps)

    base_locked = _parse_lockfile(
        REPO_ROOT / "requirements.lock",
        "# Generated from pyproject.toml runtime dependencies",
    )
    pw_locked = _parse_lockfile(
        REPO_ROOT / "requirements-playwright.lock",
        "# Generated from pyproject.toml optional dependency: playwright",
    )

    for expected_pkg in ("greenlet", "playwright", "pyee"):
        assert expected_pkg in pw_locked

    _verify_locked_requirements(pw_deps, pw_locked)

    for shared_pkg in base_locked.keys() & pw_locked.keys():
        assert base_locked[shared_pkg] == pw_locked[shared_pkg]

    dockerfile_text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert (
        "COPY requirements.lock requirements-playwright.lock pyproject.toml README.md ./"
        in dockerfile_text
    )
    assert "pip install --no-cache-dir --no-deps -r requirements-playwright.lock" in dockerfile_text
    assert ".[playwright]" not in dockerfile_text


def test_dockerfile_hardening() -> None:
    text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    from_lines = [line for line in lines if line.upper().startswith("FROM ")]
    assert len(from_lines) == 1
    assert re.match(
        r"^FROM\s+python:3\.14-slim-bookworm@sha256:[0-9a-f]{64}$",
        from_lines[0],
    )

    assert "ARG INSTALL_PLAYWRIGHT=false" in text
    assert "PLAYWRIGHT_BROWSERS_PATH=/ms-playwright" in text
    assert "pip install --no-cache-dir --no-deps -r requirements.lock" in text
    assert "pip install --no-cache-dir --no-deps ." in text

    assert "groupadd --gid 10001 appuser" in text
    assert "useradd --create-home --uid 10001 --gid 10001 appuser" in text
    assert "chown -R appuser:appuser /app /data" in text
    assert "USER 10001" in lines
    assert (
        lines.index("chown -R appuser:appuser /app /data")
        < lines.index("USER 10001")
        < lines.index("EXPOSE 8080")
    )
    assert "Entrypoint prepares" not in text
    assert any(
        line.upper().startswith("HEALTHCHECK ") or "http://127.0.0.1:8080/healthz" in line
        for line in lines
    )
    assert "http://127.0.0.1:8080/healthz" in text
    assert 'CMD ["pricewatcher", "--host", "0.0.0.0", "--port", "8080"]' in text


def test_container_volume_ownership_and_privilege_drop(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    from pricewatcher.main import _ensure_volume_permissions_and_drop_privileges

    db_dir = tmp_path / "data"
    cfg_dir = tmp_path / "config"
    db_dir.mkdir()
    cfg_dir.mkdir()
    symlink_secret = cfg_dir / "link_outside"
    symlink_secret.symlink_to(tmp_path)

    monkeypatch.setenv("PRICEWATCHER_DB_PATH", str(db_dir / "prices.db"))
    monkeypatch.setenv("PRICEWATCHER_CONFIG_DIR", str(cfg_dir))
    monkeypatch.delenv("PUID", raising=False)
    monkeypatch.delenv("PGID", raising=False)

    euid_calls = iter([0, 10001])
    chowned: list[tuple[Path, int, int]] = []
    dropped: list[tuple[str, Any]] = []

    monkeypatch.setattr("os.geteuid", lambda: next(euid_calls))
    monkeypatch.setattr("os.chown", lambda p, u, g: chowned.append((Path(p), u, g)))
    monkeypatch.setattr("os.setgroups", lambda groups: dropped.append(("setgroups", list(groups))))
    monkeypatch.setattr("os.setgid", lambda gid: dropped.append(("setgid", gid)))
    monkeypatch.setattr("os.setuid", lambda uid: dropped.append(("setuid", uid)))

    _ensure_volume_permissions_and_drop_privileges()

    assert (cfg_dir / "watches").is_dir()
    assert (db_dir, 10001, 10001) in chowned
    assert (cfg_dir, 10001, 10001) in chowned
    assert (cfg_dir / "watches", 10001, 10001) in chowned
    assert all(path != symlink_secret for path, _, _ in chowned)
    assert dropped == [("setgroups", []), ("setgid", 10001), ("setuid", 10001)]


def test_dockerignore_excludes_sensitive_and_dev_files() -> None:
    entries = {
        line.strip()
        for line in (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    required = {
        ".git",
        ".venv",
        "data/",
        "tests/",
        ".env",
        "config/settings.yaml",
        "config/watches/*.yaml",
        "config/watches/*.yml",
        "__pycache__/",
        ".pytest_cache/",
        ".mypy_cache/",
        ".ruff_cache/",
        ".impeccable/",
        "AUDIT_FIX.md",
        "*.db*",
    }
    missing = required - entries
    assert not missing, f"Missing .dockerignore exclusions: {sorted(missing)}"


def test_docker_compose_configuration() -> None:
    compose: dict[str, Any] = yaml.safe_load(
        (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    )
    service = compose["services"]["pricewatcher"]

    assert "platform" not in service
    assert "127.0.0.1:8080:8080" in service["ports"]
    assert "8080:8080" not in service["ports"]
    assert "./config:/app/config" in service["volumes"]
    assert "./data:/data" in service["volumes"]

    env: dict[str, Any] = service["environment"]
    assert env["PRICEWATCHER_DB_PATH"] == "/data/prices.db"
    assert env["PRICEWATCHER_CONFIG_DIR"] == "/app/config"
    assert env["PRICEWATCHER_INSECURE_NO_AUTH"] == "${PRICEWATCHER_INSECURE_NO_AUTH:-}"
    assert env["PRICEWATCHER_COOKIE_SECURE"] == "${PRICEWATCHER_COOKIE_SECURE:-1}"
    assert env["PRICEWATCHER_TRUSTED_PROXIES"] == "${PRICEWATCHER_TRUSTED_PROXIES:-}"

    required_env_vars = {
        "TZ",
        "PRICEWATCHER_DB_PATH",
        "PRICEWATCHER_CONFIG_DIR",
        "PRICEWATCHER_ADMIN_PASSWORD_HASH",
        "PRICEWATCHER_SESSION_SECRET",
        "PRICEWATCHER_INSECURE_NO_AUTH",
        "PRICEWATCHER_COOKIE_SECURE",
        "PRICEWATCHER_TRUSTED_PROXIES",
        "PRICEWATCHER_ALLOW_PRIVATE_HOSTS",
        "PRICEWATCHER_CONTACT_URL",
        "PRICEWATCHER_MAX_RESPONSE_BYTES",
        "WAHA_URL",
        "WAHA_API_KEY",
        "WAHA_SESSION",
        "SMTP_USER",
        "SMTP_PASS",
    }
    missing = required_env_vars - set(env.keys())
    assert not missing, f"Missing env vars in docker-compose.yml: {sorted(missing)}"


def test_env_example_documents_all_vars_without_secrets() -> None:
    text = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    vars_found: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("#"):
            line = line.lstrip("#").strip()
        if "=" not in line or line.startswith("http"):
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        if re.fullmatch(r"[A-Z][A-Z0-9_]+", key):
            vars_found[key] = val.strip()

    expected_vars = {
        "PRICEWATCHER_ADMIN_PASSWORD_HASH",
        "PRICEWATCHER_SESSION_SECRET",
        "PRICEWATCHER_INSECURE_NO_AUTH",
        "PRICEWATCHER_COOKIE_SECURE",
        "PRICEWATCHER_TRUSTED_PROXIES",
        "PRICEWATCHER_ALLOW_PRIVATE_HOSTS",
        "PRICEWATCHER_CONTACT_URL",
        "PRICEWATCHER_MAX_RESPONSE_BYTES",
        "PRICEWATCHER_DB_PATH",
        "PRICEWATCHER_CONFIG_DIR",
        "WAHA_URL",
        "WAHA_API_KEY",
        "WAHA_SESSION",
        "SMTP_USER",
        "SMTP_PASS",
        "TZ",
    }
    missing = expected_vars - set(vars_found.keys())
    assert not missing, f"Missing env vars in .env.example: {sorted(missing)}"

    assert vars_found["PRICEWATCHER_ADMIN_PASSWORD_HASH"] == ""
    assert vars_found["PRICEWATCHER_SESSION_SECRET"] == ""
    assert vars_found["PRICEWATCHER_INSECURE_NO_AUTH"] == ""
    assert vars_found["PRICEWATCHER_COOKIE_SECURE"] == "1"
    assert vars_found["PRICEWATCHER_TRUSTED_PROXIES"] == ""
    assert vars_found["SMTP_USER"] == ""
    assert vars_found["SMTP_PASS"] == ""
    assert "replace_with" in vars_found["WAHA_API_KEY"].lower()
    assert "@gmail.com" not in text.lower()


def test_github_workflow_supply_chain_and_permissions() -> None:
    workflow_text = (REPO_ROOT / ".github" / "workflows" / "docker-publish.yml").read_text(
        encoding="utf-8"
    )
    workflow: dict[str, Any] = yaml.safe_load(workflow_text)

    triggers = workflow.get("on") or workflow.get(True)
    assert isinstance(triggers, dict)
    for event in ("push", "pull_request", "workflow_dispatch"):
        assert event in triggers

    assert workflow.get("permissions") == {}

    jobs: dict[str, Any] = workflow["jobs"]
    assert set(jobs.keys()) >= {"test", "build-and-push"}

    test_job = jobs["test"]
    assert test_job["runs-on"] == "ubuntu-latest"
    assert test_job["permissions"] == {"contents": "read"}
    setup_python = next(
        step
        for step in test_job["steps"]
        if str(step.get("uses", "")).startswith("actions/setup-python@")
    )
    cache_paths = setup_python["with"]["cache-dependency-path"].splitlines()
    assert "requirements.lock" in cache_paths
    assert "requirements-playwright.lock" in cache_paths

    freshness_steps = [
        step for step in test_job["steps"] if "lockfile" in str(step.get("name", "")).lower()
    ]
    assert len(freshness_steps) == 1
    freshness_run = freshness_steps[0]["run"]
    assert "python -m pip check" in freshness_run
    assert "pyproject.toml" in freshness_run
    assert "requirements.lock" in freshness_run
    assert "requirements-playwright.lock" in freshness_run

    test_runs = "\n".join(step.get("run", "") for step in test_job["steps"])
    for expected_cmd in (
        "python -m pip check",
        "ruff check",
        "ruff format --check",
        "mypy src",
        "pip-audit",
        "pytest -v",
    ):
        assert expected_cmd in test_runs

    build_job = jobs["build-and-push"]
    needs = build_job["needs"]
    assert needs == "test" or "test" in needs
    assert build_job["if"] == "github.event_name != 'pull_request'"
    assert build_job["permissions"] == {"contents": "read", "packages": "write"}

    uses_count = 0
    for job in jobs.values():
        for step in job["steps"]:
            uses = step.get("uses")
            if uses is not None:
                uses_count += 1
                assert SHA_PIN_RE.match(uses), f"Action is not pinned to 40-char SHA: {uses!r}"
    assert uses_count >= 7

    for raw_line in workflow_text.splitlines():
        if "uses:" in raw_line:
            assert re.search(r"#\s*v\d+\.\d+\.\d+\s*$", raw_line), (
                f"Expected version comment on uses line: {raw_line!r}"
            )
