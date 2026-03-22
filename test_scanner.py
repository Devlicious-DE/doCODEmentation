from pathlib import Path

from scanner import _extract_image_tag, _load_yaml, build_inventory


def test_sensitive_env_files_are_never_parsed(tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text("PASSWORD=supersecretvalue", encoding="utf-8")

    try:
        _load_yaml(env_path)
        assert False, "Expected sensitive file read to be rejected"
    except ValueError as exc:
        assert "Refusing to read sensitive file" in str(exc)


def test_variable_references_are_never_resolved() -> None:
    assert _extract_image_tag("ghcr.io/app/service:${APP_VERSION:-latest}") == "unresolved"


def test_basic_compose_scan_has_expected_keys(tmp_path: Path) -> None:
    compose = tmp_path / "web" / "docker-compose.yml"
    (tmp_path / "web").mkdir()
    compose.write_text(
        """
services:
  web:
    container_name: web-app
    image: nginx:1.27
    environment:
      - API_KEY=${API_KEY}
      - SIMPLE=abc
    ports:
      - "8080:80"
    healthcheck:
      test: ["CMD", "echo", "ok"]
""".strip(),
        encoding="utf-8",
    )

    result = build_inventory(tmp_path, scanner_version="0.1.0-test")
    assert result.inventory["metadata"]["version"] == "0.1.0-test"
    assert len(result.inventory["services"]) == 1
    service = result.inventory["services"][0]
    expected_keys = {
        "name",
        "compose_service_name",
        "container_name",
        "image",
        "image_tag",
        "service_type",
        "urls",
        "internal_ports",
        "published_ports",
        "networks",
        "bind_mounts",
        "environment_keys",
        "depends_on",
        "healthcheck",
        "restart",
        "security",
        "labels",
        "source_file",
        "source",
        "potential_hardcoded_secrets",
    }
    assert expected_keys.issubset(set(service.keys()))
