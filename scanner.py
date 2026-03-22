from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import re

from ruamel.yaml import YAML


COMPOSE_FILE_PATTERNS = (
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
)


@dataclass
class ScanResult:
    inventory: dict[str, Any]
    warnings: list[str]


def _is_sensitive_path(path: Path) -> bool:
    name = path.name.lower()
    if name.endswith(".env") or name == ".env":
        return True
    if name in {"secrets.yaml", "secrets.yml"}:
        return True
    if "secret" in name:
        return True
    return False


def discover_compose_files(base_dir: Path) -> list[Path]:
    files: list[Path] = []
    for pattern in COMPOSE_FILE_PATTERNS:
        files.extend(base_dir.glob(f"*/{pattern}"))
    filtered: list[Path] = []
    for file_path in sorted(set(files)):
        # Security: never parse paths that look like env files or secret stores.
        if _is_sensitive_path(file_path):
            continue
        filtered.append(file_path)
    return filtered


def _load_yaml(path: Path) -> dict[str, Any]:
    # Security: refuse secret-like paths even if passed by mistake.
    if _is_sensitive_path(path):
        raise ValueError(f"Refusing to read sensitive file: {path}")
    yaml = YAML(typ="safe")
    with path.open("r", encoding="utf-8") as f:
        data = yaml.load(f) or {}
    if not isinstance(data, dict):
        return {}
    return data


def _labels_to_dict(labels: Any) -> dict[str, str]:
    def _sanitize_label_value(key: str, value: str) -> str:
        k = key.lower()
        if any(
            token in k
            for token in ("password", "passwd", "secret", "token", "apikey", "api_key", "auth")
        ):
            return "***redacted***"
        return value

    if isinstance(labels, dict):
        return {str(k): _sanitize_label_value(str(k), str(v)) for k, v in labels.items()}
    if isinstance(labels, list):
        out: dict[str, str] = {}
        for item in labels:
            if not isinstance(item, str):
                continue
            if "=" in item:
                k, v = item.split("=", 1)
                key = k.strip()
                out[key] = _sanitize_label_value(key, v.strip())
            else:
                out[item.strip()] = "true"
        return out
    return {}


def _extract_host_from_rule(rule: str) -> list[str]:
    host_calls = re.findall(r"Host\((.*?)\)", rule)
    hosts: list[str] = []
    for call in host_calls:
        for candidate in re.findall(r"[`\"]([^`\"]+)[`\"]", call):
            if candidate:
                hosts.append(candidate)
    return hosts


def _extract_urls(labels: dict[str, str], ports: list[str]) -> list[str]:
    router_rules = [v for k, v in labels.items() if ".http.routers." in k and k.endswith(".rule")]
    entrypoints = [v for k, v in labels.items() if ".http.routers." in k and k.endswith(".entrypoints")]
    tls_enabled = any(k.endswith(".tls") and str(v).lower() == "true" for k, v in labels.items()) or any(
        k.endswith(".tls.certresolver") for k in labels
    )
    scheme = "https" if tls_enabled or any("websecure" in ep for ep in entrypoints) else "http"

    urls: list[str] = []
    for rule in router_rules:
        for host in _extract_host_from_rule(rule):
            urls.append(f"{scheme}://{host}")
    if urls:
        return sorted(set(urls))

    fallback: list[str] = []
    for p in ports:
        if ":" not in p:
            continue
        host_port = p.split(":")[0].strip('"')
        host_port = host_port.split("/")[0]
        if host_port.isdigit():
            proto = "https" if host_port == "443" else "http"
            fallback.append(f"{proto}://localhost:{host_port}")
    return sorted(set(fallback))


def _extract_internal_ports(service: dict[str, Any], labels: dict[str, str]) -> list[int]:
    ports: list[int] = []
    for k, v in labels.items():
        if k.endswith(".loadbalancer.server.port"):
            try:
                ports.append(int(str(v)))
            except ValueError:
                pass
    if ports:
        return sorted(set(ports))

    expose = service.get("expose", [])
    if isinstance(expose, list):
        for p in expose:
            try:
                ports.append(int(str(p)))
            except ValueError:
                pass
    if ports:
        return sorted(set(ports))

    raw_ports = service.get("ports", [])
    if isinstance(raw_ports, list):
        for p in raw_ports:
            s = str(p)
            if ":" in s:
                container = s.split(":")[-1].split("/")[0]
                try:
                    ports.append(int(container))
                except ValueError:
                    pass
    return sorted(set(ports))


def _extract_bind_mounts(volumes: Any) -> list[str]:
    out: list[str] = []
    if not isinstance(volumes, list):
        return out
    for v in volumes:
        if isinstance(v, str) and ":" in v:
            src = v.split(":", 1)[0]
            if src.startswith("/") or src.startswith("./") or src.startswith("../") or src.startswith("${"):
                out.append(src)
        elif isinstance(v, dict):
            if str(v.get("type", "")).lower() == "bind":
                src = str(v.get("source", "")).strip()
                if src:
                    out.append(src)
    return sorted(set(out))


def _extract_env_keys(environment: Any) -> list[str]:
    # Security: keys only; never values; never resolve ${VAR}.
    keys: list[str] = []
    if isinstance(environment, dict):
        keys.extend(str(k) for k in environment.keys())
    elif isinstance(environment, list):
        for item in environment:
            s = str(item)
            if "=" in s:
                keys.append(s.split("=", 1)[0])
            elif s:
                keys.append(s)
    return sorted(set(keys))


def _extract_env_items(environment: Any) -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    if isinstance(environment, dict):
        for key, value in environment.items():
            items.append((str(key), "" if value is None else str(value)))
    elif isinstance(environment, list):
        for raw in environment:
            token = str(raw)
            if "=" in token:
                k, v = token.split("=", 1)
                items.append((k.strip(), v.strip()))
            elif token:
                items.append((token.strip(), ""))
    return items


def _is_placeholder_secret_value(value: str) -> bool:
    lowered = value.strip().lower()
    placeholders = {
        "",
        "changeme",
        "change-me",
        "example",
        "example123",
        "password",
        "secret",
        "token",
        "your_password",
        "your_secret",
    }
    return lowered in placeholders


def _env_key_looks_secret_sensitive(key: str) -> bool:
    """Heuristic: key name suggests a credential (not host/user/name service refs)."""
    k = key.lower()
    tokens = (
        "password",
        "passwd",
        "secret",
        "token",
        "credential",
        "api_key",
        "apikey",
    )
    if any(t in k for t in tokens):
        return True
    if "auth" in k and any(x in k for x in ("password", "secret", "token", "key", "jwt")):
        return True
    if k.endswith("_key") or k.endswith("key"):
        if any(x in k for x in ("secret", "api", "private", "access")):
            return True
    return False


def _detect_potential_hardcoded_secrets(environment: Any) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for key, value in _extract_env_items(environment):
        if not _env_key_looks_secret_sensitive(key):
            continue
        if _is_placeholder_secret_value(value):
            continue
        stripped = value.strip()
        if stripped.startswith("${") and stripped.endswith("}"):
            continue
        if len(stripped) <= 8:
            continue
        findings.append({"key": key, "issue": "potential hardcoded secret"})
    return findings


def _depends_list(depends_on: Any) -> list[str]:
    if isinstance(depends_on, list):
        return sorted(set(str(x) for x in depends_on))
    if isinstance(depends_on, dict):
        return sorted(set(str(x) for x in depends_on.keys()))
    return []


def _read_only_bool(value: Any) -> bool:
    return str(value).lower() == "true"


def _classify_service_type(image: Any) -> str:
    image_str = str(image or "").lower()
    if any(x in image_str for x in ("postgres", "mysql", "mariadb", "mongodb", "influxdb")):
        return "database"
    if any(x in image_str for x in ("redis", "valkey", "memcached")):
        return "cache"
    if any(x in image_str for x in ("traefik", "nginx", "caddy", "haproxy")):
        return "proxy"
    if any(x in image_str for x in ("grafana", "prometheus", "loki", "alertmanager")):
        return "monitoring"
    if any(x in image_str for x in ("n8n", "node-red", "airflow")):
        return "automation"
    if any(x in image_str for x in ("immich", "plex", "jellyfin", "emby")):
        return "media"
    if any(x in image_str for x in ("homepage", "authentik", "adguard")):
        return "web"
    return "other"


def _security_flags(
    service: dict[str, Any], service_type: str, override: dict[str, Any] | None = None
) -> dict[str, Any]:
    security_opt = service.get("security_opt", []) or []
    no_new_privileges = any("no-new-privileges:true" in str(v).lower() for v in security_opt)

    cap_drop = service.get("cap_drop", [])
    cap_drop_state = "none"
    if isinstance(cap_drop, list) and cap_drop:
        lowered = {str(c).upper() for c in cap_drop}
        cap_drop_state = "all" if "ALL" in lowered else "partial"

    user = service.get("user")
    user_mode = "unset"
    if user is not None and str(user).strip():
        user_str = str(user).strip().lower()
        user_mode = "root" if user_str in {"0", "root", "0:0"} else "non_root"

    read_only = _read_only_bool(service.get("read_only", False))

    score = 100
    if not no_new_privileges:
        score -= 30
    if service_type not in {"database", "cache"}:
        if cap_drop_state == "none":
            score -= 30
        elif cap_drop_state == "partial":
            score -= 15
    if not read_only:
        score -= 20
    if user_mode in {"root", "unset"}:
        score -= 20
    score = max(0, min(100, score))

    security = {
        "no_new_privileges": no_new_privileges,
        "cap_drop": cap_drop_state,
        "read_only": read_only,
        "user_mode": user_mode,
        "score": score,
    }
    if override:
        if override.get("security_exception"):
            security["exception"] = True
            security["exception_reason"] = str(override.get("security_exception_reason", "manual exception"))
            score_floor = override.get("security_score_floor", 70)
            try:
                floor_int = int(score_floor)
            except (TypeError, ValueError):
                floor_int = 70
            security["score"] = max(security["score"], max(0, min(100, floor_int)))
    return security


def build_inventory(
    base_dir: Path, manual_overrides: dict[str, Any] | None = None, scanner_version: str = "0.1.0"
) -> ScanResult:
    warnings: list[str] = []
    files = discover_compose_files(base_dir)

    services: list[dict[str, Any]] = []
    network_map: dict[str, set[str]] = {}

    override_by_name: dict[str, dict[str, Any]] = {}
    if manual_overrides:
        for item in manual_overrides.get("services", []):
            if isinstance(item, dict) and item.get("name"):
                override_by_name[str(item["name"])] = item

    for compose_file in files:
        try:
            compose = _load_yaml(compose_file)
            raw_services = compose.get("services", {})
            if not isinstance(raw_services, dict):
                warnings.append(f"{compose_file}: services block is invalid")
                continue

            id_map = {
                str(svc_name): str((svc_raw or {}).get("container_name") or svc_name)
                for svc_name, svc_raw in raw_services.items()
                if isinstance(svc_raw, dict)
            }
            for service_name, service_raw in raw_services.items():
                if not isinstance(service_raw, dict):
                    warnings.append(f"{compose_file}: service {service_name} is invalid")
                    continue

                labels = _labels_to_dict(service_raw.get("labels", {}))
                raw_ports = [str(p) for p in (service_raw.get("ports", []) or [])]
                networks = service_raw.get("networks", [])
                if isinstance(networks, dict):
                    network_names = sorted(set(str(n) for n in networks.keys()))
                elif isinstance(networks, list):
                    network_names = sorted(set(str(n) for n in networks))
                else:
                    network_names = []

                service_id = str(service_raw.get("container_name") or service_name)
                for n in network_names:
                    network_map.setdefault(n, set()).add(service_id)

                healthcheck = service_raw.get("healthcheck")
                health_present = isinstance(healthcheck, dict) and not bool(healthcheck.get("disable", False))
                health_cmd = None
                if isinstance(healthcheck, dict) and "test" in healthcheck:
                    health_cmd = str(healthcheck.get("test"))

                service_override = override_by_name.get(service_id, {}) or override_by_name.get(
                    str(service_name), {}
                )
                effective_image = service_override.get("image", service_raw.get("image"))
                service_type = _classify_service_type(effective_image)
                secret_findings = _detect_potential_hardcoded_secrets(service_raw.get("environment", {}))

                service_obj = {
                    "name": service_id,
                    "compose_service_name": str(service_name),
                    "container_name": service_override.get("container_name", service_raw.get("container_name")),
                    "image": effective_image,
                    "image_tag": _extract_image_tag(effective_image),
                    "service_type": service_type,
                    "urls": service_override.get("urls")
                    or ([service_override["url"]] if service_override.get("url") else _extract_urls(labels, raw_ports)),
                    "internal_ports": _extract_internal_ports(service_raw, labels),
                    "published_ports": raw_ports,
                    "networks": network_names,
                    "bind_mounts": _extract_bind_mounts(service_raw.get("volumes", [])),
                    "environment_keys": _extract_env_keys(service_raw.get("environment", {})),
                    "depends_on": [id_map.get(d, d) for d in _depends_list(service_raw.get("depends_on"))],
                    "healthcheck": {"present": health_present, "command": health_cmd},
                    "restart": service_raw.get("restart"),
                    "security": _security_flags(service_raw, service_type, service_override),
                    "security_score": _security_flags(service_raw, service_type, service_override)["score"],
                    "labels": labels,
                    "source_file": str(compose_file),
                    "source": "compose",
                    "note": service_override.get("note"),
                    "potential_hardcoded_secrets": secret_findings,
                }
                services.append(service_obj)
        except Exception as exc:
            warnings.append(f"{compose_file}: {exc}")

    if manual_overrides:
        for item in manual_overrides.get("services", []):
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if name in {s.get("name") for s in services}:
                continue
            merged = {
                "name": item.get("name"),
                "compose_service_name": item.get("compose_service_name"),
                "container_name": item.get("container_name"),
                "image": item.get("image"),
                "image_tag": _extract_image_tag(item.get("image")),
                "service_type": item.get("service_type") or _classify_service_type(item.get("image")),
                "urls": item.get("urls") or ([item["url"]] if item.get("url") else []),
                "internal_ports": item.get("internal_ports", []),
                "published_ports": item.get("published_ports", []),
                "networks": item.get("networks", []),
                "bind_mounts": item.get("bind_mounts", []),
                "environment_keys": item.get("environment_keys", []),
                "depends_on": item.get("depends_on", []),
                "healthcheck": item.get("healthcheck", {"present": False, "command": None}),
                "restart": item.get("restart"),
                "security": item.get(
                    "security",
                    {
                        "no_new_privileges": False,
                        "cap_drop": "none",
                        "read_only": False,
                        "user_mode": "unset",
                        "score": 0,
                    },
                ),
                "labels": item.get("labels", {}),
                "source_file": "manual_overrides",
                "source": "manual",
                "note": item.get("note"),
                "potential_hardcoded_secrets": item.get("potential_hardcoded_secrets", []),
            }
            if merged["name"]:
                services.append(merged)

    services = sorted(services, key=lambda s: str(s.get("name", "")).lower())
    network_topology = {k: sorted(v) for k, v in sorted(network_map.items())}

    root_services = [s["name"] for s in services if s.get("security", {}).get("user_mode") == "root"]
    unset_user = [s["name"] for s in services if s.get("security", {}).get("user_mode") == "unset"]
    no_health = [s["name"] for s in services if not s.get("healthcheck", {}).get("present", False)]

    hardcoded_secret_warnings: list[dict[str, str]] = []
    for service in services:
        for finding in service.get("potential_hardcoded_secrets", []):
            hardcoded_secret_warnings.append(
                {
                    "service": str(service.get("name", "unknown")),
                    "key": str(finding.get("key", "")),
                    "issue": "potential hardcoded secret",
                }
            )

    inventory = {
        "metadata": {
            "scanner": "doCODEmentation",
            "version": scanner_version,
            "base_dir": str(base_dir),
            "compose_files": [str(p) for p in files],
            "service_count": len(services),
            "network_count": len(network_topology),
        },
        "services": services,
        "networks": network_topology,
        "relationships": [
            {"service": s["name"], "depends_on": s.get("depends_on", [])} for s in services if s.get("depends_on")
        ],
        "security_summary": {
            "root_services": root_services,
            "unset_user_services": unset_user,
            "services_without_healthcheck": no_health,
            "hardcoded_secret_warnings": hardcoded_secret_warnings,
        },
    }
    return ScanResult(inventory=inventory, warnings=warnings)


def _extract_image_tag(image: Any) -> str | None:
    if not image:
        return None
    image_str = str(image)
    if "${" in image_str and "}" in image_str:
        return "unresolved"
    if ":" not in image_str:
        return None
    return image_str.rsplit(":", 1)[-1]
